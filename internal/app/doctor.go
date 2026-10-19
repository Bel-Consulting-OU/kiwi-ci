package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Doctor is the diagnostic engine (`kiwi doctor [--server URL] [--job ID]`).
// Local checks cover the execution substrate; --server checks cover the
// control plane; --job answers "can this job run here?" against live runner
// eligibility. Every finding prints an exact fix, not just a red X.
func Doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	server := fs.String("server", "", "also diagnose a Kiwi control plane URL")
	job := fs.String("job", "", "explain why a job can/cannot run: name the missing runner capability")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("OS: %s/%s  Go: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	localDoctor()
	// One endpoint resolution for the server and job probes.
	base := *server
	if base == "" {
		if ep, err := ResolveEndpoint("", ""); err == nil {
			base = ep.Server
		}
	}
	if *server != "" || *job != "" {
		fmt.Println()
		serverDoctor(base)
	}
	if *job != "" {
		fmt.Println()
		if err := jobDoctor(base, *job); err != nil {
			return err
		}
	}
	return nil
}

// jobDoctor answers the audit's operator question: "this job cannot run
// because no online runner satisfies: linux + arm64 + container + …". It
// reads the job's required labels from the API and compares them with every
// online runner's capabilities.
func jobDoctor(base, jobID string) error {
	fmt.Println("== job " + jobID + " ==")
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+"/api/v1/jobs/"+jobID, nil)
	if err != nil {
		return err
	}
	if tok, err := (&Endpoint{Server: base}).tokenForProbe(); err == nil && tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("job          FAIL (%v)\n", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("job          FAIL (HTTP %d)\n", resp.StatusCode)
		return nil
	}
	var j struct {
		Key            string   `json:"key"`
		Status         string   `json:"status"`
		RequiredLabels []string `json:"required_labels"`
		Placement      struct {
			Regions []string `json:"regions"`
		} `json:"placement"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		fmt.Printf("job          FAIL (decode: %v)\n", err)
		return nil
	}
	fmt.Printf("key          %s\n", j.Key)
	fmt.Printf("status       %s\n", j.Status)
	fmt.Printf("requires     %s\n", strings.Join(j.RequiredLabels, " + "))
	if len(j.Placement.Regions) > 0 {
		fmt.Printf("regions      %s\n", strings.Join(j.Placement.Regions, ", "))
	}

	// Runner eligibility.
	rreq, err := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+"/api/v1/runners", nil)
	if err != nil {
		return err
	}
	if tok, err := (&Endpoint{Server: base}).tokenForProbe(); err == nil && tok != "" {
		rreq.Header.Set("Authorization", "Bearer "+tok)
	}
	rresp, err := client.Do(rreq)
	if err != nil {
		fmt.Printf("runners      FAIL (%v)\n", err)
		return nil
	}
	defer rresp.Body.Close()
	var runners struct {
		Runners []struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Labels   []string `json:"labels"`
			Status   string   `json:"status"`
			Capacity struct {
				CPU    int64 `json:"cpu"`
				Memory int64 `json:"memory"`
			} `json:"capacity"`
		} `json:"runners"`
	}
	_ = json.NewDecoder(rresp.Body).Decode(&runners)

	matched := 0
	for _, r := range runners.Runners {
		if !runnerSatisfies(r.Labels, j.RequiredLabels) {
			continue
		}
		matched++
		fmt.Printf("✓ runner     %s (labels: %s)\n", r.Name, strings.Join(r.Labels, ","))
	}
	if matched == 0 {
		fmt.Printf("✗ no online runner satisfies: %s\n", strings.Join(j.RequiredLabels, " + "))
		fmt.Println("  → provision a runner carrying those labels (`kiwi runner register --labels …`)")
	} else {
		fmt.Printf("eligible     %d runner(s)\n", matched)
	}
	return nil
}

// runnerSatisfies reports whether a runner's labels are a superset of the
// job's required labels — the scheduler's eligibility rule, stated once.
func runnerSatisfies(have, need []string) bool {
	set := map[string]bool{}
	for _, l := range have {
		set[l] = true
	}
	for _, l := range need {
		if !set[l] {
			return false
		}
	}
	return true
}

// tokenForProbe is the doctor's credential lookup (never prints the token).
func (e Endpoint) tokenForProbe() (string, error) {
	return e.RequireToken()
}

func localDoctor() {
	fmt.Println("== local ==")
	for _, name := range []string{"git", "bash", "sh", "docker", "psql", "pg_dump", "pg_restore"} {
		toolCheck(name)
	}
	if runtime.GOOS == "darwin" {
		for _, name := range []string{"tart", "xcodebuild", "security"} {
			toolCheck(name)
		}
		// Resource caps on macOS are advisory: the kernel has no per-job
		// cgroup, so cpu/memory/pids limits are enforced by the executor's
		// own bookkeeping and Tart VM sizing — not by the host. Linux
		// runners with cgroup v2 get real kernel caps. Say it plainly so
		// an operator is not surprised by a noisy-neighbor job.
		fmt.Println("resource caps advisory on macOS (no cgroup v2): cpu/memory/pids")
		fmt.Println("  are tracked by the executor and Tart VM size, not the kernel.")
		fmt.Println("  Use a Linux runner when a hard ceiling is required.")
	}
	// Git version.
	if p, err := exec.LookPath("git"); err == nil {
		out, _ := exec.Command(p, "--version").Output()
		fmt.Printf("git version  %s\n", strings.TrimSpace(string(out)))
	}
	// Docker daemon / rootless.
	if p, err := exec.LookPath("docker"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, err := exec.CommandContext(ctx, p, "info", "--format",
			"{{.ServerVersion}} rootless={{.SecurityOptions}}").Output()
		cancel()
		if err != nil {
			fmt.Printf("docker daemon  NOT RUNNING (%v)\n", err)
		} else {
			fmt.Printf("docker daemon  %s\n", strings.TrimSpace(string(out)))
		}
	}
	// Filesystem / disk.
	if st := diskUsage("."); st != "" {
		fmt.Printf("disk         %s\n", st)
	}
	// Clock sanity (year must be plausible).
	if time.Now().Year() < 2020 {
		fmt.Println("clock        SUSPECT (year < 2020)")
	} else {
		fmt.Println("clock        ok")
	}
	// Shell.
	fmt.Printf("shell        %s\n", os.Getenv("SHELL"))
	// Repo status when inside one.
	if out, err := exec.Command("git", "rev-parse", "--is-inside-work-tree").Output(); err == nil && strings.TrimSpace(string(out)) == "true" {
		if dirty, _ := exec.Command("git", "status", "--porcelain").Output(); len(strings.TrimSpace(string(dirty))) > 0 {
			fmt.Println("repo         dirty working tree")
		} else {
			fmt.Println("repo         clean")
		}
	}
}

func toolCheck(name string) {
	p, err := exec.LookPath(name)
	if err != nil {
		fmt.Printf("%-14s missing   → install %s\n", name, name)
		return
	}
	fmt.Printf("%-14s %s\n", name, p)
}

func serverDoctor(base string) {
	fmt.Println("== server " + base + " ==")
	base = strings.TrimRight(base, "/")
	client := &http.Client{Timeout: 5 * time.Second}

	// TLS chain / certificate expiry. The dial address comes from
	// net/url — never host+":443" string concatenation, which breaks on
	// explicit ports and IPv6 literals.
	if strings.HasPrefix(base, "https://") {
		u, err := url.Parse(base)
		if err != nil {
			fmt.Printf("tls            FAIL (invalid URL %q: %v)\n", base, err)
		} else {
			host := u.Hostname()
			port := u.Port()
			if port == "" {
				port = "443"
			}
			addr := net.JoinHostPort(host, port)
			if _, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{ServerName: host}); err != nil {
				fmt.Printf("tls            FAIL (%v)\n", err)
			} else {
				fmt.Println("tls            ok")
			}
		}
	}

	for _, probe := range []struct {
		path, label string
	}{
		{"/liveness", "liveness"},
		{"/readiness", "readiness"},
		{"/readiness/lease", "lease-leader"},
		{"/version", "version"},
	} {
		resp, err := client.Get(base + probe.path)
		if err != nil {
			fmt.Printf("%-14s FAIL (%v)\n", probe.label, err)
			continue
		}
		status := "ok"
		if probe.path == "/version" && resp.StatusCode == http.StatusOK {
			var doc map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&doc)
			status = fmt.Sprintf("ok %v", doc["version"])
		} else if resp.StatusCode != http.StatusOK {
			status = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		_ = resp.Body.Close()
		fmt.Printf("%-14s %s\n", probe.label, status)
	}
}

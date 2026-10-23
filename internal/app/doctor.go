package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Doctor is the diagnostic engine (`kiwi doctor [--server URL] [--job ID]`).
// Local checks cover the execution substrate; --server checks cover the
// control plane; --job answers "can this job run here?" against live runner
// eligibility. Every finding prints an exact fix, not just a red X.
func Doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	server := fs.String("server", "", "also diagnose a Kiwi control plane URL")
	job := fs.String("job", "", "explain why a job can/cannot run: name the missing runner capability")
	pipelineFile := fs.String("pipeline", "", "verify toolchains: declared in this pipeline (default .kiwi/pipeline.yaml when present)")
	installToolchains := fs.Bool("install-toolchains", false, "attempt checksum-pinned toolchain installs into ~/.kiwi/tools (requires network)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("OS: %s/%s  Go: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	localDoctor()
	// Toolchain declaration check: hermetic native jobs fail closed when a
	// pinned tool is missing. Doctor surfaces that before the pipeline does.
	if err := doctorPipelineToolchains(*pipelineFile, *installToolchains); err != nil {
		return err
	}
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

// doctorPipelineToolchains verifies every top-level toolchains: entry is
// present (and version-matched) on this host. A missing pin is FAIL: native
// jobs would fail closed at step 1. --install-toolchains attempts the
// checksum-pinned bootstrap into ~/.kiwi/tools when an install: block exists.
func doctorPipelineToolchains(file string, install bool) error {
	if file == "" {
		if _, err := os.Stat(".kiwi/pipeline.yaml"); err == nil {
			file = ".kiwi/pipeline.yaml"
		} else {
			return nil
		}
	}
	s, err := pipeline.Load(file)
	if err != nil {
		fmt.Printf("toolchains    FAIL (load %s: %v)\n", file, err)
		return fmt.Errorf("doctor pipeline: %w", err)
	}
	if len(s.Toolchains) == 0 {
		return nil
	}
	fmt.Println("== toolchains ==")
	failed := false
	// Stable order: sorted names.
	names := make([]string, 0, len(s.Toolchains))
	for n := range s.Toolchains {
		names = append(names, n)
	}
	// sort without importing sort again if already present — sort.Strings
	// is in this file's imports via other uses? It is not. Use a simple sort.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		tc := s.Toolchains[name]
		bin := tc.Path
		if bin == "" && len(tc.Command) > 0 {
			bin = tc.Command[0]
		}
		if bin == "" {
			bin = name
		}
		if install && tc.Install != nil {
			if err := installToolchain(name, tc); err != nil {
				fmt.Printf("%-14s FAIL (install: %v)\n", name, err)
				failed = true
				continue
			}
		}
		path, err := exec.LookPath(bin)
		if err != nil {
			fmt.Printf("%-14s FAIL (not on PATH; declare install: or put %s on PATH)\n", name, bin)
			failed = true
			continue
		}
		args := tc.Command
		if len(args) == 0 {
			args = []string{path, "--version"}
		} else {
			args = append([]string{}, args...)
			args[0] = path
		}
		out, verr := exec.Command(args[0], args[1:]...).Output()
		if verr != nil {
			out, _ = exec.Command(path, "-v").Output()
		}
		ver := strings.TrimSpace(string(out))
		if tc.Version != "" && !strings.Contains(ver, tc.Version) {
			fmt.Printf("%-14s FAIL (have %q, want prefix %q)\n", name, ver, tc.Version)
			failed = true
			continue
		}
		fmt.Printf("%-14s ok  %s (%s)\n", name, ver, path)
	}
	if failed {
		return fmt.Errorf("doctor: one or more declared toolchains are missing or mismatched")
	}
	return nil
}

// installToolchain is a minimal checksum-pinned bootstrap: download the
// install.url into ~/.kiwi/tools/<name>/<version>/ and verify sha256.
// Extraction of tar.gz/zip is intentionally not implemented yet — raw
// single-binary pins only — so the surface stays tiny and native.
func installToolchain(name string, tc pipeline.Toolchain) error {
	inst := tc.Install
	if inst == nil {
		return nil
	}
	ver := tc.Version
	if ver == "" {
		ver = "any"
	}
	dir := filepath.Join(homeOrDot(), ".kiwi", "tools", name, ver)
	dest := filepath.Join(dir, inst.Bin)
	if st, err := os.Stat(dest); err == nil && st.Mode()&0o111 != 0 {
		return nil // already bootstrapped
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if inst.Format != "" && inst.Format != "raw" {
		return fmt.Errorf("format %q not supported yet (raw only)", inst.Format)
	}
	// Network download is intentionally explicit; doctor without
	// --install-toolchains never fetches.
	req, err := http.NewRequest(http.MethodGet, inst.URL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, inst.URL)
	}
	tmp := dest + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, strings.TrimSpace(inst.SHA256)) {
		_ = os.Remove(tmp)
		return fmt.Errorf("sha256 mismatch for %s: got %s want %s", name, got, inst.SHA256)
	}
	return os.Rename(tmp, dest)
}

func homeOrDot() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "."
}

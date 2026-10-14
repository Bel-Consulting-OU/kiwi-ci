package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Doctor is the diagnostic engine (`kiwi doctor [--server URL]`). Local
// checks cover the execution substrate; --server checks cover the control
// plane. Every finding prints an exact fix, not just a red X.
func Doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	server := fs.String("server", "", "also diagnose a Kiwi control plane URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("OS: %s/%s  Go: %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	localDoctor()
	if *server != "" {
		fmt.Println()
		serverDoctor(*server)
	}
	return nil
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

	// TLS chain / certificate expiry.
	if strings.HasPrefix(base, "https://") {
		host := strings.TrimPrefix(base, "https://")
		if i := strings.Index(host, "/"); i >= 0 {
			host = host[:i]
		}
		if _, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", host+":443", &tls.Config{ServerName: host}); err != nil {
			fmt.Printf("tls            FAIL (%v)\n", err)
		} else {
			fmt.Println("tls            ok")
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

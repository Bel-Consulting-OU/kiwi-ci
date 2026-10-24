package executor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// nativeServiceEnvPrefix is the env namespace native services publish.
// KIWI_SERVICE_<NAME>_HOST / _PORT always appear when a port was allocated.
const nativeServiceEnvPrefix = "KIWI_SERVICE_"

// startNativeServices launches host-process services for a native job,
// waits for each readiness probe, and returns a teardown that kills every
// process group. Failures are loud: a service that never becomes ready
// fails the job before step 1.
func startNativeServices(ctx context.Context, jobID string, services []pipeline.Service, emit func(string)) (string, map[string]string, func() error, error) {
	if len(services) == 0 {
		return "", nil, func() error { return nil }, nil
	}
	type running struct {
		svc     pipeline.Service
		cmd     *exec.Cmd
		port    int
		done    chan error
		release func()
	}
	var procs []*running
	env := map[string]string{}
	cleanup := func() error {
		var firstErr error
		for i := len(procs) - 1; i >= 0; i-- {
			p := procs[i]
			if p.cmd != nil {
				_ = terminateProcess(p.cmd)
				_ = killProcess(p.cmd)
			}
			if p.release != nil {
				p.release()
			}
			select {
			case <-p.done:
			case <-time.After(3 * time.Second):
				if firstErr == nil {
					firstErr = fmt.Errorf("native service %s did not exit after kill", p.svc.Name)
				}
			}
		}
		return firstErr
	}

	for _, svc := range services {
		if !svc.Native {
			return "", nil, cleanup, fmt.Errorf("job %s service %s is not native; only native: true services can run on runtime native", jobID, svc.Name)
		}
		if len(svc.Command) == 0 {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s has no command", jobID, svc.Name)
		}
		// Prefer an explicit port from the ready probe (tcp:N / http:N/...).
		// Otherwise allocate an ephemeral port and publish it as PORT.
		// Probing a declared 6399 while the process was told PORT=ephemeral
		// (or the reverse) is how services timed out forever.
		port, hasDeclared := readyProbePort(svc.Ready)
		if !hasDeclared {
			p, perr := freeTCPPort()
			if perr != nil {
				return "", nil, cleanup, fmt.Errorf("job %s native service %s allocate port: %w", jobID, svc.Name, perr)
			}
			port = p
		}
		args := append([]string{}, svc.Command...)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = os.TempDir()
		cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", port))
		// User env is applied AFTER PORT so an explicit PORT= in service.env
		// would override Kiwi's authoritative port. Re-apply PORT last so the
		// probe and the process cannot disagree.
		for k, v := range svc.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("PORT=%d", port))
		configureProcess(cmd)
		if err := cmd.Start(); err != nil {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s start %s: %w", jobID, svc.Name, args[0], err)
		}
		release, serr := superviseChild(cmd)
		if serr != nil {
			_ = killProcess(cmd)
			return "", nil, cleanup, fmt.Errorf("job %s native service %s supervise: %w", jobID, svc.Name, serr)
		}
		p := &running{svc: svc, cmd: cmd, port: port, done: make(chan error, 1), release: release}
		go func(c *exec.Cmd, ch chan error) { ch <- c.Wait() }(cmd, p.done)
		procs = append(procs, p)
		if emit != nil {
			emit(fmt.Sprintf("started native %s pid=%d port=%d", svc.Name, cmd.Process.Pid, port))
		}
		key := strings.ToUpper(sanitizeServiceEnv(svc.Name))
		env[nativeServiceEnvPrefix+key+"_HOST"] = "127.0.0.1"
		env[nativeServiceEnvPrefix+key+"_PORT"] = strconv.Itoa(port)
	}

	for _, p := range procs {
		probe := p.svc.Ready
		if probe == "" {
			select {
			case err := <-p.done:
				return "", nil, cleanup, fmt.Errorf("job %s native service %s exited before ready: %v", jobID, p.svc.Name, err)
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		if err := waitNativeReady(ctx, probe, "127.0.0.1", p.port); err != nil {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s ready probe: %w", jobID, p.svc.Name, err)
		}
		if emit != nil {
			emit(fmt.Sprintf("ready %s (%s)", p.svc.Name, probe))
		}
	}
	return "native-services", env, cleanup, nil
}

// readyProbePort extracts a concrete TCP/HTTP port from a ready probe.
// Returns (0,false) when the probe has no numeric port (caller allocates).
func readyProbePort(probe string) (int, bool) {
	kind, rest, ok := strings.Cut(probe, ":")
	if !ok {
		return 0, false
	}
	if kind != "tcp" && kind != "http" {
		return 0, false
	}
	n := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		n = rest[:i]
	}
	port, err := strconv.Atoi(n)
	if err != nil || port <= 0 || port > 65535 {
		return 0, false
	}
	return port, true
}

func waitNativeReady(ctx context.Context, probe, host string, port int) error {
	kind, rest, ok := strings.Cut(probe, ":")
	if !ok {
		return fmt.Errorf("ready probe %q must look like tcp:PORT or http:PORT/path", probe)
	}
	deadline := time.Now().Add(serviceReadyTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch kind {
		case "tcp":
			p := rest
			if port > 0 {
				p = strconv.Itoa(port)
			}
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, p), time.Second)
			if err == nil {
				_ = conn.Close()
				return nil
			}
			lastErr = err
		case "http":
			p := port
			path := rest
			if i := strings.IndexByte(rest, '/'); i > 0 {
				if n, err := strconv.Atoi(rest[:i]); err == nil {
					p = n
					path = rest[i:]
				}
			}
			url := fmt.Sprintf("http://%s:%d%s", host, p, path)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				lastErr = err
				break
			}
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				break
			}
			_ = resp.Body.Close()
			// Only 2xx counts as ready: a 503 from a half-booted service
			// is not readiness.
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		default:
			return fmt.Errorf("unsupported ready probe kind %q", kind)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(serviceReadyPoll):
		}
	}
	return fmt.Errorf("timed out after %s: %w", serviceReadyTimeout, lastErr)
}

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func sanitizeServiceEnv(name string) string {
	var b strings.Builder
	prev := false
	for _, r := range name {
		ok := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			if !prev {
				b.WriteByte('_')
				prev = true
			}
			continue
		}
		b.WriteRune(r)
		prev = false
	}
	return b.String()
}

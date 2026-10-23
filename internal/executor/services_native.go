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
	"syscall"
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
		svc  pipeline.Service
		cmd  *exec.Cmd
		port int
		done chan error
	}
	var procs []*running
	env := map[string]string{}
	cleanup := func() error {
		var firstErr error
		for i := len(procs) - 1; i >= 0; i-- {
			p := procs[i]
			if p.cmd != nil && p.cmd.Process != nil {
				// SIGKILL the whole process group (sleep and its children).
				_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
				_ = syscall.Kill(p.cmd.Process.Pid, syscall.SIGKILL)
			}
			select {
			case <-p.done:
			case <-time.After(3 * time.Second):
				if firstErr == nil {
					firstErr = fmt.Errorf("native service %s did not exit after SIGKILL", p.svc.Name)
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
		port, perr := freeTCPPort()
		if perr != nil {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s allocate port: %w", jobID, svc.Name, perr)
		}
		args := append([]string{}, svc.Command...)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = os.TempDir()
		cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", port))
		for k, v := range svc.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s start %s: %w", jobID, svc.Name, args[0], err)
		}
		p := &running{svc: svc, cmd: cmd, port: port, done: make(chan error, 1)}
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
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				return nil
			}
			lastErr = err
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

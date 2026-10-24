package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// nativeServiceEnvPrefix is the env namespace native services publish.
// KIWI_SERVICE_<NAME>_HOST / _PORT always appear when a port was allocated.
const nativeServiceEnvPrefix = "KIWI_SERVICE_"

// nativePortClaims is the process-wide host-port ownership table for
// native services. Two concurrent jobs (matrix variants) must not both
// believe they own tcp:5432 on the same runner host.
var nativePortClaims = struct {
	sync.Mutex
	byPort map[int]string
}{byPort: map[int]string{}}

func claimNativePort(port int, owner string) error {
	nativePortClaims.Lock()
	defer nativePortClaims.Unlock()
	if prev, ok := nativePortClaims.byPort[port]; ok {
		return fmt.Errorf("host port %d already claimed by %s", port, prev)
	}
	nativePortClaims.byPort[port] = owner
	return nil
}

func releaseNativePort(port int) {
	nativePortClaims.Lock()
	defer nativePortClaims.Unlock()
	delete(nativePortClaims.byPort, port)
}

// childProc tracks one native service process so readiness can race
// process lifetime: a child that exits while the port probe succeeds
// (another process answering) must fail, never certify the wrong listener.
type childProc struct {
	cmd  *exec.Cmd
	done chan struct{}
	mu   sync.Mutex
	err  error
}

func (c *childProc) wait() error {
	err := c.cmd.Wait()
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
	close(c.done)
	return err
}

func (c *childProc) exited() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *childProc) exitErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// startNativeServices launches host-process services for a native job.
//
// Environment is whatever the executor already materialized (clean base +
// job env); os.Environ() is never imported. workRoot is the job workspace.
// Every service must declare a concrete ready port (validated in the
// pipeline); the port is claimed in the process-wide registry before start.
// Readiness races child exit so a port owned by some other process can
// never certify the service Kiwi launched.
func startNativeServices(ctx context.Context, jobID, workRoot string, baseEnv map[string]string, services []pipeline.Service, emit func(string)) (string, map[string]string, func() error, error) {
	if len(services) == 0 {
		return "", nil, func() error { return nil }, nil
	}
	type running struct {
		svc     pipeline.Service
		child   *childProc
		port    int
		release func()
	}
	var procs []*running
	env := map[string]string{}
	claimed := []int{}
	cleanup := func() error {
		var firstErr error
		for i := len(procs) - 1; i >= 0; i-- {
			p := procs[i]
			if p.child != nil && p.child.cmd != nil {
				_ = terminateProcess(p.child.cmd)
				_ = killProcess(p.child.cmd)
			}
			if p.release != nil {
				p.release()
			}
			if p.child != nil {
				select {
				case <-p.child.done:
				case <-time.After(3 * time.Second):
					if firstErr == nil {
						firstErr = fmt.Errorf("native service %s did not exit after kill", p.svc.Name)
					}
				}
			}
		}
		for _, port := range claimed {
			releaseNativePort(port)
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
		probe, perr := pipeline.ParseReadyProbe(svc.Ready)
		if perr != nil {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s: %w", jobID, svc.Name, perr)
		}
		port := int(probe.Port)
		owner := jobID + "/" + svc.Name
		if err := claimNativePort(port, owner); err != nil {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s: %w", jobID, svc.Name, err)
		}
		claimed = append(claimed, port)
		// Fail early if something else already listens on the claimed port.
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond); err == nil {
			_ = conn.Close()
			return "", nil, cleanup, fmt.Errorf("job %s native service %s: host port %d is already in use before start", jobID, svc.Name, port)
		}

		args := append([]string{}, svc.Command...)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		if workRoot != "" {
			cmd.Dir = workRoot
		} else {
			cmd.Dir = os.TempDir()
		}
		// Executor-resolved environment only (never os.Environ).
		cmd.Env = envMapToSlice(baseEnv)
		for k, v := range svc.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		// PORT last so service.env cannot override the authoritative port.
		cmd.Env = append(cmd.Env, fmt.Sprintf("PORT=%d", port))
		configureProcess(cmd)

		stdoutR, stdoutW, perr := os.Pipe()
		if perr != nil {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s stdout pipe: %w", jobID, svc.Name, perr)
		}
		stderrR, stderrW, perr := os.Pipe()
		if perr != nil {
			_ = stdoutR.Close()
			_ = stdoutW.Close()
			return "", nil, cleanup, fmt.Errorf("job %s native service %s stderr pipe: %w", jobID, svc.Name, perr)
		}
		cmd.Stdout = stdoutW
		cmd.Stderr = stderrW

		if err := cmd.Start(); err != nil {
			_ = stdoutW.Close()
			_ = stderrW.Close()
			_ = stdoutR.Close()
			_ = stderrR.Close()
			return "", nil, cleanup, fmt.Errorf("job %s native service %s start %s: %w", jobID, svc.Name, args[0], err)
		}
		// Parent closes writer ends so streamLines sees EOF when the child exits.
		_ = stdoutW.Close()
		_ = stderrW.Close()
		if emit != nil {
			logPrefix := func(s string) string { return s }
			go streamLines(stdoutR, defaultMaxLine, func(line string) {
				emit(logPrefix("[" + svc.Name + "/out] " + line))
			})
			go streamLines(stderrR, defaultMaxLine, func(line string) {
				emit(logPrefix("[" + svc.Name + "/err] " + line))
			})
		} else {
			go func() { _, _ = io.Copy(io.Discard, stdoutR) }()
			go func() { _, _ = io.Copy(io.Discard, stderrR) }()
		}

		release, serr := superviseChild(cmd)
		if serr != nil {
			_ = killProcess(cmd)
			return "", nil, cleanup, fmt.Errorf("job %s native service %s supervise: %w", jobID, svc.Name, serr)
		}
		ch := &childProc{cmd: cmd, done: make(chan struct{})}
		go ch.wait()
		procs = append(procs, &running{svc: svc, child: ch, port: port, release: release})
		if emit != nil {
			emit(fmt.Sprintf("started native %s pid=%d port=%d", svc.Name, cmd.Process.Pid, port))
		}
		key := strings.ToUpper(sanitizeServiceEnv(svc.Name))
		env[nativeServiceEnvPrefix+key+"_HOST"] = "127.0.0.1"
		env[nativeServiceEnvPrefix+key+"_PORT"] = strconv.Itoa(port)
	}

	for _, p := range procs {
		if err := waitNativeReady(ctx, p.svc.Ready, "127.0.0.1", p.port, p.child); err != nil {
			return "", nil, cleanup, fmt.Errorf("job %s native service %s ready probe: %w", jobID, p.svc.Name, err)
		}
		if emit != nil {
			emit(fmt.Sprintf("ready %s (%s)", p.svc.Name, p.svc.Ready))
		}
	}
	return "native-services", env, cleanup, nil
}

func envMapToSlice(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

// waitNativeReady races the ready probe against child exit. A successful
// TCP/HTTP answer while the child has exited means the port belongs to
// some other process; that must never count as ready for this service.
func waitNativeReady(ctx context.Context, probeSpec, host string, port int, child *childProc) error {
	probe, err := pipeline.ParseReadyProbe(probeSpec)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(serviceReadyTimeout)
	var lastErr error
	checkAlive := func() error {
		if child != nil && child.exited() {
			return fmt.Errorf("process exited before ready (exit=%v)", child.exitErr())
		}
		return nil
	}
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := checkAlive(); err != nil {
			return err
		}
		switch probe.Kind {
		case pipeline.ReadyProbeTCP:
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(probe.Port))), time.Second)
			if err == nil {
				_ = conn.Close()
				if err := checkAlive(); err != nil {
					return err
				}
				return nil
			}
			lastErr = err
		case pipeline.ReadyProbeHTTP:
			url := fmt.Sprintf("http://%s:%d%s", host, probe.Port, probe.Path)
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
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if err := checkAlive(); err != nil {
					return err
				}
				return nil
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		default:
			return fmt.Errorf("unsupported ready probe kind %q", probe.Kind)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(serviceReadyPoll):
		}
	}
	if err := checkAlive(); err != nil {
		return err
	}
	return fmt.Errorf("timed out after %s: %w", serviceReadyTimeout, lastErr)
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

// readyProbePort is the executor-local shim over the shared pipeline parser.
func readyProbePort(probe string) (int, bool) {
	p, err := pipeline.ParseReadyProbe(probe)
	if err != nil || (p.Kind != pipeline.ReadyProbeTCP && p.Kind != pipeline.ReadyProbeHTTP) || p.Port == 0 {
		return 0, false
	}
	return int(p.Port), true
}

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
// believe they own tcp:5432 on the same runner host. The in-memory map is
// the fast path; claimNativePort also takes a durable per-port lock file
// under the system temp dir so TWO RUNNER PROCESSES on one host cannot
// both claim the same port (the previous process-local gap). A lock whose
// recorded owner PID is dead is reclaimed; a live foreign owner fails
// closed. The pre-start dial still catches foreign listeners that never
// took the lock.
var nativePortClaims = struct {
	sync.Mutex
	byPort map[int]string
}{byPort: map[int]string{}}

// nativePortClaimDir is the host-wide lock directory for native port
// ownership (one file per TCP port). Empty owner/pid means invalid.
var nativePortClaimDir = func() string {
	return filepath.Join(os.TempDir(), "kiwi-native-port-claims")
}

func claimNativePort(port int, owner string) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid host port %d", port)
	}
	nativePortClaims.Lock()
	if prev, ok := nativePortClaims.byPort[port]; ok {
		nativePortClaims.Unlock()
		return fmt.Errorf("host port %d already claimed by %s", port, prev)
	}
	// Durable cross-process claim before accepting the in-memory one.
	if err := claimNativePortFile(port, owner); err != nil {
		nativePortClaims.Unlock()
		return err
	}
	nativePortClaims.byPort[port] = owner
	nativePortClaims.Unlock()
	return nil
}

func releaseNativePort(port int) {
	nativePortClaims.Lock()
	delete(nativePortClaims.byPort, port)
	nativePortClaims.Unlock()
	releaseNativePortFile(port)
}

// claimNativePortFile takes O_CREATE|O_EXCL ownership of port in the
// host-wide claim directory. A lock left by a dead PID is reclaimed; a
// lock held by a live process fails closed.
func claimNativePortFile(port int, owner string) error {
	dir := nativePortClaimDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("host port %d claim dir: %w", port, err)
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.lock", port))
	payload := []byte(fmt.Sprintf("pid=%d\nowner=%s\n", os.Getpid(), owner))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err == nil {
		_, werr := f.Write(payload)
		cerr := f.Close()
		return errors.Join(werr, cerr)
	}
	if !os.IsExist(err) {
		return fmt.Errorf("host port %d claim: %w", port, err)
	}
	// Existing lock: reclaim only when the recorded owner process is gone.
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		return fmt.Errorf("host port %d already claimed (unreadable lock): %w", port, rerr)
	}
	var lockPID int
	var lockOwner string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "pid=") {
			fmt.Sscanf(line, "pid=%d", &lockPID)
		}
		if strings.HasPrefix(line, "owner=") {
			lockOwner = strings.TrimPrefix(line, "owner=")
		}
	}
	if lockPID > 0 && processAlive(lockPID) {
		return fmt.Errorf("host port %d already claimed by %s (pid %d)", port, lockOwner, lockPID)
	}
	// Stale lock (dead owner): take it over.
	if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
		return fmt.Errorf("host port %d stale lock remove: %w", port, rmErr)
	}
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("host port %d claim after stale release: %w", port, err)
	}
	_, werr := f.Write(payload)
	cerr := f.Close()
	return errors.Join(werr, cerr)
}

func releaseNativePortFile(port int) {
	path := filepath.Join(nativePortClaimDir(), fmt.Sprintf("%d.lock", port))
	// Only remove OUR lock: a foreign live owner must keep its file.
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if !strings.Contains(string(b), fmt.Sprintf("pid=%d\n", os.Getpid())) {
		return
	}
	_ = os.Remove(path)
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
// CONTRACT (transactional):
//   - On error, every resource acquired during this call (child process,
//     supervision handle, pipe, host-port claim) has already been rolled
//     back before the error is returned. Callers must NOT invoke a
//     returned cleanup after a non-nil error.
//   - On success, the returned cleanup is idempotent and must run when the
//     job finishes (it releases processes, supervision, and port claims).
//
// Environment is executor-materialized (never os.Environ()). Executables
// resolve against that environment's PATH so the child cannot run a
// different binary than the effective toolchain claims.
// Readiness races child exit so a foreign listener cannot certify our child.
// NativeServiceInfo is the durable identity of one started native service
// recorded in the runner's runtime ledger for crash recovery.
type NativeServiceInfo struct {
	Name  string `json:"name"`
	Port  int    `json:"port"`
	PID   int    `json:"pid"`
	PGID  int    `json:"pgid"`
	Start string `json:"start,omitempty"`
}

// startNativeServices launches host-process services for a native job.
// cgroupParent, when non-empty, is the durable job cgroup the children are
// clone-into'd (Linux UseCgroupFD) before any userspace instruction runs.
func startNativeServices(ctx context.Context, jobID, workRoot string, baseEnv map[string]string, services []pipeline.Service, cgroupParent string, onStart func([]NativeServiceInfo) error, emit func(string)) (string, map[string]string, []NativeServiceInfo, func() error, error) {
	if len(services) == 0 {
		return "", nil, nil, func() error { return nil }, nil
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
	var once sync.Once
	var cleanupErr error
	cleanup := func() error {
		once.Do(func() {
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
			cleanupErr = firstErr
		})
		return cleanupErr
	}
	// Transactional: any error path rolls back before the caller sees it.
	var err error
	defer func() {
		if err != nil {
			_ = cleanup()
		}
	}()
	var infos []NativeServiceInfo
	fail := func(format string, a ...any) (string, map[string]string, []NativeServiceInfo, func() error, error) {
		err = fmt.Errorf(format, a...)
		return "", nil, nil, nil, err
	}
	failInfo := fail

	for _, svc := range services {
		if !svc.Native {
			return failInfo("job %s service %s is not native; only native: true services can run on runtime native", jobID, svc.Name)
		}
		if len(svc.Command) == 0 {
			return failInfo("job %s native service %s has no command", jobID, svc.Name)
		}
		probe, perr := pipeline.ParseReadyProbe(svc.Ready)
		if perr != nil {
			return failInfo("job %s native service %s: %w", jobID, svc.Name, perr)
		}
		port := int(probe.Port)
		owner := jobID + "/" + svc.Name
		if cerr := claimNativePort(port, owner); cerr != nil {
			return failInfo("job %s native service %s: %w", jobID, svc.Name, cerr)
		}
		claimed = append(claimed, port)
		// Fail early if something else already listens on the claimed port.
		if conn, derr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond); derr == nil {
			_ = conn.Close()
			return failInfo("job %s native service %s: host port %d is already in use before start", jobID, svc.Name, port)
		}

		args := append([]string{}, svc.Command...)
		// Fully merged effective environment: svc.Env may change PATH, so
		// resolve argv0 against base+svc (not base alone). Relative paths
		// ("./bin/tool") resolve against cmd.Dir, matching Go's Dir
		// contract for the process that will actually run.
		workDir := workRoot
		if workDir == "" {
			workDir = os.TempDir()
		}
		effectiveEnv := mergeEnvMap(baseEnv, svc.Env)
		bin, rerr := resolveExecutable(args[0], workDir, effectiveEnv)
		if rerr != nil {
			return failInfo("job %s native service %s: %w", jobID, svc.Name, rerr)
		}
		args[0] = bin
		envSlice := envMapToSlice(effectiveEnv)
		envSlice = append(envSlice, fmt.Sprintf("PORT=%d", port))
		closeCgroupFD := func() {}
		// Start is single-shot: a UseCgroupFD failure must rebuild a fresh
		// command (see native.go), not call Start twice on the same Cmd.
		newCmd := func() *exec.Cmd {
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			cmd.Dir = workDir
			cmd.Env = envSlice
			return cmd
		}
		cmd := newCmd()
		if cgroupParent != "" {
			cl, err := configureProcessCgroup(cmd, cgroupParent)
			if err != nil {
				configureProcess(cmd)
			} else {
				closeCgroupFD = cl
			}
		} else {
			configureProcess(cmd)
		}

		stdoutR, stdoutW, perr := os.Pipe()
		if perr != nil {
			closeCgroupFD()
			return failInfo("job %s native service %s stdout pipe: %w", jobID, svc.Name, perr)
		}
		stderrR, stderrW, perr := os.Pipe()
		if perr != nil {
			closeCgroupFD()
			_ = stdoutR.Close()
			_ = stdoutW.Close()
			return failInfo("job %s native service %s stderr pipe: %w", jobID, svc.Name, perr)
		}
		cmd.Stdout = stdoutW
		cmd.Stderr = stderrW

		usedCgroupFD := cgroupFDActive(cmd)
		serr := cmd.Start()
		if serr != nil && usedCgroupFD {
			closeCgroupFD()
			closeCgroupFD = func() {}
			cmd = newCmd()
			configureProcess(cmd)
			cmd.Stdout = stdoutW
			cmd.Stderr = stderrW
			usedCgroupFD = false
			serr = cmd.Start()
		}
		if serr != nil {
			closeCgroupFD()
			_ = stdoutW.Close()
			_ = stderrW.Close()
			_ = stdoutR.Close()
			_ = stderrR.Close()
			return failInfo("job %s native service %s start %s: %w", jobID, svc.Name, bin, serr)
		}
		closeCgroupFD()
		_ = stdoutW.Close()
		_ = stderrW.Close()
		if emit != nil {
			go streamLines(stdoutR, defaultMaxLine, func(line string) {
				emit("[" + svc.Name + "/out] " + line)
			})
			go streamLines(stderrR, defaultMaxLine, func(line string) {
				emit("[" + svc.Name + "/err] " + line)
			})
		} else {
			go func() { _, _ = io.Copy(io.Discard, stdoutR) }()
			go func() { _, _ = io.Copy(io.Discard, stderrR) }()
		}

		release, serr := superviseChild(cmd)
		if serr != nil {
			// Same contract as the ordinary native-step path: an unsupervised
			// child must not run. Terminate the tree, force-kill, and reap
			// through the bounded primitive so no zombie or unsupervised
			// process survives a Windows Job Object assign failure.
			_ = terminateProcess(cmd)
			_ = killProcess(cmd)
			_ = reapKilledCommand(cmd, killGrace)
			_ = stdoutR.Close()
			_ = stderrR.Close()
			return failInfo("job %s native service %s supervise: %w", jobID, svc.Name, serr)
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
		pgid := cmd.Process.Pid // Setpgid: child is group leader
		infos = append(infos, NativeServiceInfo{
			Name: svc.Name, Port: port,
			PID: cmd.Process.Pid, PGID: pgid,
			Start: ProcessStartStamp(cmd.Process.Pid),
		})
		if onStart != nil {
			if oerr := onStart(append([]NativeServiceInfo{}, infos...)); oerr != nil {
				return fail("job %s native service %s record ownership: %w", jobID, svc.Name, oerr)
			}
		}
	}

	for _, p := range procs {
		if rerr := waitNativeReady(ctx, p.svc.Ready, "127.0.0.1", p.port, p.child); rerr != nil {
			return failInfo("job %s native service %s ready probe: %w", jobID, p.svc.Name, rerr)
		}
		if emit != nil {
			emit(fmt.Sprintf("ready %s (%s)", p.svc.Name, p.svc.Ready))
		}
	}
	return "native-services", env, infos, cleanup, nil
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

// ProcessStartStamp is a best-effort identity for a live PID so crash
// recovery can refuse to kill a recycled PID. Linux uses /proc starttime;
// other Unixes fall back to `ps -o start=`.
func ProcessStartStamp(pid int) string {
	if pid <= 0 {
		return ""
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		s := string(b)
		if i := strings.LastIndex(s, ")"); i >= 0 {
			fields := strings.Fields(s[i+1:])
			// fields[0] is state after comm; starttime is the 20th field
			// after comm (index 19 in this slice).
			if len(fields) > 19 {
				return "t:" + fields[19]
			}
		}
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "start=").Output()
	if err == nil {
		return "ps:" + strings.TrimSpace(string(out))
	}
	return ""
}

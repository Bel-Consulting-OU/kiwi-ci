package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// upStartupTimeout bounds how long Up waits for the control plane to answer
// /readiness before giving up. The whole stack is in-process, so this only
// covers listener bind and store construction.
const upStartupTimeout = 30 * time.Second

// upShutdownTimeout bounds the wait for the in-process peers to exit after
// cancellation. Run() joins everything it spawned, so this is a diagnostic
// backstop, not the normal path.
const upShutdownTimeout = 20 * time.Second

// upTokenFile persists the generated shared bearer token inside the stack's
// state directory so a restarted `kiwi up` keeps the same admin/runner
// credential without any operator bookkeeping.
const upTokenFile = "up-token"

// Up runs the single-machine Kiwi stack: ONE process running the control
// plane and one local runner, with the durable ledger, cache, artifact and
// evidence state rooted in a single state directory. It is the zero
// administration entry point (audit recommendation: "kiwi up" should give a
// developer the whole stack on one laptop) and deliberately dev-mode only:
// no production contract, no TLS, no PostgreSQL, no remote runners — those
// remain explicit `kiwi server` / `kiwi runner` deployments with their own
// flags.
//
// Everything Up starts is composed from the SAME app.Server and app.Runner
// entry points the dedicated commands use, so the single-machine mode can
// never drift into a second, weaker server implementation.
func Up(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	listen := fs.String("listen", "", "control-plane listen address (default: a free 127.0.0.1 port)")
	dataDir := fs.String("data-dir", "", "persistent stack state directory (default: ~/.kiwi/up)")
	token := fs.String("token", "", "shared admin/runner bearer token (default: generated once and persisted in the state directory)")
	labels := fs.String("labels", "up-local", "comma-separated labels the local runner registers with")
	allowRemote := fs.Bool("allow-insecure-remote", false, "allow a non-loopback PLAINTEXT control plane (the bearer token then travels in cleartext; NOT recommended)")
	showToken := fs.Bool("show-token", false, "print the bearer token even when it was reused from the state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("up takes no arguments (got %d)", fs.NArg())
	}
	explicitToken := strings.TrimSpace(*token) != ""
	if err := upValidateLoopback(*listen, *allowRemote); err != nil {
		return err
	}

	dir, err := upStateDir(*dataDir)
	if err != nil {
		return err
	}
	if err := upEnsureStateDir(dir); err != nil {
		return err
	}
	bearer, freshToken, err := upBearerToken(dir, *token)
	if err != nil {
		return err
	}
	// Bind the control-plane listener OURSELVES and hand the bound listener
	// to the server. Reserving a port, closing the probe listener and letting
	// the server re-bind would leave a window in which a local process takes
	// the freed port, answers the unauthenticated /readiness probe, and then
	// receives the runner's bearer credential on its first request.
	ln, addr, err := upBindControlPlane(*listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Hand the listener to the server through the same seam the socket-level
	// tests use. The override is one-shot and restored as soon as the server
	// has either taken the listener or exited, so no other reader sees it.
	adopted := make(chan struct{})
	prevListen := listenControlPlane
	listenControlPlane = func(_, _ string) (net.Listener, error) {
		close(adopted)
		return ln, nil
	}
	var restoreOnce sync.Once
	restoreSeam := func() { restoreOnce.Do(func() { listenControlPlane = prevListen }) }
	defer restoreSeam()

	serverErr := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		serverErr <- Server(runCtx, []string{
			"--listen", addr,
			"--data-dir", dir,
			"--runner-token", bearer,
		})
	}()

	// The restore receive (or the server's exit / the startup bound) is the
	// synchronization point: the server goroutine's read of the seam
	// happens-before close(adopted), and the receive happens-before the
	// restore write.
	select {
	case <-adopted:
	case <-serverDone:
	case <-time.After(upStartupTimeout):
	}
	restoreSeam()

	if err := upWaitReady(runCtx, addr, serverDone, serverErr); err != nil {
		cancel()
		awaitDone(serverDone, upShutdownTimeout)
		return err
	}

	base := upBaseURL(addr)
	if !upIsLoopbackAddr(addr) {
		fmt.Fprintf(os.Stdout, "kiwi up: WARNING: control plane %s is exposed beyond loopback over PLAINTEXT HTTP; the bearer token travels in cleartext and anyone who can reach the port can administer this stack\n", addr)
	}
	fmt.Fprintf(os.Stdout, "kiwi up: control plane %s (dashboard %s/)\n", base, base)
	fmt.Fprintf(os.Stdout, "kiwi up: state directory %s\n", dir)
	switch {
	case freshToken:
		fmt.Fprintf(os.Stdout, "kiwi up: generated bearer token (stored 0600 at %s): %s\n", filepath.Join(dir, upTokenFile), bearer)
	case explicitToken:
		// The operator supplied the token; it is not echoed back.
	case *showToken:
		fmt.Fprintf(os.Stdout, "kiwi up: admin/runner token: %s\n", bearer)
	default:
		fmt.Fprintf(os.Stdout, "kiwi up: using the stored bearer token at %s (pass --show-token to print it)\n", filepath.Join(dir, upTokenFile))
	}
	fmt.Fprintf(os.Stdout, "kiwi up: runner labels: %s\n", *labels)

	runnerArgs := []string{
		"--server", base,
		"--token", bearer,
		"--name", "up-local",
		"--identity-dir", filepath.Join(dir, "runner"),
	}
	if v := strings.TrimSpace(*labels); v != "" {
		runnerArgs = append(runnerArgs, "--labels", v)
	}
	runnerErr := make(chan error, 1)
	runnerDone := make(chan struct{})
	go func() {
		defer close(runnerDone)
		runnerErr <- Runner(runCtx, runnerArgs)
	}()

	// Every peer is joined through its DONE channel (closed after the error
	// value was sent), so an already-consumed error channel can never park
	// the shutdown path for the full bound.
	select {
	case <-runnerDone:
		cancel()
		awaitDone(serverDone, upShutdownTimeout)
		if err := doneError(runnerErr); err != nil {
			return fmt.Errorf("local runner: %w", err)
		}
		return nil
	case <-serverDone:
		cancel()
		awaitDone(runnerDone, upShutdownTimeout)
		if err := doneError(serverErr); err != nil {
			return fmt.Errorf("control plane: %w", err)
		}
		return nil
	case <-ctx.Done():
		fmt.Fprintln(os.Stdout, "kiwi up: shutting down")
		cancel()
		awaitDone(runnerDone, upShutdownTimeout)
		awaitDone(serverDone, upShutdownTimeout)
		return nil
	}
}

// upStateDir resolves the persistent state directory. The default lives
// beside the runner's existing ~/.kiwi tree so one laptop has one Kiwi home.
func upStateDir(explicit string) (string, error) {
	if v := strings.TrimSpace(explicit); v != "" {
		abs, err := filepath.Abs(v)
		if err != nil {
			return "", fmt.Errorf("--data-dir: %w", err)
		}
		return abs, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("no home directory for the default state directory (%v); pass --data-dir", err)
	}
	return filepath.Join(home, ".kiwi", "up"), nil
}

// upEnsureStateDir creates the state directory and proves it is a real
// directory this user can trust before any credential is read from or written
// to it: no symlink, owned by the effective user (unix), and tightened to
// 0700 so a pre-existing permissive directory cannot expose the persisted
// token or the server's keys.
func upEnsureStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat state directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("state directory %s is not a real directory (refusing a symlink or non-directory path)", dir)
	}
	if err := verifyUpStateDirOwner(info); err != nil {
		return fmt.Errorf("state directory %s: %w", dir, err)
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("tighten state directory %s to 0700: %w", dir, err)
		}
	}
	return nil
}

// upBearerToken resolves the shared token: an explicit --token wins;
// otherwise the persisted token is reused after proving the file is a real
// regular file owned by this user with mode 0600; otherwise one is generated
// and created exclusively (O_EXCL, so a concurrently planted symlink or file
// can never be written through). fresh reports a first generation.
func upBearerToken(dir, explicit string) (token string, fresh bool, err error) {
	if v := strings.TrimSpace(explicit); v != "" {
		return v, false, nil
	}
	path := filepath.Join(dir, upTokenFile)
	if data, rerr := readUpTokenFile(path); rerr == nil {
		return data, false, nil
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return "", false, rerr
	}
	raw := make([]byte, 32)
	if _, cerr := rand.Read(raw); cerr != nil {
		return "", false, fmt.Errorf("generate bearer token: %w", cerr)
	}
	token = hex.EncodeToString(raw)
	f, werr := createUpTokenExclusive(path)
	if werr != nil {
		if errors.Is(werr, os.ErrExist) {
			return "", false, fmt.Errorf("token file %s appeared while starting (remove it to regenerate)", path)
		}
		return "", false, fmt.Errorf("persist bearer token: %w", werr)
	}
	if _, werr := f.Write([]byte(token + "\n")); werr != nil {
		_ = f.Close()
		return "", false, fmt.Errorf("persist bearer token: %w", werr)
	}
	if werr := f.Sync(); werr != nil {
		_ = f.Close()
		return "", false, fmt.Errorf("persist bearer token: %w", werr)
	}
	if werr := f.Close(); werr != nil {
		return "", false, fmt.Errorf("persist bearer token: %w", werr)
	}
	return token, true, nil
}

// readUpTokenFile reads and verifies the persisted token. The open is
// symlink-refusing on unix (O_NOFOLLOW) and the descriptor itself is
// re-verified, so a path swapped between check and open can never smuggle a
// foreign token into this stack. A file that exists but is not a trustworthy
// 0600 regular file fails closed with an actionable message instead of being
// adopted or silently rotated.
func readUpTokenFile(path string) (string, error) {
	f, err := openUpTokenRead(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat token file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("token file %s is not a regular file (remove it to regenerate)", path)
	}
	if err := verifyUpTokenFileOwner(info); err != nil {
		return "", fmt.Errorf("token file %s: %w", path, err)
	}
	if err := verifyUpTokenFileMode(info); err != nil {
		return "", fmt.Errorf("token file %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", fmt.Errorf("read token file %s: %w", path, err)
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "", fmt.Errorf("token file %s is empty (remove it to generate a new token)", path)
	}
	return v, nil
}

// upBindControlPlane binds the control-plane listener for the single-machine
// stack and returns the bound listener plus its concrete address. Binding
// here (instead of reserving a port and letting the server re-bind) is what
// makes the credential handoff race-free: the only server that can serve this
// stack is the one served from the listener Up holds.
func upBindControlPlane(listen string) (net.Listener, string, error) {
	v := strings.TrimSpace(listen)
	if v == "" {
		v = "127.0.0.1:0"
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return nil, "", fmt.Errorf("invalid --listen %q (want host:port): %w", listen, err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, "", fmt.Errorf("bind control plane %s: %w", v, err)
	}
	return ln, ln.Addr().String(), nil
}

// upValidateLoopback refuses a PLAINTEXT control plane reachable beyond
// loopback unless the operator explicitly opted in: the stack's bearer token
// (admin + runner) would otherwise travel in cleartext to anyone who can
// reach the port, and dev-mode has no TLS. A wildcard host (empty or
// 0.0.0.0/::) binds every interface, so it needs the same opt-in.
func upValidateLoopback(listen string, allow bool) error {
	v := strings.TrimSpace(listen)
	if v == "" || allow {
		return nil
	}
	host, _, err := net.SplitHostPort(v)
	if err != nil {
		return nil // upBindControlPlane reports the malformed address
	}
	if host == "" {
		return fmt.Errorf("refusing --listen %q: an empty host binds every interface; use 127.0.0.1:PORT or pass --allow-insecure-remote (the bearer token travels in cleartext)", v)
	}
	if upLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("refusing non-loopback plaintext control plane %q: use a loopback --listen or pass --allow-insecure-remote (the bearer token travels in cleartext)", v)
}

// upLoopbackHost reports whether a listen host is loopback-only.
func upLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// upIsLoopbackAddr reports whether a resolved listen address stays on
// loopback, including the wildcard forms upBaseURL maps for clients.
func upIsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "", "0.0.0.0", "::":
		return false
	}
	return upLoopbackHost(host)
}

// upBaseURL converts a listen address into a client base URL, mapping
// wildcard hosts onto loopback: a local stack is always reachable at 127.0.0.1.
func upBaseURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// upWaitReady polls the control plane's unauthenticated /readiness probe
// until it answers 200, the server exits, or the startup bound expires. The
// server's exit error (sent before the done channel closed) is surfaced here.
func upWaitReady(ctx context.Context, addr string, serverDone <-chan struct{}, serverErr <-chan error) error {
	client := &http.Client{Timeout: 2 * time.Second}
	url := upBaseURL(addr) + "/readiness"
	deadline := time.Now().Add(upStartupTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-serverDone:
			if err := doneError(serverErr); err != nil {
				return fmt.Errorf("control plane exited during startup: %w", err)
			}
			return errors.New("control plane exited during startup")
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("control plane on %s did not become ready within %s", addr, upStartupTimeout)
}

// awaitDone waits up to d for an in-process peer's done channel to close, so
// a shutdown path can never hang forever on a stuck component.
func awaitDone(ch <-chan struct{}, d time.Duration) {
	select {
	case <-ch:
	case <-time.After(d):
	}
}

// doneError reads a peer's already-sent result without blocking; callers use
// it only after that peer's done channel closed.
func doneError(ch <-chan error) error {
	select {
	case err := <-ch:
		return err
	default:
		return nil
	}
}

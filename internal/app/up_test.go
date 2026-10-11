package app

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// upRunnerDTO decodes the fields the single-machine test asserts from the
// admin runner listing.
type upRunnerDTO struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Labels []string `json:"labels"`
}

// TestUpRunsSingleMachineStack drives `kiwi up` end to end: one process
// serving the control plane and a local runner registered against it, with
// the state directory holding the persisted token. It then cancels the stack
// and requires every in-process peer to return.
func TestUpRunsSingleMachineStack(t *testing.T) {
	if testing.Short() {
		t.Skip("single-machine stack startup is an integration-shaped test")
	}
	dir := t.TempDir()
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Up(ctx, []string{
			"--listen", addr,
			"--data-dir", dir,
			"--token", "up-test-token",
			"--labels", "up-test-label",
		})
	}()

	base := "http://" + addr
	waitReadiness(t, base+"/readiness")
	waitRunnerLabel(t, base, "up-test-token", "up-test-label")

	// An explicit --token is not persisted; that is the documented
	// precedence, so the state directory stays without a token file.
	if _, err := os.Stat(filepath.Join(dir, upTokenFile)); !os.IsNotExist(err) {
		t.Fatalf("explicit token must not be persisted, stat err = %v", err)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Up returned %v after cancellation", err)
		}
	case <-time.After(upStartupTimeout + upShutdownTimeout):
		t.Fatal("Up did not return after context cancellation")
	}
}

// TestUpReportsBindFailureImmediately proves a failed control-plane bind is
// surfaced at once: the startup path must not re-wait on the already-consumed
// server error channel (which used to stall the CLI for upShutdownTimeout).
func TestUpReportsBindFailureImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("bind failure timing is an integration-shaped test")
	}
	// Occupy every port we will ask for by holding the listener ourselves.
	ln, addr, err := upBindControlPlane("")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	start := time.Now()
	err = Up(context.Background(), []string{
		"--listen", addr,
		"--data-dir", t.TempDir(),
		"--token", "occupied-token",
	})
	if err == nil {
		t.Fatal("Up accepted an occupied listen address")
	}
	if elapsed := time.Since(start); elapsed > upShutdownTimeout/2 {
		t.Fatalf("Up took %s to report the bind failure (want immediate)", elapsed)
	}
	if !strings.Contains(err.Error(), "bind control plane") {
		t.Fatalf("Up error = %v, want the bind failure", err)
	}
}

// waitReadiness polls an unauthenticated readiness probe until it answers
// 200, failing the test on a non-200 that persists to the deadline.
func waitReadiness(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(upStartupTimeout)
	client := &http.Client{Timeout: 2 * time.Second}
	var last string
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("readiness probe %s never answered 200 (last: %s)", url, last)
}

// waitRunnerLabel polls the admin runner listing until a runner carrying the
// expected label is registered.
func waitRunnerLabel(t *testing.T, base, token, label string) {
	t.Helper()
	deadline := time.Now().Add(upStartupTimeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, base+"/api/v1/runners", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err == nil {
			var runners []upRunnerDTO
			dec := json.NewDecoder(resp.Body)
			derr := dec.Decode(&runners)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && derr == nil {
				for _, r := range runners {
					for _, l := range r.Labels {
						if l == label {
							return
						}
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no runner with label %q registered within %s", label, upStartupTimeout)
}

// TestUpStateDirAndTokenHelpers pins the state-directory and token
// precedence: explicit values win, the generated token is persisted 0600 and
// reused, and a second call never rotates a live stack's credential.
func TestUpStateDirAndTokenHelpers(t *testing.T) {
	dir := t.TempDir()
	if err := upEnsureStateDir(dir); err != nil {
		t.Fatal(err)
	}

	got, err := upStateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("upStateDir(%q) = %q, want an absolute path", dir, got)
	}

	explicit, fresh, err := upBearerToken(dir, "explicit-token")
	if err != nil {
		t.Fatal(err)
	}
	if explicit != "explicit-token" || fresh {
		t.Fatalf("explicit token = %q fresh=%v, want the explicit value and fresh=false", explicit, fresh)
	}
	if _, err := os.Stat(filepath.Join(dir, upTokenFile)); !os.IsNotExist(err) {
		t.Fatalf("explicit token must not be persisted, stat err = %v", err)
	}

	first, fresh, err := upBearerToken(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if !fresh || len(first) != 64 {
		t.Fatalf("generated token %q fresh=%v, want 64 hex chars and fresh=true", first, fresh)
	}
	info, err := os.Stat(filepath.Join(dir, upTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("token file mode = %o, want 600", perm)
		}
	}

	second, fresh, err := upBearerToken(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if second != first || fresh {
		t.Fatalf("second resolution = %q fresh=%v, want the persisted %q and fresh=false", second, fresh, first)
	}
}

// TestUpTokenFileRefusals proves the credential file fails closed instead of
// being adopted or written through: a symlinked state directory, an empty
// token file, a permissive mode and a symlinked token file are all refused,
// and a permissive state directory is tightened before anything is written.
func TestUpTokenFileRefusals(t *testing.T) {
	t.Run("state dir tightened", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "stack")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := upEnsureStateDir(dir); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o700 {
				t.Fatalf("state dir mode = %o, want 700", perm)
			}
		}
	})
	t.Run("empty token file", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "stack")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, upTokenFile), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := upBearerToken(dir, ""); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("empty token file = %v, want an empty-file refusal", err)
		}
	})
	if runtime.GOOS == "windows" {
		t.Skip("symlink and POSIX-mode refusals are unix-specific")
	}
	t.Run("permissive token file", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "stack")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, upTokenFile)
		if err := os.WriteFile(path, []byte("planted\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := upBearerToken(dir, ""); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("permissive token file = %v, want a mode refusal", err)
		}
	})
	t.Run("symlinked token file", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "stack")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "planted")
		if err := os.WriteFile(target, []byte("planted\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, upTokenFile)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := upBearerToken(dir, ""); err == nil {
			t.Fatal("symlinked token file was adopted")
		}
	})
	t.Run("symlinked state dir", func(t *testing.T) {
		realDir := t.TempDir()
		link := filepath.Join(t.TempDir(), "stack-link")
		if err := os.Symlink(realDir, link); err != nil {
			t.Fatal(err)
		}
		if err := upEnsureStateDir(link); err == nil {
			t.Fatal("symlinked state directory accepted")
		}
	})
}

// TestUpBindControlPlaneAndBaseURL pins the address binding: an empty or :0
// address resolves to a concrete free 127.0.0.1 port on a held listener,
// fixed addresses pass through verbatim, invalid addresses are refused, and
// wildcard binds map onto loopback for clients.
func TestUpBindControlPlaneAndBaseURL(t *testing.T) {
	ln, addr, err := upBindControlPlane("")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !strings.HasPrefix(addr, "127.0.0.1:") || strings.HasSuffix(addr, ":0") {
		t.Fatalf("default listen = %q, want a concrete 127.0.0.1 port", addr)
	}

	ln2, addr2, err := upBindControlPlane("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	if strings.HasSuffix(addr2, ":0") {
		t.Fatalf(":0 listen = %q, want a discovered concrete port", addr2)
	}

	if _, _, err := upBindControlPlane("not-an-address"); err == nil {
		t.Fatal("upBindControlPlane accepted an address without a port")
	}

	if got := upBaseURL("0.0.0.0:8080"); got != "http://127.0.0.1:8080" {
		t.Fatalf("upBaseURL wildcard = %q", got)
	}
	if got := upBaseURL("[::1]:9090"); got != "http://[::1]:9090" {
		t.Fatalf("upBaseURL loopback v6 = %q", got)
	}
}

// TestUpRejectsArguments keeps the single-machine command argument-free:
// positional arguments are a usage error, never silently ignored.
func TestUpRejectsArguments(t *testing.T) {
	if err := Up(context.Background(), []string{"extra"}); err == nil {
		t.Fatal("Up accepted a positional argument")
	}
}

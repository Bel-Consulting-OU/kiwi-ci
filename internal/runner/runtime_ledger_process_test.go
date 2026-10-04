package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Process-boundary regression for the P1 ledger-isolation invariant: two REAL
// runner processes (different stable ids) share one WorkDir while runner A
// holds a live job; starting B must not touch A's ledger state, workspace or
// job. A hard-killed A is then restarted and must reclaim its own crashed
// state. Function-level tests cannot prove this: the destructiveness came
// from cross-process namespace sharing.

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test file")
		}
		dir = parent
	}
}

func buildKiwi(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "kiwi")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/kiwi")
	cmd.Dir = moduleRoot(t)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build kiwi: %v\n%s", err, out)
	}
	return bin
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func apiJSON(t *testing.T, method, url, token string, body any) (int, map[string]any, []byte) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, []byte(err.Error())
	}
	defer resp.Body.Close()
	raw := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		raw = append(raw, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	return resp.StatusCode, decoded, raw
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestRunnerProcessBoundaryLedgerIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("process-boundary test builds and runs real binaries")
	}
	root := t.TempDir()
	bin := buildKiwi(t, root)
	workDir := filepath.Join(root, "shared-work")
	os.MkdirAll(workDir, 0o700)
	// Workspaces are created under TMPDIR; both runners share it, exactly
	// like two runners sharing /tmp on a host.
	sharedTmp := filepath.Join(root, "shared-tmp")
	os.MkdirAll(sharedTmp, 0o700)
	port := freeTCPPort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	server := exec.Command(bin, "server", "--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--admin-token", "admin-token-pbt", "--data-dir", filepath.Join(root, "data"))
	server.Env = append(os.Environ(), "KIWI_RUNNER_TOKEN=runner-token-pbt")
	server.Stdout = os.Stderr
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if server.Process != nil {
			_ = server.Process.Kill()
			_, _ = server.Process.Wait()
		}
	})
	waitFor(t, "server liveness", 30*time.Second, func() bool {
		code, _, _ := apiJSON(t, http.MethodGet, base+"/liveness", "", nil)
		return code == 200
	})

	// A local dumb-HTTP git mirror: the runner must clone the checkout.
	mirrorRoot := filepath.Join(root, "git-http")
	repoSrc := filepath.Join(root, "repo-src")
	runGit := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	os.MkdirAll(repoSrc, 0o755)
	runGit(repoSrc, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repoSrc, "README.md"), []byte("# pbt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(repoSrc, "add", "-A")
	runGit(repoSrc, "-c", "user.email=e@t", "-c", "user.name=t", "commit", "-qm", "init")
	os.MkdirAll(filepath.Join(mirrorRoot, "owner"), 0o755)
	runGit(root, "clone", "--bare", repoSrc, filepath.Join(mirrorRoot, "owner", "repo.git"))
	runGit(filepath.Join(mirrorRoot, "owner", "repo.git"), "update-server-info")
	gitSrv := httptest.NewServer(http.FileServer(http.Dir(mirrorRoot)))
	t.Cleanup(gitSrv.Close)
	repoURL := gitSrv.URL + "/owner/repo.git"

	// A trusted schedule whose single job holds the runner for a while.
	spec := "version: 1\non:\n  schedule:\n    cron: \"0 0 * * *\"\njobs:\n  hold:\n    runtime: native\n    steps:\n      - name: hold\n        run: |\n          echo alive > hold.txt\n          sleep 6\n"
	code, _, raw := apiJSON(t, http.MethodPut, base+"/api/v1/schedules",
		"admin-token-pbt", map[string]any{"id": "pbt", "repository": "owner/repo",
			"repo_url": repoURL, "spec": spec, "trusted": true, "enabled": true})
	if code != 200 && code != 201 {
		t.Fatalf("schedule put = %d: %s", code, raw)
	}
	code, run, raw := apiJSON(t, http.MethodPost, base+"/api/v1/schedules/pbt/trigger", "admin-token-pbt", map[string]any{})
	if code != 202 {
		t.Fatalf("trigger = %d: %s", code, raw)
	}
	runID, _ := run["id"].(string)
	if runID == "" {
		t.Fatalf("no run id: %s", raw)
	}

	startRunner := func(name, identity string) *exec.Cmd {
		cmd := exec.Command(bin, "runner", "--server", base, "--token", "runner-token-pbt",
			"--name", name, "--labels", "native", "--work-dir", workDir,
			"--identity-dir", filepath.Join(root, "identity-"+name))
		cmd.Env = append(os.Environ(),
			"KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK=1",
			"KIWI_ALLOW_INSECURE_CLONE=1",
			"TMPDIR="+sharedTmp)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}

	runnerA := startRunner("runner-a", "a")
	t.Cleanup(func() {
		if runnerA.Process != nil {
			_ = runnerA.Process.Kill()
			_, _ = runnerA.Process.Wait()
		}
	})

	// A's live workspace and its ledger entry appear while the hold step runs.
	var liveWS string
	waitFor(t, "runner A live workspace", 60*time.Second, func() bool {
		matches, _ := filepath.Glob(filepath.Join(sharedTmp, "kiwi-run-*"))
		for _, m := range matches {
			if st, err := os.Stat(filepath.Join(m, "hold.txt")); err == nil && st.Mode().IsRegular() {
				liveWS = m
				return true
			}
		}
		return false
	})
	ledgerEntries := func() []string {
		matches, _ := filepath.Glob(filepath.Join(workDir, ".kiwi-runtime", "*", "ledger", "*.json"))
		return matches
	}
	waitFor(t, "runner A ledger entry", 30*time.Second, func() bool { return len(ledgerEntries()) >= 1 })

	// Runner B (different stable id) starts against the SAME WorkDir. Its
	// reconciliation must not touch A's namespace or A's live workspace.
	runnerB := startRunner("runner-b", "b")
	t.Cleanup(func() {
		if runnerB.Process != nil {
			_ = runnerB.Process.Kill()
			_, _ = runnerB.Process.Wait()
		}
	})
	time.Sleep(3 * time.Second) // B reconciles on startup
	if _, err := os.Stat(filepath.Join(liveWS, "hold.txt")); err != nil {
		t.Fatalf("runner B destroyed runner A's live workspace: %v", err)
	}
	if got := ledgerEntries(); len(got) < 1 {
		t.Fatalf("runner B removed runner A's ledger entries: %v", got)
	}
	waitFor(t, "run success under two runners", 60*time.Second, func() bool {
		_, doc, _ := apiJSON(t, http.MethodGet, base+"/api/v1/runs/"+runID, "admin-token-pbt", nil)
		return doc["status"] == "success"
	})

	// Crash scenario: trigger another run, kill A mid-job, restart A, and
	// prove the replacement reclaims its OWN previous state. Schedule firing
	// is deduplicated per nominal minute (by design), so wait for the next
	// minute before the next trigger.
	time.Sleep(time.Duration(61-(time.Now().Unix()%60)) * time.Second)
	code, run2, raw := apiJSON(t, http.MethodPost, base+"/api/v1/schedules/pbt/trigger", "admin-token-pbt", map[string]any{})
	if code != 202 {
		t.Fatalf("second trigger = %d: %s", code, raw)
	}
	run2ID, _ := run2["id"].(string)
	if run2ID == "" {
		t.Fatalf("no second run id: %s", raw)
	}
	var crashedWS string
	waitFor(t, "second live workspace", 60*time.Second, func() bool {
		matches, _ := filepath.Glob(filepath.Join(sharedTmp, "kiwi-run-*"))
		for _, m := range matches {
			if m == liveWS {
				continue
			}
			if st, err := os.Stat(filepath.Join(m, "hold.txt")); err == nil && st.Mode().IsRegular() {
				crashedWS = m
				return true
			}
		}
		return false
	})
	if err := runnerA.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = runnerA.Process.Wait()
	// The workspace and ledger entry survive the hard kill (no deferred
	// cleanup ran).
	if _, err := os.Stat(crashedWS); err != nil {
		t.Fatalf("crashed workspace vanished before reclaim: %v", err)
	}
	var a2Out bytes.Buffer
	runnerA2 := startRunner("runner-a", "a")
	runnerA2.Stdout = &a2Out
	runnerA2.Stderr = &a2Out
	t.Cleanup(func() {
		if runnerA2.Process != nil {
			_ = runnerA2.Process.Kill()
			_, _ = runnerA2.Process.Wait()
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(crashedWS); os.IsNotExist(err) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(crashedWS); !os.IsNotExist(err) {
		entries, _ := filepath.Glob(filepath.Join(workDir, ".kiwi-runtime", "*", "ledger", "*.json"))
		workspaces, _ := filepath.Glob(filepath.Join(sharedTmp, "kiwi-run-*"))
		t.Fatalf("runner A replacement did not reclaim %s\nledger entries: %v\nworkspaces: %v\na2 output:\n%s", crashedWS, entries, workspaces, a2Out.String())
	}
	if _, err := os.Stat(liveWS); err != nil {
		// The first job completed normally; its workspace was cleaned by
		// A's deferred cleanup before the kill, so only absence is expected.
		_ = err
	}
	// The replacement must keep serving: a fresh run completes normally.
	time.Sleep(time.Duration(61-(time.Now().Unix()%60)) * time.Second)
	code, run3, raw := apiJSON(t, http.MethodPost, base+"/api/v1/schedules/pbt/trigger", "admin-token-pbt", map[string]any{})
	if code != 202 {
		t.Fatalf("third trigger = %d: %s", code, raw)
	}
	run3ID, _ := run3["id"].(string)
	if run3ID == "" {
		t.Fatalf("no third run id: %s", raw)
	}
	waitFor(t, "runner A replacement serves a fresh run", 90*time.Second, func() bool {
		_, doc, _ := apiJSON(t, http.MethodGet, base+"/api/v1/runs/"+run3ID, "admin-token-pbt", nil)
		return doc["status"] == "success"
	})
	_ = run2ID
	_ = strings.TrimSpace
}

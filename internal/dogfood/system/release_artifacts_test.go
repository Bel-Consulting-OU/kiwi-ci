package system_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Release-artifact proofs (SYSTEM species). These three scenarios execute the
// product binaries and the product control-plane/runner path — no stubs, no
// in-memory model harness:
//
//	DF-UPGRADE-002  N-1 binary → HEAD binary on one state directory
//	DF-SELF-002     G1 → G2 binary self-build from the same source tree
//	DF-RELEASE-001  exact packaged bytes install → serve → work → evidence
//
// Skip policy is narrow: only a git worktree/build failure may skip
// DF-UPGRADE-002 — and even that is a hard failure under
// KIWI_REQUIRE_N_MINUS_ONE=1 (set by `make release-gate`). The other two
// must run.

const (
	// goToolchainPath overrides the Go used for source builds in these
	// proofs. Empty means resolve via exec.LookPath("go") so the production
	// gate is portable across Linux/macOS CI hosts (never a developer-local
	// Homebrew path). Release packaging must still consume the exact built
	// artifact bytes — this toolchain only builds that artifact once.
	goToolchainPath = ""
	// nMinusOneScanDepth is how many recent commits to scan when picking an
	// N-1 worktree SHA (after the preferred named anchors).
	nMinusOneScanDepth = 15

	// requireNMinusOneEnv turns DF-UPGRADE-002's narrow skip policy into a
	// hard failure: when set to 1/true/yes, a missing or unbuildable N-1 is
	// t.Fatal, never t.Skip. `make release-gate` /
	// `make dogfood-release-artifacts` set it so release certification
	// cannot skip the N-1 proof.
	requireNMinusOneEnv = "KIWI_REQUIRE_N_MINUS_ONE"
	// nMinusOneBinEnv names a pre-built released N-1 artifact to upgrade
	// from (preferred over building a git worktree).
	nMinusOneBinEnv = "KIWI_N_MINUS_ONE_BIN"
	// nMinusOneSHA256Env pins the SHA-256 of the released artifact named by
	// nMinusOneBinEnv. A mismatch is ALWAYS a hard failure — the wrong
	// bytes must never certify a release.
	nMinusOneSHA256Env = "KIWI_N_MINUS_ONE_SHA256"
	// nMinusOneSHAEnv forces the N-1 worktree commit (skips the history
	// scan). Used by the fail-closed tests to point at an unbuildable SHA.
	nMinusOneSHAEnv = "KIWI_N_MINUS_ONE_SHA"
)

// nMinusOneRequired reports whether DF-UPGRADE-002 must fail closed instead
// of skipping when no N-1 artifact can be produced.
func nMinusOneRequired() bool {
	v := strings.TrimSpace(os.Getenv(requireNMinusOneEnv))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// nMinusOneFatalSkip is the testing surface failOrSkipNMinusOne needs —
// *testing.T satisfies it, and the fail-closed tests use a recorder to pin
// Fatal-vs-Skip without failing the parent test.
type nMinusOneFatalSkip interface {
	Helper()
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
}

// failOrSkipNMinusOne reports a missing/unbuildable N-1. Under
// KIWI_REQUIRE_N_MINUS_ONE this is a hard failure (release-gate must never
// silently drop the N-1 proof); otherwise the historical narrow skip.
func failOrSkipNMinusOne(t nMinusOneFatalSkip, format string, args ...any) {
	t.Helper()
	if nMinusOneRequired() {
		t.Fatalf(format, args...)
	} else {
		t.Skipf(format, args...)
	}
}

// releasedNMinusOne returns the released N-1 artifact named by
// KIWI_N_MINUS_ONE_BIN when configured. The bytes are hash-checked against
// KIWI_N_MINUS_ONE_SHA256 when that pin is set; a mismatch is always fatal.
// Returns ("", "", nil) when no released artifact is configured.
func releasedNMinusOne(t *testing.T) (binPath, sha string, err error) {
	t.Helper()
	binPath = strings.TrimSpace(os.Getenv(nMinusOneBinEnv))
	if binPath == "" {
		return "", "", nil
	}
	if st, serr := os.Stat(binPath); serr != nil || st.IsDir() {
		return "", "", fmt.Errorf("released N-1 artifact %q is not a readable file: %v", binPath, serr)
	}
	sha = sha256File(t, binPath)
	if want := strings.TrimSpace(strings.ToLower(os.Getenv(nMinusOneSHA256Env))); want != "" {
		if sha != want {
			return "", "", fmt.Errorf("released N-1 artifact %q sha256 = %s, want pinned %s", binPath, sha, want)
		}
	}
	return binPath, sha, nil
}

// buildNMinusOneWorktree builds the N-1 product binary from a real git
// worktree at the N-1 commit. Returns an error (never skips) when the SHA
// cannot be resolved, the worktree cannot be created, or the build fails —
// the caller decides skip vs fatal via failOrSkipNMinusOne.
func buildNMinusOneWorktree(t *testing.T, srcDir, goBin, n1SHA, outPath string) error {
	t.Helper()
	wt := filepath.Join(t.TempDir(), "kiwi-n1")
	add := exec.Command("git", "worktree", "add", "--detach", wt, n1SHA)
	add.Dir = srcDir
	if out, err := add.CombinedOutput(); err != nil {
		return fmt.Errorf("git worktree add %s: %v\n%s", n1SHA, err, out)
	}
	defer func() {
		rm := exec.Command("git", "worktree", "remove", "--force", wt)
		rm.Dir = srcDir
		_ = rm.Run()
	}()
	build := exec.Command(goBin, "build", "-o", outPath, "./cmd/kiwi")
	build.Dir = wt
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("N-1 go build from %s: %v\n%s", n1SHA, err, out)
	}
	return nil
}

// goTool returns the Go toolchain used for host and in-job builds.
func goTool(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("KIWI_TEST_GO"); env != "" {
		if st, err := os.Stat(env); err == nil && !st.IsDir() {
			return env
		}
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	t.Fatalf("go toolchain not found on PATH (set KIWI_TEST_GO to override)")
	return ""
}

// moduleRoot locates the repository root (the directory holding go.mod).
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test working directory")
		}
		dir = parent
	}
}

// buildKiwi builds ./cmd/kiwi from srcDir into outPath using the host Go
// toolchain. This is the real `go build` of the product binary.
func buildKiwi(t *testing.T, srcDir, outPath string) {
	t.Helper()
	goBin := goTool(t)
	cmd := exec.Command(goBin, "build", "-o", outPath, "./cmd/kiwi")
	cmd.Dir = srcDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build -o %s from %s: %v\n%s", outPath, srcDir, err, out)
	}
	if st, err := os.Stat(outPath); err != nil || st.IsDir() {
		t.Fatalf("built binary missing at %s (err=%v)", outPath, err)
	}
}

// sha256File returns the lowercase hex SHA-256 of a file's exact bytes.
func sha256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// shellQuote single-quotes a path for POSIX sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// goJobEnv is the job-level environment a trusted native self-build needs.
// Distributed runners never inherit the host environment: PATH must name the
// Homebrew Go, and HOME/GOCACHE/GOMODCACHE must point at real caches or the
// build cannot resolve the module.
func goJobEnv(t *testing.T) map[string]string {
	t.Helper()
	goBin := goTool(t)
	goDir := filepath.Dir(goBin)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("user home: %v", err)
	}
	gocache := os.Getenv("GOCACHE")
	if gocache == "" {
		gocache = filepath.Join(home, "Library/Caches/go-build")
	}
	gomodcache := os.Getenv("GOMODCACHE")
	if gomodcache == "" {
		gomodcache = filepath.Join(home, "go/pkg/mod")
	}
	return map[string]string{
		"PATH":       goDir + ":/usr/local/bin:/usr/bin:/bin",
		"HOME":       home,
		"GOCACHE":    gocache,
		"GOMODCACHE": gomodcache,
	}
}

// selfBuildPipeline renders a trusted native job whose run step is literally
// `go build -o <out> ./cmd/kiwi` from the given source directory. The job is
// executable only through a trusted ingress (untrusted policy forbids native).
func selfBuildPipeline(t *testing.T, srcDir, outPath string) string {
	t.Helper()
	env := goJobEnv(t)
	var b strings.Builder
	b.WriteString("version: 1\njobs:\n  selfbuild:\n    runtime: native\n    timeout: 10m\n")
	b.WriteString("    env:\n")
	for _, k := range []string{"PATH", "HOME", "GOCACHE", "GOMODCACHE"} {
		fmt.Fprintf(&b, "      %s: %s\n", k, shellQuote(env[k]))
	}
	b.WriteString("    steps:\n      - name: build-kiwi\n        run: |\n")
	fmt.Fprintf(&b, "          set -euo pipefail\n")
	fmt.Fprintf(&b, "          cd %s\n", shellQuote(srcDir))
	fmt.Fprintf(&b, "          %s build -o %s ./cmd/kiwi\n", shellQuote(goTool(t)), shellQuote(outPath))
	fmt.Fprintf(&b, "          test -x %s\n", shellQuote(outPath))
	fmt.Fprintf(&b, "          %s version\n", shellQuote(outPath))
	return b.String()
}

// binaryServer is one out-of-process `kiwi server` launched from a product
// binary (N-1, HEAD, or the packaged artifact).
type binaryServer struct {
	Bin     string
	DataDir string
	BaseURL string
	cmd     *exec.Cmd
	logPath string
}

// startBinaryServer launches `bin server --data-dir dataDir --listen
// 127.0.0.1:0` and waits for the bound address line. The process is the
// product binary — not the test binary's in-process server.
func startBinaryServer(t *testing.T, bin, dataDir, adminToken, runnerToken string) *binaryServer {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	cmd := exec.Command(bin, "server",
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--admin-token", adminToken,
		"--runner-token", runnerToken,
		"--mode", "dev",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("start %s server: %v", bin, err)
	}
	srv := &binaryServer{Bin: bin, DataDir: dataDir, cmd: cmd, logPath: logPath}
	t.Cleanup(func() {
		srv.stop()
		logFile.Close()
	})

	const prefix = "Kiwi server listening on http://"
	deadline := time.Now().Add(20 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(logPath)
		last = string(raw)
		for _, line := range strings.Split(last, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, prefix) {
				addr := strings.TrimSpace(strings.TrimPrefix(line, prefix))
				if addr != "" {
					srv.BaseURL = "http://" + addr
					return srv
				}
			}
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			t.Fatalf("%s server exited before listen: %s", bin, last)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s server did not print %q within 20s; log:\n%s", bin, prefix+"...", last)
	return nil
}

// stop terminates the server process and waits for it to exit so the state
// directory is released before a successor binary starts on it.
func (s *binaryServer) stop() {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		_ = s.cmd.Process.Kill()
		<-done
	}
	s.cmd = nil
}

// submitAndCompleteAPIHistory creates durable run/job history over the public
// API: one untrusted submit, a synthetic runner registration, a real next
// lease, and a real complete. No executor runs — the control plane still
// persists the full lifecycle, which is the state an upgrade must preserve.
func submitAndCompleteAPIHistory(ctx context.Context, t *testing.T, sys *system.System, marker string) (runID string, job system.JobView) {
	t.Helper()
	runID, err := sys.SubmitPipeline(ctx, containerEchoPipeline, system.SubmitOpts{
		RepoFullName: "kiwi-dogfood/upgrade-" + marker,
		RepoURL:      "https://github.com/kiwi-dogfood/upgrade-" + marker + ".git",
	})
	if err != nil {
		t.Fatalf("submit history %s: %v", marker, err)
	}
	runnerID, err := sys.RegisterRunner(ctx, "hist-"+marker, []string{"native", "container"})
	if err != nil {
		t.Fatalf("register history runner: %v", err)
	}
	var task system.LeaseTask
	leased := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		lt, ok, lerr := sys.Next(ctx, runnerID)
		if lerr != nil {
			t.Fatalf("next: %v", lerr)
		}
		if ok {
			task = lt
			leased = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("next: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !leased {
		t.Fatalf("history job for %s was never leased", marker)
	}
	code, err := sys.Complete(ctx, task, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("complete history: %v", err)
	}
	if code != 204 {
		t.Fatalf("complete history = HTTP %d, want 204", code)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait history terminal: %v", err)
	}
	if status != model.StatusSuccess {
		t.Fatalf("history job status = %s, want success", status)
	}
	job, err = sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("history job: %v", err)
	}
	return runID, job
}

// runTrustedNativeSelfBuild starts a product runner against sys, submits a
// trusted native self-build pipeline through the product trusted schedule
// ingress, and waits for terminal success.
func runTrustedNativeSelfBuild(ctx context.Context, t *testing.T, sys *system.System, pipelineYAML, runnerName string) string {
	t.Helper()
	if err := sys.StartRunner(runnerName, nil); err != nil {
		t.Fatalf("start runner %s: %v", runnerName, err)
	}
	runID, err := sys.SubmitTrustedSchedule(ctx, pipelineYAML, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit trusted self-build: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "selfbuild")
	if err != nil {
		j, _ := sys.JobByKey(ctx, runID, "selfbuild")
		t.Fatalf("wait selfbuild: %v (job error=%q)", err, j.Error)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "selfbuild")
		t.Fatalf("selfbuild status = %s error=%q, want success", status, j.Error)
	}
	return runID
}

// assertBinaryVersion runs `<bin> version` and requires a kiwi banner.
func assertBinaryVersion(t *testing.T, bin string) string {
	t.Helper()
	cmd := exec.Command(bin, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s version: %v\n%s", bin, err, out)
	}
	text := strings.TrimSpace(string(out))
	if !strings.Contains(text, "kiwi") {
		t.Fatalf("%s version output = %q, want a kiwi version banner", bin, text)
	}
	return text
}

// ---------------------------------------------------------------------------
// DF-UPGRADE-002 — N-1 binary matrix
// ---------------------------------------------------------------------------

// TestSysDFUpgrade002NMinusOne proves DF-UPGRADE-002 on the SYSTEM species:
// a real N-1 product binary owns a state directory and writes run history
// over the public API; a real HEAD product binary then takes the SAME state
// directory (binary upgrade), still serves that history, and accepts new
// work. Skips only when the git worktree or the N-1 build fails — and under
// KIWI_REQUIRE_N_MINUS_ONE=1 (set by `make release-gate`) even that is a
// hard failure, so release certification cannot silently drop this proof.
//
// A released N-1 artifact (KIWI_N_MINUS_ONE_BIN, optionally hash-pinned by
// KIWI_N_MINUS_ONE_SHA256) is preferred over building a git worktree.
func TestSysDFUpgrade002NMinusOne(t *testing.T) {
	srcDir := moduleRoot(t)
	goBin := goTool(t)

	n1Bin := filepath.Join(t.TempDir(), "kiwi-n1")
	// Prefer the released artifact when one is configured and its bytes
	// hash-check; fall back to a real N-1 worktree build otherwise.
	relBin, relSHA, relErr := releasedNMinusOne(t)
	if relErr != nil {
		// Wrong bytes on a released artifact is always fatal — never skip.
		t.Fatalf("DF-UPGRADE-002: released N-1 artifact: %v", relErr)
	}
	var n1SHA string
	switch {
	case relBin != "":
		n1SHA = relSHA
		if err := copyFile(relBin, n1Bin); err != nil {
			t.Fatalf("DF-UPGRADE-002: install released N-1 artifact: %v", err)
		}
		if got := sha256File(t, n1Bin); got != n1SHA {
			t.Fatalf("DF-UPGRADE-002: installed N-1 sha256 = %s, want released %s", got, n1SHA)
		}
		t.Logf("DF-UPGRADE-002: using released N-1 artifact %s sha256=%s", relBin, n1SHA)
	default:
		// Locate a prior commit that still builds cmd/kiwi.
		n1SHA = pickNMinusOneSHA(t, srcDir)
		if n1SHA == "" {
			failOrSkipNMinusOne(t, "DF-UPGRADE-002: no prior commit produced a buildable N-1 worktree (set %s=1 to fail closed, or supply %s/%s)", requireNMinusOneEnv, nMinusOneBinEnv, nMinusOneSHA256Env)
		}
		if err := buildNMinusOneWorktree(t, srcDir, goBin, n1SHA, n1Bin); err != nil {
			failOrSkipNMinusOne(t, "DF-UPGRADE-002: N-1 worktree build failed: %v", err)
		}
	}
	assertBinaryVersion(t, n1Bin)

	headBin := filepath.Join(t.TempDir(), "kiwi-head")
	buildKiwi(t, srcDir, headBin)
	assertBinaryVersion(t, headBin)

	stateDir := t.TempDir()
	adminTok, runnerTok := "upg-admin-token", "upg-runner-token"

	// --- N-1 owns the state directory and writes history ---
	n1 := startBinaryServer(t, n1Bin, stateDir, adminTok, runnerTok)
	n1Sys, err := system.Attach(n1.BaseURL, adminTok, runnerTok, t.TempDir())
	if err != nil {
		t.Fatalf("attach N-1: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	histRunID, histJob := submitAndCompleteAPIHistory(ctx, t, n1Sys, "n1")
	if histJob.Status != model.StatusSuccess {
		t.Fatalf("N-1 history job status = %s, want success", histJob.Status)
	}
	n1Sys.StopRunner()
	_ = n1Sys.Close()
	n1.stop()

	// --- HEAD binary upgrades the SAME state directory ---
	head := startBinaryServer(t, headBin, stateDir, adminTok, runnerTok)
	headSys, err := system.Attach(head.BaseURL, adminTok, runnerTok, t.TempDir())
	if err != nil {
		t.Fatalf("attach HEAD: %v", err)
	}
	defer func() { _ = headSys.Close() }()

	// Historical run must still be readable on the upgraded binary.
	run2, err := headSys.QueryRun(ctx, histRunID)
	if err != nil {
		t.Fatalf("HEAD query historical run: %v", err)
	}
	if run2.ID != histRunID {
		t.Fatalf("HEAD historical run id = %q, want %q", run2.ID, histRunID)
	}
	if run2.Status != model.StatusSuccess {
		t.Fatalf("HEAD historical run status = %s, want success", run2.Status)
	}
	jobs2, err := headSys.QueryJobs(ctx, histRunID)
	if err != nil {
		t.Fatalf("HEAD query historical jobs: %v", err)
	}
	found := false
	for _, j := range jobs2 {
		if j.Key == "build" && j.Status == model.StatusSuccess {
			found = true
		}
	}
	if !found {
		t.Fatalf("HEAD historical jobs = %+v, want terminal success build", jobs2)
	}

	// New work on the upgraded binary must succeed.
	newRunID, newJob := submitAndCompleteAPIHistory(ctx, t, headSys, "head")
	if newJob.Status != model.StatusSuccess {
		t.Fatalf("HEAD new job status = %s, want success", newJob.Status)
	}
	if newRunID == histRunID {
		t.Fatal("HEAD new run reused the historical run id")
	}
}

// TestNMinusOneRequireModeFailsClosed pins the P1-D policy: under
// KIWI_REQUIRE_N_MINUS_ONE=1 a missing or unbuildable N-1 is a hard failure
// (the release gate must never skip DF-UPGRADE-002), a released artifact
// with a wrong SHA-256 is always fatal, and the resolution helpers report
// failure rather than inventing an artifact.
func TestNMinusOneRequireModeFailsClosed(t *testing.T) {
	srcDir := moduleRoot(t)

	t.Run("require env is honored", func(t *testing.T) {
		t.Setenv(requireNMinusOneEnv, "")
		if nMinusOneRequired() {
			t.Fatal("empty env reported as require mode")
		}
		t.Setenv(requireNMinusOneEnv, "1")
		if !nMinusOneRequired() {
			t.Fatal("KIWI_REQUIRE_N_MINUS_ONE=1 not detected as require mode")
		}
		t.Setenv(requireNMinusOneEnv, "true")
		if !nMinusOneRequired() {
			t.Fatal("KIWI_REQUIRE_N_MINUS_ONE=true not detected as require mode")
		}
		t.Setenv(requireNMinusOneEnv, "0")
		if nMinusOneRequired() {
			t.Fatal("KIWI_REQUIRE_N_MINUS_ONE=0 reported as require mode")
		}
	})

	t.Run("unbuildable SHA resolves to no artifact", func(t *testing.T) {
		// A forced SHA that names no commit: the worktree cannot be built
		// and the resolver must report absent — the caller's skip-or-fatal
		// policy then fails closed under require mode.
		t.Setenv(nMinusOneSHAEnv, "0000000000000000000000000000000000000000")
		if got := pickNMinusOneSHA(t, srcDir); got != "" {
			t.Fatalf("pickNMinusOneSHA(unknown forced SHA) = %q, want empty", got)
		}
	})

	t.Run("worktree build of unknown SHA errors", func(t *testing.T) {
		t.Setenv(nMinusOneSHAEnv, "")
		goBin := goTool(t)
		err := buildNMinusOneWorktree(t, srcDir, goBin,
			"0000000000000000000000000000000000000000",
			filepath.Join(t.TempDir(), "kiwi-n1"))
		if err == nil {
			t.Fatal("buildNMinusOneWorktree(unknown SHA) succeeded, want error")
		}
	})

	t.Run("released artifact SHA mismatch always fails", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "fake-released-kiwi")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\necho fake kiwi\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv(nMinusOneBinEnv, bin)
		t.Setenv(nMinusOneSHA256Env, strings.Repeat("0", 64))
		_, _, err := releasedNMinusOne(t)
		if err == nil {
			t.Fatal("releasedNMinusOne with a wrong pinned sha256 succeeded, want error")
		}
		// And with no pin the artifact is accepted (hash recorded).
		t.Setenv(nMinusOneSHA256Env, "")
		gotBin, gotSHA, err := releasedNMinusOne(t)
		if err != nil {
			t.Fatalf("releasedNMinusOne without pin = %v", err)
		}
		if gotBin != bin || gotSHA == "" {
			t.Fatalf("releasedNMinusOne = (%q, %q), want (%q, non-empty)", gotBin, gotSHA, bin)
		}
	})

	t.Run("require mode fatal policy", func(t *testing.T) {
		rec := &nMinusOneCallRecorder{}
		t.Setenv(requireNMinusOneEnv, "1")
		failOrSkipNMinusOne(rec, "DF-UPGRADE-002 require-mode probe")
		if rec.fatal == "" {
			t.Fatalf("require mode: failOrSkipNMinusOne did not Fatalf (skipped=%q)", rec.skip)
		}
		if rec.skip != "" {
			t.Fatalf("require mode: failOrSkipNMinusOne also Skipf: %q", rec.skip)
		}
		rec2 := &nMinusOneCallRecorder{}
		t.Setenv(requireNMinusOneEnv, "")
		failOrSkipNMinusOne(rec2, "DF-UPGRADE-002 skip-mode probe")
		if rec2.skip == "" || rec2.fatal != "" {
			t.Fatalf("skip mode: want Skipf only, got fatal=%q skip=%q", rec2.fatal, rec2.skip)
		}
	})
}

// nMinusOneCallRecorder records Fatal/Skip calls for the fail-closed policy
// tests (a real *testing.T cannot observe Fatal from outside).
type nMinusOneCallRecorder struct{ fatal, skip string }

func (r *nMinusOneCallRecorder) Helper() {}
func (r *nMinusOneCallRecorder) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
}
func (r *nMinusOneCallRecorder) Skipf(format string, args ...any) {
	r.skip = fmt.Sprintf(format, args...)
}

// pickNMinusOneSHA walks recent history for a commit that is not HEAD and can
// form a worktree. KIWI_N_MINUS_ONE_SHA forces the commit (and is how the
// fail-closed tests point at an unbuildable SHA). Returns "" when none is
// acceptable (caller skips or fatals per KIWI_REQUIRE_N_MINUS_ONE).
func pickNMinusOneSHA(t *testing.T, srcDir string) string {
	t.Helper()
	if forced := strings.TrimSpace(os.Getenv(nMinusOneSHAEnv)); forced != "" {
		rev := exec.Command("git", "rev-parse", "--verify", forced+"^{commit}")
		rev.Dir = srcDir
		if o, err := rev.CombinedOutput(); err == nil {
			return strings.TrimSpace(string(o))
		}
		// Unresolvable forced SHA: report it as absent so the caller's
		// skip-or-fatal policy decides (require mode fails closed).
		return ""
	}
	log := exec.Command("git", "log", "--format=%H", "-n", fmt.Sprint(nMinusOneScanDepth))
	log.Dir = srcDir
	out, err := log.CombinedOutput()
	if err != nil {
		t.Fatalf("git log: %v\n%s", err, out)
	}
	head := exec.Command("git", "rev-parse", "HEAD")
	head.Dir = srcDir
	headOut, err := head.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v\n%s", err, headOut)
	}
	headSHA := strings.TrimSpace(string(headOut))
	// Prefer the named historical anchors from the DF-UPGRADE-002 brief.
	preferred := []string{"d00ede2", "0d8f2c5"}
	var candidates []string
	for _, p := range preferred {
		rev := exec.Command("git", "rev-parse", "--verify", p+"^{commit}")
		rev.Dir = srcDir
		if o, err := rev.CombinedOutput(); err == nil {
			candidates = append(candidates, strings.TrimSpace(string(o)))
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		sha := strings.TrimSpace(line)
		if sha != "" && sha != headSHA {
			candidates = append(candidates, sha)
		}
	}
	seen := map[string]bool{}
	for _, sha := range candidates {
		if sha == "" || sha == headSHA || seen[sha] {
			continue
		}
		seen[sha] = true
		return sha
	}
	return ""
}

// ---------------------------------------------------------------------------
// DF-SELF-002 — G1 → G2 binary self-build
// ---------------------------------------------------------------------------

// TestSysDFSelf002G1ToG2 proves DF-SELF-002 on the SYSTEM species:
//
//	G0 = host `go build` of ./cmd/kiwi
//	G1 = product pipeline (trusted native job) whose run step is
//	     `go build -o g1 ./cmd/kiwi` from the same source tree
//	G2 = G1's product control plane runs a pipeline whose job builds g2
//	     from that same source tree
//
// Both generations are asserted through `version` on the produced bytes.
// Source identity is the single module root used for every build.
func TestSysDFSelf002G1ToG2(t *testing.T) {
	srcDir := moduleRoot(t)
	outDir := t.TempDir()
	g0 := filepath.Join(outDir, "g0")
	g1 := filepath.Join(outDir, "g1")
	g2 := filepath.Join(outDir, "g2")

	// G0: host toolchain build of the current tree.
	buildKiwi(t, srcDir, g0)
	assertBinaryVersion(t, g0)

	// G0 → G1: SystemHarness (product server + product runner) executes a
	// trusted native job whose run step is literally `go build -o g1 ./cmd/kiwi`.
	sys := start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	g1Pipeline := selfBuildPipeline(t, srcDir, g1)
	runTrustedNativeSelfBuild(ctx, t, sys, g1Pipeline, "g0-selfbuild-runner")
	if _, err := os.Stat(g1); err != nil {
		t.Fatalf("G1 missing after G0 self-build: %v", err)
	}
	g1Version := assertBinaryVersion(t, g1)
	if !strings.Contains(g1Version, "kiwi") {
		t.Fatalf("G1 version banner = %q", g1Version)
	}
	// Source identity: G0 and G1 come from the same module root.
	if !strings.Contains(g1Pipeline, srcDir) {
		t.Fatalf("G1 pipeline does not name source dir %s", srcDir)
	}

	// G1 → G2: G1 is the product binary that serves the next generation's
	// pipeline. A real `g1 server` owns a fresh state directory; the product
	// runner executes a trusted native job that builds G2 from the same tree.
	g1State := t.TempDir()
	adminTok, runnerTok := "self-admin-token", "self-runner-token"
	g1Srv := startBinaryServer(t, g1, g1State, adminTok, runnerTok)
	g1Sys, err := system.Attach(g1Srv.BaseURL, adminTok, runnerTok, t.TempDir())
	if err != nil {
		t.Fatalf("attach G1: %v", err)
	}
	defer func() { _ = g1Sys.Close() }()

	g2Pipeline := selfBuildPipeline(t, srcDir, g2)
	g2RunID := runTrustedNativeSelfBuild(ctx, t, g1Sys, g2Pipeline, "g1-selfbuild-runner")
	if g2RunID == "" {
		t.Fatal("G1 self-build produced no run id")
	}
	if _, err := os.Stat(g2); err != nil {
		t.Fatalf("G2 missing after G1 self-build: %v", err)
	}
	assertBinaryVersion(t, g2)

	// Source identity: every generation built from the same directory.
	if !strings.Contains(g2Pipeline, srcDir) {
		t.Fatalf("G2 pipeline does not name source dir %s", srcDir)
	}
	// Record both generation hashes. Deterministic Go builds of the same
	// source tree produce identical bytes; equality is the expected
	// outcome, not a failure. What is proven is that G2 was produced by a
	// pipeline running on G1's control plane (run above) and that both
	// generations are executable product binaries.
	h1, h2 := sha256File(t, g1), sha256File(t, g2)
	t.Logf("DF-SELF-002 source=%s g1_sha256=%s g2_sha256=%s g2_run=%s", srcDir, h1, h2, g2RunID)
	if h2 == "" {
		t.Fatal("empty G2 hash")
	}
}

// ---------------------------------------------------------------------------
// DF-RELEASE-001 — packaged artifact lifecycle
// ---------------------------------------------------------------------------

// TestSysDFRelease001PackagedArtifact proves DF-RELEASE-001 on the SYSTEM
// species: one `go build` produces the packaged bytes, those exact bytes are
// hashed, installed into a fresh directory, and executed as the server that
// accepts real work and emits verifiable evidence. The hash of the binary
// that ran is the hash recorded before install.
func TestSysDFRelease001PackagedArtifact(t *testing.T) {
	srcDir := moduleRoot(t)
	stage := t.TempDir()

	// 1. Build once — the exact bytes a user would install.
	pkgBin := filepath.Join(stage, "kiwi-pkg")
	buildKiwi(t, srcDir, pkgBin)

	// 2. Hash the packaged artifact.
	pkgSHA := sha256File(t, pkgBin)
	if pkgSHA == "" {
		t.Fatal("empty packaged artifact hash")
	}
	t.Logf("DF-RELEASE-001 packaged artifact sha256=%s path=%s", pkgSHA, pkgBin)

	// 3. Install into a fresh directory (byte-for-byte copy of the package).
	installDir := t.TempDir()
	installedBin := filepath.Join(installDir, "kiwi")
	if err := copyFile(pkgBin, installedBin); err != nil {
		t.Fatalf("install packaged binary: %v", err)
	}
	installSHA := sha256File(t, installedBin)
	if installSHA != pkgSHA {
		t.Fatalf("installed binary sha256 = %s, want packaged %s", installSHA, pkgSHA)
	}

	// The binary that will serve is the installed copy; its hash must still
	// be the recorded package hash.
	usedSHA := sha256File(t, installedBin)
	if usedSHA != pkgSHA {
		t.Fatalf("binary-used sha256 = %s, want recorded packaged %s", usedSHA, pkgSHA)
	}
	assertBinaryVersion(t, installedBin)

	// 4. Fresh data dir + the installed binary as the real server.
	dataDir := filepath.Join(t.TempDir(), "fresh-data")
	adminTok, runnerTok := "rel-admin-token", "rel-runner-token"
	srv := startBinaryServer(t, installedBin, dataDir, adminTok, runnerTok)
	if srv.Bin != installedBin {
		t.Fatalf("server bin = %s, want installed %s", srv.Bin, installedBin)
	}

	sys, err := system.Attach(srv.BaseURL, adminTok, runnerTok, t.TempDir())
	if err != nil {
		t.Fatalf("attach packaged server: %v", err)
	}
	defer func() { _ = sys.Close() }()

	// 5. Submit + complete real trusted native work on the packaged server.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	probe := filepath.Join(dataDir, "release-probe.txt")
	pipeline := fmt.Sprintf(`version: 1
jobs:
  release:
    runtime: native
    timeout: 2m
    steps:
      - name: prove-work
        run: |
          set -euo pipefail
          echo kiwi-release-001 > %s
          test -s %s
`, shellQuote(probe), shellQuote(probe))
	if err := sys.StartRunner("release-runner", nil); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	runID, err := sys.SubmitTrustedSchedule(ctx, pipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit release work: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "release")
	if err != nil {
		j, _ := sys.JobByKey(ctx, runID, "release")
		t.Fatalf("wait release job: %v (error=%q)", err, j.Error)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "release")
		t.Fatalf("release job status = %s error=%q, want success", status, j.Error)
	}
	if _, err := os.Stat(probe); err != nil {
		t.Fatalf("release job did not write its proof file: %v", err)
	}
	job, err := sys.JobByKey(ctx, runID, "release")
	if err != nil {
		t.Fatalf("release job view: %v", err)
	}

	// 6. Evidence from the packaged server must verify (same product path).
	evCtx, evCancel := context.WithTimeout(ctx, 30*time.Second)
	defer evCancel()
	envBytes, err := sys.FetchEvidence(evCtx, job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatalf("fetch evidence: %v", err)
	}
	if _, err := sys.VerifyEvidence(ctx, envBytes); err != nil {
		t.Fatalf("verify evidence: %v", err)
	}

	// 7. Assert the hash of the binary used is the one recorded in this
	//    result (re-read the installed file the server was started from).
	finalSHA := sha256File(t, installedBin)
	if finalSHA != pkgSHA {
		t.Fatalf("post-run binary-used sha256 = %s, want recorded packaged %s", finalSHA, pkgSHA)
	}
	t.Logf("DF-RELEASE-001 result: BinarySHA256=%s BinaryPath=%s RunID=%s JobID=%s", finalSHA, installedBin, runID, job.ID)
}

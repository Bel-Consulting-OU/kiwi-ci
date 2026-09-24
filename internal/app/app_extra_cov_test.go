package app

import (
	"context"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestDispatchFlagAndTransportErrors(t *testing.T) {
	testutil.UnixChmod(t)
	dir := t.TempDir()
	pipe := writePipeline(t, dir, "version: 1\njobs: {}\n")
	// Flag parse error.
	if err := Dispatch(context.Background(), []string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	// Unknown forge kind.
	if err := Dispatch(context.Background(), []string{"--repo", "acme/app", "--forge", "bogus"}); err == nil {
		t.Fatal("unknown forge accepted")
	}
	// Malformed clone URL.
	if err := Dispatch(context.Background(), []string{"--repo", "http://[::1", "--forge", "github"}); err == nil {
		t.Fatal("malformed repo URL accepted")
	}
	// Forge fetch failure (unreachable API base).
	t.Setenv("KIWI_GITHUB_API_BASE", "http://127.0.0.1:1")
	if err := Dispatch(context.Background(), []string{"--repo", "acme/app"}); err == nil {
		t.Fatal("unreachable forge accepted")
	}
	// Malformed control-plane URL.
	if err := Dispatch(context.Background(), []string{"--repo", "acme/app", "--pipeline", pipe, "--server", "http://[::1"}); err == nil {
		t.Fatal("malformed control-plane URL accepted")
	}
	// Unreachable control plane.
	if err := Dispatch(context.Background(), []string{"--repo", "acme/app", "--pipeline", pipe, "--server", "http://127.0.0.1:1"}); err == nil {
		t.Fatal("unreachable control plane accepted")
	}
	// A 200 response with a malformed run body.
	badBody := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	})
	if err := Dispatch(context.Background(), []string{"--repo", "acme/app", "--pipeline", pipe, "--server", badBody.URL}); err == nil {
		t.Fatal("malformed dispatch response accepted")
	}
	// An error response body is surfaced.
	failing := jsonServer(t, http.StatusConflict, "conflict")
	err := Dispatch(context.Background(), []string{"--repo", "acme/app", "--pipeline", pipe, "--server", failing.URL})
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("dispatch conflict = %v", err)
	}
	// Inputs are validated at flag-parse time.
	if err := Dispatch(context.Background(), []string{"--repo", "acme/app", "--pipeline", pipe, "--input", "broken"}); err == nil {
		t.Fatal("malformed --input accepted")
	}
}

func TestForgeAdapterForMatrix(t *testing.T) {
	if _, err := forgeAdapterFor("http://[::1", "acme/app", ""); err == nil {
		t.Fatal("malformed repository URL accepted")
	}
	// Host-based detection: gitlab, forgejo and codeberg.
	gl, err := forgeAdapterFor("https://gitlab.example.com/acme/app.git", "acme/app", "")
	if err != nil {
		t.Fatal(err)
	}
	if gl == nil {
		t.Fatal("gitlab adapter is nil")
	}
	if _, err := forgeAdapterFor("https://git.example.com/acme/app.git", "acme/app", "gitlab"); err != nil {
		t.Fatalf("explicit gitlab adapter: %v", err)
	}
	if _, err := forgeAdapterFor("https://codeberg.org/acme/app.git", "acme/app", ""); err != nil {
		t.Fatalf("codeberg detection: %v", err)
	}
	if _, err := forgeAdapterFor("https://forgejo.example.com/acme/app", "acme/app", ""); err != nil {
		t.Fatalf("forgejo detection: %v", err)
	}
	if _, err := forgeAdapterFor("https://github.com/acme/app", "acme/app", ""); err != nil {
		t.Fatalf("github adapter: %v", err)
	}
	// Self-hosted GitHub host takes the base URL from the clone URL, and
	// the explicit env override wins.
	if _, err := forgeAdapterFor("https://github.example.com/acme/app", "acme/app", "github"); err != nil {
		t.Fatalf("self-hosted github adapter: %v", err)
	}
	t.Setenv("KIWI_GITHUB_API_BASE", "https://api.example.com")
	if _, err := forgeAdapterFor("https://github.example.com/acme/app", "acme/app", "github"); err != nil {
		t.Fatalf("github base override: %v", err)
	}
	t.Setenv("KIWI_GITLAB_BASE", "https://gitlab.example.com/api/v4")
	if _, err := forgeAdapterFor("https://gitlab.example.com/acme/app", "acme/app", "gitlab"); err != nil {
		t.Fatalf("gitlab base override: %v", err)
	}
	t.Setenv("KIWI_FORGEJO_BASE", "https://forgejo.example.com/api/v1")
	if _, err := forgeAdapterFor("https://forgejo.example.com/acme/app", "acme/app", "forgejo"); err != nil {
		t.Fatalf("forgejo base override: %v", err)
	}
	if _, err := forgeAdapterFor("https://example.com/acme/app", "acme/app", "svn"); err == nil {
		t.Fatal("unsupported forge kind accepted")
	}
}

func TestImportWarningsAndWriteErrors(t *testing.T) {
	// A workflow with unsupported constructs yields warnings/unsupported
	// entries on both the write and --list-unsupported paths.
	body := "name: ci\non:\n  push:\n  schedule:\n    - cron: '0 3 * * 1'\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	src := filepath.Join(t.TempDir(), "ci.yml")
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.yaml")
	if err := Import([]string{"github-actions", "--file", src, "--out", out}); err != nil {
		t.Fatalf("import with unsupported constructs: %v", err)
	}
	if err := Import([]string{"github-actions", "--file", src, "--list-unsupported"}); err != nil {
		t.Fatalf("import --list-unsupported: %v", err)
	}
	// Unknown importer with a valid source reaches the switch default.
	if err := Import([]string{"bogus", "--file", src}); err == nil {
		t.Fatal("unknown importer with a source accepted")
	}
	// Unknown importer without a source fails at detection.
	if err := Import([]string{"bogus"}); err == nil {
		t.Fatal("unknown importer without a source accepted")
	}
	// The output parent is a regular file: MkdirAll fails.
	blocked := t.TempDir()
	if err := os.WriteFile(filepath.Join(blocked, "out"), []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Import([]string{"github-actions", "--file", src, "--out", filepath.Join(blocked, "out", "pipeline.yaml")}); err == nil {
		t.Fatal("output under a file accepted")
	}
	// The output directory is read-only: os.WriteFile fails.
	readonly := t.TempDir()
	if err := os.Chmod(readonly, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only directory is writable")
	}
	if err := Import([]string{"github-actions", "--file", src, "--out", filepath.Join(readonly, "pipeline.yaml")}); err == nil {
		t.Fatal("write into a read-only directory accepted")
	}
}

func TestInitWriteFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module x\n")
	readonly := filepath.Join(dir, "ro")
	if err := os.Mkdir(readonly, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only directory is writable")
	}
	if err := Init([]string{"--dir", dir, "-f", "ro/pipeline.yaml"}); err == nil {
		t.Fatal("write into a read-only directory accepted")
	}
}

// badCompilePipeline parses but fails compilation (an interpolated matrix
// value smuggles a traversal working directory).
const badCompilePipeline = `version: 1
jobs:
  x:
    matrix:
      DIR: ["../../evil"]
    steps:
      - working_directory: ${{ matrix.DIR }}
        run: echo hi
`

func TestValidateAndExplainCompileErrors(t *testing.T) {
	dir := t.TempDir()
	badCompile := writePipeline(t, dir, badCompilePipeline)
	if err := Validate([]string{"-f", badCompile}); err == nil {
		t.Fatal("uncompilable pipeline accepted by Validate")
	}
	if err := Explain([]string{"-f", badCompile}); err == nil {
		t.Fatal("uncompilable pipeline accepted by Explain")
	}
	if err := RunLocal(context.Background(), []string{"-f", badCompile}); err == nil {
		t.Fatal("uncompilable pipeline accepted by RunLocal")
	}
	// A malformed document fails at Load.
	malformed := filepath.Join(dir, "malformed.yaml")
	if err := os.WriteFile(malformed, []byte("\t::: not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RunLocal(context.Background(), []string{"-f", malformed}); err == nil {
		t.Fatal("malformed pipeline accepted by RunLocal")
	}
	if err := Validate([]string{"-f", malformed}); err == nil {
		t.Fatal("malformed pipeline accepted by Validate")
	}
	if err := Explain([]string{"-f", malformed}); err == nil {
		t.Fatal("malformed pipeline accepted by Explain")
	}
}

func TestDetectChangedFilesOptsMergeBaseFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "1")
	initGitRepo(t, dir)
	if got := detectChangedFilesOpts(dir, "", "HEAD", "no-such-ref", ""); got != nil {
		t.Fatalf("bad merge base = %v", got)
	}
}

func TestServerForgejoGitLabBaseURLAndAppKey(t *testing.T) {
	// applyForgeConfig failures surface through Server when the GitHub App
	// key cannot be read.
	addr := freeTCPAddr(t)
	err := Server(context.Background(), []string{"--listen", addr, "--github-app-id", "7",
		"--github-app-private-key", filepath.Join(t.TempDir(), "missing.pem")})
	if err == nil || !strings.Contains(err.Error(), "github app private key") {
		t.Fatalf("missing GitHub App key = %v", err)
	}
}

func TestServerApplyEnvFailure(t *testing.T) {
	t.Setenv("KIWI_GITHUB_APP_ID", "not-a-number")
	err := Server(context.Background(), []string{"--listen", freeTCPAddr(t)})
	if err == nil || !strings.Contains(err.Error(), "KIWI_GITHUB_APP_ID") {
		t.Fatalf("invalid environment overlay = %v", err)
	}
}

func TestServerPersistentConstructorErrors(t *testing.T) {
	// A data-dir that is a regular file cannot host the persistent store.
	fileAsDir := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Server(context.Background(), []string{"--listen", freeTCPAddr(t), "--data-dir", fileAsDir}); err == nil {
		t.Fatal("data-dir as a file accepted")
	}
	// A cluster key dir that is a regular file cannot host the key store.
	clusterAsFile := filepath.Join(t.TempDir(), "cluster")
	if err := os.WriteFile(clusterAsFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Server(context.Background(), []string{"--listen", freeTCPAddr(t), "--data-dir", t.TempDir(), "--cluster-key-dir", clusterAsFile}); err == nil {
		t.Fatal("cluster-key-dir as a file accepted")
	}
}

func TestServerRunnerEnrollmentKeyStoreFailure(t *testing.T) {
	// Enrollment persists the CA through the cluster key store; a data-dir
	// that cannot be written fails the startup instead of serving.
	readonly := t.TempDir()
	if err := os.Chmod(readonly, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only directory is writable")
	}
	if err := Server(context.Background(), []string{"--listen", freeTCPAddr(t), "--data-dir", readonly, "--runner-enroll-token", "tok"}); err == nil {
		t.Fatal("read-only data-dir accepted for enrollment")
	}
}

// TestRunnerAdminDoWithoutOutputIsUnreachable was removed: it only called the
// no-op production `discard` helper and referenced runnerpki.RunnerURIPrefix,
// asserting nothing. The RunnerAdmin argument contract is covered by
// TestRunnerAdminListShortIDs and the other RunnerAdmin tests in this file.

func TestRunnerAdminListShortIDs(t *testing.T) {
	ts, _ := runnerAdminFake(t, http.StatusOK, `[{"id":"short","name":"n"}]`)
	if err := RunnerAdmin(context.Background(), "list", []string{"--server", ts.URL}); err != nil {
		t.Fatalf("short runner ID list: %v", err)
	}
}

func TestReplayMkdirTempFailure(t *testing.T) {
	archive := snapshotArchive(t)
	srv := replayServer(t, `[{"id":"snap1","job_key":"build","created_at":"2026-09-14T00:00:00Z"}]`, http.StatusOK, http.StatusOK, archive)
	pipe := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    steps:\n      - run: echo ok\n")
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing-root"))
	err := Replay(context.Background(), []string{"--server", srv.URL, "--pipeline", pipe, "run1", "build"})
	if err == nil {
		t.Fatal("unwritable TMPDIR accepted")
	}
}

func TestReplayClientDoErrorAfterListing(t *testing.T) {
	// The listener accepts exactly one connection: the snapshot listing
	// succeeds, the download connection is refused.
	archive := snapshotArchive(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/runs/run1/snapshots" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Connection", "close")
			_, _ = w.Write([]byte(`[{"id":"snap1","job_key":"build","created_at":"2026-09-14T00:00:00Z"}]`))
			return
		}
		_, _ = w.Write(archive)
	})
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(&oneConnListener{Listener: ln}) }()
	t.Cleanup(func() { _ = srv.Close() })
	pipe := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    steps:\n      - run: echo ok\n")
	err = Replay(context.Background(), []string{"--server", "http://" + ln.Addr().String(), "--pipeline", pipe, "run1", "build"})
	if err == nil {
		t.Fatal("refused snapshot download accepted")
	}
}

// oneConnListener accepts a single connection then reports a permanent
// error, so only the first HTTP request of a test succeeds.
type oneConnListener struct {
	net.Listener
	accepted bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.accepted {
		return nil, fmt.Errorf("listener closed")
	}
	l.accepted = true
	return l.Listener.Accept()
}

func TestReplayRedirectNotFollowed(t *testing.T) {
	// The snapshot list endpoint redirects: the client refuses to follow
	// and the non-200 status surfaces as an error.
	redirect := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/snapshots", http.StatusFound)
	})
	pipe := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    steps:\n      - run: echo ok\n")
	if err := Replay(context.Background(), []string{"--server", redirect.URL, "--pipeline", pipe, "run1", "build"}); err == nil {
		t.Fatal("redirected snapshot list accepted")
	}
}

var _ = httptest.NewServer
var _ = pgx.Connect

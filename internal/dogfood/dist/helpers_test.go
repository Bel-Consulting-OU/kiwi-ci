package dist_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// ---------------------------------------------------------------------------
// module / binary helpers
// ---------------------------------------------------------------------------

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

// buildKiwi compiles cmd/kiwi into dir and returns the binary path.
func buildKiwi(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "kiwi")
	goBin := os.Getenv("KIWI_TEST_GO")
	if goBin == "" {
		var err error
		goBin, err = exec.LookPath("go")
		if err != nil {
			t.Fatalf("go toolchain not found on PATH (set KIWI_TEST_GO to override): %v", err)
		}
	}
	cmd := exec.Command(goBin, "build", "-o", bin, "./cmd/kiwi")
	cmd.Dir = moduleRoot(t)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build kiwi: %v\n%s", err, out)
	}
	return bin
}

// ---------------------------------------------------------------------------
// network helpers
// ---------------------------------------------------------------------------

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// ---------------------------------------------------------------------------
// PostgreSQL lifecycle
// ---------------------------------------------------------------------------

// startPostgres returns a DSN for a real PostgreSQL database the test owns.
//
// When KIWI_TEST_POSTGRES_URL is set it is used as the admin DSN and a
// throwaway database is created on that server. Otherwise a private
// PostgreSQL instance is started via /opt/homebrew/bin/initdb + postgres
// inside t.TempDir(). The returned stop function tears the instance down
// (no-op when an external server was used).
func startPostgres(t *testing.T) (dsn, stop string) {
	t.Helper()
	if admin := strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL")); admin != "" {
		return pgCreateDatabase(t, admin), ""
	}
	return pgStartLocal(t)
}

// pgStartLocal boots a private PostgreSQL under t.TempDir() and returns a
// DSN that points at a fresh database on it.
func pgStartLocal(t *testing.T) (dsn string, stop string) {
	t.Helper()
	initdb := resolvePG(t, "initdb")
	pgBin := resolvePG(t, "postgres")
	psql := resolvePG(t, "psql")

	root := t.TempDir()
	pgData := filepath.Join(root, "pgdata")
	// Unix-domain socket paths are capped at ~104 bytes on macOS; a
	// t.TempDir() under the long test name exceeds that. Use a short
	// system temp directory for the socket only.
	sockDir, err := os.MkdirTemp("", "pgsock")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

	init := exec.Command(initdb, "-D", pgData, "-U", "postgres", "--auth=trust", "--no-sync", "-E", "UTF8")
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("initdb: %v\n%s", err, out)
	}

	port := freeTCPPort(t)
	pgCmd := exec.Command(pgBin, "-D", pgData,
		"-p", fmt.Sprint(port),
		"-k", sockDir,
		"-c", "listen_addresses=127.0.0.1",
		"-c", "fsync=off",
		"-c", "synchronous_commit=off",
	)
	pgLog, err := os.Create(filepath.Join(root, "postgres.log"))
	if err != nil {
		t.Fatal(err)
	}
	pgCmd.Stdout = pgLog
	pgCmd.Stderr = pgLog
	if err := pgCmd.Start(); err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() {
		if pgCmd.Process != nil {
			_ = pgCmd.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { _, _ = pgCmd.Process.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = pgCmd.Process.Kill()
				_, _ = pgCmd.Process.Wait()
			}
		}
		_ = pgLog.Close()
	})

	// Wait for the server to accept connections.
	admin := fmt.Sprintf("host=127.0.0.1 port=%d user=postgres dbname=postgres sslmode=disable", port)
	live := false
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, psql, admin, "-c", "SELECT 1")
		err := cmd.Run()
		cancel()
		if err == nil {
			live = true
			break
		}
		// If the server already exited, stop early and dump its log.
		if pgCmd.ProcessState != nil && pgCmd.ProcessState.Exited() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !live {
		logBytes, _ := os.ReadFile(pgLog.Name())
		t.Fatalf("timeout waiting for postgres liveness (port %d)\n--- postgres.log ---\n%s", port, logBytes)
	}

	// Create a throwaway database for this test.
	dbName := fmt.Sprintf("kiwi_dist_%d", time.Now().UnixNano()%1_000_000_000)
	mk := exec.Command(psql, admin, "-c", "CREATE DATABASE "+dbName)
	if out, err := mk.CombinedOutput(); err != nil {
		t.Fatalf("create database: %v\n%s", err, out)
	}
	return fmt.Sprintf("postgres://postgres@127.0.0.1:%d/%s?sslmode=disable", port, dbName), "local"
}

// pgCreateDatabase creates a throwaway database on the server named by
// adminDSN and returns a DSN pointing at it. adminDSN must already be a
// postgres:// URL (the form the server config accepts).
func pgCreateDatabase(t *testing.T, adminDSN string) string {
	t.Helper()
	psql := resolvePG(t, "psql")
	dbName := fmt.Sprintf("kiwi_dist_%d", time.Now().UnixNano()%1_000_000_000)
	mk := exec.Command(psql, adminDSN, "-c", "CREATE DATABASE "+dbName)
	if out, err := mk.CombinedOutput(); err != nil {
		t.Fatalf("create database on external server: %v\n%s", out, err)
	}
	t.Cleanup(func() {
		_ = exec.Command(psql, adminDSN, "-c", "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)").Run()
	})
	return replaceURLDatabase(adminDSN, dbName)
}

// ensureRepoIdentityFunctions runs the repo-identity SQL function prelude
// against dsn (functions only — safe on an empty database). Call it BEFORE
// pg_restore so callees exist the moment the dump starts creating objects.
func ensureRepoIdentityFunctions(t *testing.T, dsn string) {
	t.Helper()
	runRepoIdentitySQL(t, dsn, storage.EnsureRepoIdentityFunctionsSQL())
}

// rebuildRepoIdentitySchema converges functions AND the expression indexes
// that inline them. Call it AFTER pg_restore: a dump may recreate normalize_*
// before kiwi_canonical_repo_id (no pg_depend edge) and skip the keyset
// indexes; this makes the restored database complete.
func rebuildRepoIdentitySchema(t *testing.T, dsn string) {
	t.Helper()
	runRepoIdentitySQL(t, dsn, storage.EnsureRepoIdentitySchemaSQL())
}

// restorePGDump restores a pg_dump custom-format archive into dsn, then
// converges the repo-identity function/index family. The two keyset indexes
// are EXCLUDED from the dump restore: they inline the normalize functions,
// pg_dump records no edge that orders those functions first, and a vanilla
// pg_restore therefore fails (or skips) the indexes. rebuildRepoIdentitySchema
// creates them after the functions exist — so restore is complete and quiet.
func restorePGDump(t *testing.T, dsn, dumpPath string) {
	t.Helper()
	pgRestore := resolvePG(t, "pg_restore")
	listOut, err := exec.Command(pgRestore, "-l", dumpPath).CombinedOutput()
	if err != nil {
		t.Fatalf("pg_restore -l: %v\n%s", err, listOut)
	}
	filter, err := os.CreateTemp(t.TempDir(), "pg-restore-filter-*.list")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(listOut), "\n") {
		// Skip objects the prelude/rebuild owns: the dump's CREATE FUNCTION
		// order is unreliable and its CREATE INDEX inlines callees that may
		// not exist yet. Match on object names (pg_restore -l prints
		// schema-qualified forms).
		skip := false
		for _, name := range []string{
			"runs_repo_identity_normalized_keyset_idx",
			"runs_repo_full_name_normalized_keyset_idx",
			"kiwi_canonical_host",
			"kiwi_canonical_repo_id",
			"kiwi_normalize_run_repo_identity",
			"kiwi_normalize_run_repo_full_name",
		} {
			if strings.Contains(line, name) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if _, err := filter.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	ensureRepoIdentityFunctions(t, dsn)
	if out, err := exec.Command(pgRestore, "-L", filter.Name(), "-d", dsn, dumpPath).CombinedOutput(); err != nil {
		// Fail closed: after the controlled exclude list, a non-zero
		// pg_restore means the dump itself is damaged (not a known
		// function-order quirk). Logging it away would hide restore damage.
		t.Fatalf("pg_restore: %v\n%s", err, out)
	}
	rebuildRepoIdentitySchema(t, dsn)
}

func runRepoIdentitySQL(t *testing.T, dsn, sql string) {
	t.Helper()
	psql := resolvePG(t, "psql")
	f, err := os.CreateTemp(t.TempDir(), "repo-identity-*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(sql); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(psql, dsn, "-v", "ON_ERROR_STOP=1", "-f", f.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("repo-identity SQL: %v\n%s", err, out)
	}
}

// replaceURLDatabase swaps the database component of a postgres:// URL.
func replaceURLDatabase(dsn, dbName string) string {
	// postgres://user:pass@host:port/olddb?params
	scheme := "postgres://"
	rest := dsn
	if strings.HasPrefix(dsn, "postgresql://") {
		scheme = "postgresql://"
		rest = strings.TrimPrefix(dsn, "postgresql://")
	} else {
		rest = strings.TrimPrefix(dsn, "postgres://")
	}
	// Split off query params.
	base, query := rest, ""
	if i := strings.Index(rest, "?"); i >= 0 {
		base, query = rest[:i], rest[i:]
	}
	// Replace the path component (everything after the last /).
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[:i+1]
	}
	return scheme + base + dbName + query
}

// resolvePG finds a PostgreSQL tool binary, preferring Homebrew.
func resolvePG(t *testing.T, name string) string {
	t.Helper()
	candidates := []string{
		"/opt/homebrew/bin/" + name,
		"/opt/homebrew/opt/postgresql@17/bin/" + name,
		"/opt/homebrew/opt/postgresql@14/bin/" + name,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	t.Fatalf("PostgreSQL tool %q not found (tried Homebrew and PATH)", name)
	return ""
}

// ---------------------------------------------------------------------------
// local git dumb-HTTP mirror
// ---------------------------------------------------------------------------

// startGitMirror creates a bare git repository with one commit and serves
// it over dumb HTTP. The returned URL is the clone URL runners use.
func startGitMirror(t *testing.T, root string) string {
	t.Helper()
	repoSrc := filepath.Join(root, "repo-src")
	mirrorRoot := filepath.Join(root, "git-http")

	runGit := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=kiwi-dist", "GIT_AUTHOR_EMAIL=dist@kiwi.local",
			"GIT_COMMITTER_NAME=kiwi-dist", "GIT_COMMITTER_EMAIL=dist@kiwi.local",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	if err := os.MkdirAll(repoSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(repoSrc, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repoSrc, "README.md"), []byte("# kiwi dist dogfood\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(repoSrc, "add", "-A")
	runGit(repoSrc, "commit", "-qm", "init")

	if err := os.MkdirAll(filepath.Join(mirrorRoot, "owner"), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(root, "clone", "--bare", repoSrc, filepath.Join(mirrorRoot, "owner", "repo.git"))
	runGit(filepath.Join(mirrorRoot, "owner", "repo.git"), "update-server-info")

	gitSrv := httptest.NewServer(http.FileServer(http.Dir(mirrorRoot)))
	t.Cleanup(gitSrv.Close)
	return gitSrv.URL + "/owner/repo.git"
}

// ---------------------------------------------------------------------------
// process spawn helpers
// ---------------------------------------------------------------------------

// proc wraps a spawned OS process with clean shutdown.
type proc struct {
	cmd *exec.Cmd
}

func (p *proc) kill() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

// spawnServer starts `kiwi server` as a real OS process.
func spawnServer(t *testing.T, bin, listen, dataDir, databaseURL, runnerToken, adminToken string) *proc {
	t.Helper()
	cmd := exec.Command(bin, "server",
		"--listen", listen,
		"--data-dir", dataDir,
		"--database-url", databaseURL,
		"--runner-token", runnerToken,
		"--admin-token", adminToken,
	)
	cmd.Env = append(os.Environ(), "KIWI_RUNNER_TOKEN="+runnerToken)
	logFile := filepath.Join(dataDir, "..", "server.log")
	_ = os.MkdirAll(filepath.Dir(logFile), 0o700)
	lf, err := os.Create(logFile)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start kiwi server: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { _, _ = cmd.Process.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			}
		}
		_ = lf.Close()
	})
	return &proc{cmd: cmd}
}

// spawnRunner starts `kiwi runner` as a real OS process.
func spawnRunner(t *testing.T, bin, serverURL, token, name, workDir, identityDir string) *proc {
	t.Helper()
	cmd := exec.Command(bin, "runner",
		"--server", serverURL,
		"--token", token,
		"--name", name,
		"--labels", "native",
		"--work-dir", workDir,
		"--identity-dir", identityDir,
		"--capture-snapshots=false",
	)
	cmd.Env = append(os.Environ(),
		"KIWI_ALLOW_INSECURE_CLONE=1",
		"KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK=1",
	)
	logFile := filepath.Join(filepath.Dir(workDir), name+".log")
	lf, err := os.Create(logFile)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start kiwi runner %s: %v", name, err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { _, _ = cmd.Process.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			}
		}
		_ = lf.Close()
	})
	return &proc{cmd: cmd}
}

// killNow hard-kills a process immediately (used for the "other runner can
// claim after" sequential arm).
func (p *proc) killNow() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

// ---------------------------------------------------------------------------
// API client helpers (the external client)
// ---------------------------------------------------------------------------

// apiGet performs an authenticated GET and decodes the JSON response.
func apiGet(t *testing.T, baseURL, token, path string, out any) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			t.Fatalf("GET %s decode: %v (body %s)", path, err, payload)
		}
	}
	return resp.StatusCode
}

// apiGetBytes performs an authenticated GET and returns the raw body bytes
// and status code (no JSON decoding) — used for artifact downloads whose
// bytes must be hash-compared across backup/restore.
func apiGetBytes(t *testing.T, baseURL, token, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, payload
}

// apiPost performs an authenticated POST and decodes the JSON response.
func apiPost(t *testing.T, baseURL, token, path string, body any, out any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if out != nil && len(payload) > 0 && resp.StatusCode < 400 {
		if err := json.Unmarshal(payload, out); err != nil {
			t.Fatalf("POST %s decode: %v (body %s)", path, err, payload)
		}
	}
	return resp.StatusCode, payload
}

// apiPut performs an authenticated PUT and decodes the JSON response.
func apiPut(t *testing.T, baseURL, token, path string, body any, out any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, baseURL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", path, err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if out != nil && len(payload) > 0 && resp.StatusCode < 400 {
		if err := json.Unmarshal(payload, out); err != nil {
			t.Fatalf("PUT %s decode: %v (body %s)", path, err, payload)
		}
	}
	return resp.StatusCode, payload
}

// waitFor blocks until cond returns true or the timeout elapses.
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

// ---------------------------------------------------------------------------
// evidence fetch + verify (JWKS-resolved, same path as `kiwi verify`)
// ---------------------------------------------------------------------------

// fetchEvidence downloads the signed execution attestation envelope for one
// job attempt, polling until the outbox dispatches it.
func fetchEvidence(t *testing.T, baseURL, adminToken, jobID string, generation int64) []byte {
	t.Helper()
	path := fmt.Sprintf("/api/v1/jobs/%s/attestation?generation=%d", jobID, generation)
	deadline := time.Now().Add(25 * time.Second)
	var lastStatus string
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && len(payload) > 0 {
				return payload
			}
			lastStatus = fmt.Sprintf("%s %s", resp.Status, strings.TrimSpace(string(payload)))
		} else {
			lastStatus = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("attestation for job %s gen %d never arrived (last: %s)", jobID, generation, lastStatus)
	return nil
}

// verifyEvidence verifies a fetched envelope through provenance.VerifyWith
// (JWKS-resolved trusted key) and the execution-attestation consistency
// rules. Tampered envelopes must fail.
func verifyEvidence(t *testing.T, baseURL string, envBytes []byte) provenance.Statement {
	t.Helper()
	resolver := jwksResolver(t, baseURL)
	st, err := provenance.VerifyWith(envBytes, resolver, provenance.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyWith: %v", err)
	}
	if err := provenance.VerifyExecutionAttestation(st); err != nil {
		t.Fatalf("VerifyExecutionAttestation: %v", err)
	}
	return st
}

// jwksResolver builds a kid → public key resolver from the server's public
// JWKS endpoint (the same discovery path `kiwi verify` uses).
func jwksResolver(t *testing.T, baseURL string) func(kid string) (ed25519.PublicKey, bool) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/oidc/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("jwks fetch: %v", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks: %s: %s", resp.Status, payload)
	}
	var body struct {
		Keys []struct {
			KID string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("jwks decode: %v", err)
	}
	byKid := make(map[string]ed25519.PublicKey, len(body.Keys))
	for _, k := range body.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		byKid[k.KID] = ed25519.PublicKey(raw)
	}
	if len(byKid) == 0 {
		t.Fatal("jwks: no usable Ed25519 keys")
	}
	return func(kid string) (ed25519.PublicKey, bool) {
		pub, ok := byKid[kid]
		return pub, ok
	}
}

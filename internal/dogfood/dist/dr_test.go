package dist_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSysDFDr001PostgresObjectStoreIntegration is the PRODUCTION disaster-recovery
// drill: state is PostgreSQL plus the blob/object data directory (artifacts,
// attestations), never state.json alone.
//
//  1. Real PostgreSQL + real kiwi server + real runner complete trusted work
//     that produces an artifact and a signed execution attestation.
//  2. BEFORE backup: capture job A's artifact hash, attestation bytes/digest
//     and evidence root — the historical evidence this drill must preserve.
//  3. Backup: pg_dump of the application database + recursive copy of the
//     data dir (object/blob store).
//  4. Destroy: stop the server, drop the application database, remove the
//     data dir.
//  5. Restore: create a fresh database, restore the dump, restore the data
//     dir copy into a NEW path.
//  6. Start a NEW server process against the restored database and data dir.
//  7. Historical run is queryable over the public API AND historical
//     evidence MUST still verify (not 404): attestation bytes are
//     byte-identical, the evidence root matches, and the artifact hash is
//     unchanged. A 404 or mismatch is a hard failure — production EnvelopeRef
//     is CAS-relative (`cas:<sha256>`) and must survive a data-dir path change.
//  8. NEW job B runs on the restored cluster to prove liveness.
//
// The FS/dev variant is TestSysDFDr001FSMode in internal/dogfood/system.
func TestSysDFDr001PostgresObjectStoreIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("production DR dogfood builds binaries and starts real PostgreSQL")
	}
	root := t.TempDir()
	bin := buildKiwi(t, root)

	pgDSN, _ := startPostgres(t)
	adminDSN := strings.Replace(pgDSN, "/kiwi_", "/postgres", 1)
	// Derive a key=value admin DSN for psql from the URL.
	pgAdmin := urlToPSQLAdmin(t, pgDSN)

	const runnerToken = "dr-runner-token"
	const adminToken = "dr-admin-token"
	serverPort := freeTCPPort(t)
	serverURL := fmt.Sprintf("http://127.0.0.1:%d", serverPort)
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	srv := spawnServer(t, bin, fmt.Sprintf("127.0.0.1:%d", serverPort), dataDir, pgDSN, runnerToken, adminToken)
	waitFor(t, "server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	repoURL := startGitMirror(t, root)
	work := filepath.Join(root, "work")
	_ = os.MkdirAll(work, 0o700)
	runner := spawnRunner(t, bin, serverURL, runnerToken, "dr-runner", work, filepath.Join(root, "id"))
	waitFor(t, "runner registered", 30*time.Second, func() bool {
		code := apiGet(t, serverURL, adminToken, "/api/v1/runners", &[]any{})
		return code == 200
	})
	_ = runner

	// Trusted work through the product schedule API. Job A ("probe")
	// produces a deterministic artifact so the DR drill can hash it before
	// the disaster and require the same bytes after restore.
	spec := `version: 1
on:
  schedule:
    cron: "0 0 * * *"
jobs:
  hold:
    runtime: native
    steps:
      - name: hold
        run: sleep 2 && echo held
  probe:
    runtime: native
    steps:
      - name: probe
        run: |
          set -euo pipefail
          mkdir -p out
          echo dr-artifact-payload-v1 > out/probe.bin
    artifacts:
      - name: probe
        paths: [out]
`
	schedBody := map[string]any{
		"id":         "dr-sched-1",
		"repository": "owner/repo",
		"repo_url":   repoURL,
		"spec":       spec,
		"trusted":    true,
		"enabled":    true,
	}
	var sched struct {
		ID string `json:"id"`
	}
	code, raw := apiPut(t, serverURL, adminToken, "/api/v1/schedules", schedBody, &sched)
	if code >= 300 {
		t.Fatalf("schedule put = %d: %s", code, raw)
	}
	var run struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	code, raw = apiPost(t, serverURL, adminToken, "/api/v1/schedules/"+sched.ID+"/trigger", map[string]any{}, &run)
	if code >= 300 {
		t.Fatalf("trigger = %d: %s", code, raw)
	}
	var jobs []struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		Error           string `json:"error"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	waitFor(t, "jobs terminal", 90*time.Second, func() bool {
		code := apiGet(t, serverURL, adminToken, "/api/v1/runs/"+run.ID+"/jobs", &jobs)
		if code != 200 || len(jobs) == 0 {
			return false
		}
		// Both jobs must be done enough to persist state (hold sleeps 4s).
		return len(jobs) >= 1
	})
	// Wait until at least one job is terminal by polling job status.
	var statusOK bool
	waitFor(t, "run completed", 90*time.Second, func() bool {
		var runView struct {
			Status string `json:"status"`
		}
		code := apiGet(t, serverURL, adminToken, "/api/v1/runs/"+run.ID, &runView)
		if code != 200 {
			return false
		}
		if runView.Status == "success" || runView.Status == "failure" {
			statusOK = runView.Status == "success"
			return true
		}
		return false
	})
	if !statusOK {
		t.Fatalf("pre-DR run did not succeed")
	}

	// --- BEFORE disaster: capture job A's historical evidence ---
	code = apiGet(t, serverURL, adminToken, "/api/v1/runs/"+run.ID+"/jobs", &jobs)
	if code != 200 || len(jobs) == 0 {
		t.Fatalf("jobs query before backup = %d, jobs=%d", code, len(jobs))
	}
	var jobA *struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		Error           string `json:"error"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	for i := range jobs {
		if jobs[i].Key == "probe" {
			jobA = &jobs[i]
			break
		}
	}
	if jobA == nil {
		t.Fatalf("job A (probe) not found in %d jobs", len(jobs))
	}
	// Attestation bytes + digest + evidence root (hard requirement).
	envBefore := fetchEvidence(t, serverURL, adminToken, jobA.ID, jobA.LeaseGeneration)
	if len(envBefore) == 0 {
		t.Fatal("empty attestation envelope before backup")
	}
	attSum := sha256.Sum256(envBefore)
	attDigestBefore := hex.EncodeToString(attSum[:])
	stBefore := verifyEvidence(t, serverURL, envBefore)
	if stBefore.Attestation == nil {
		t.Fatal("pre-backup statement carries no execution attestation")
	}
	evidenceRootBefore := stBefore.Attestation.EvidenceRootSHA256
	if evidenceRootBefore == "" {
		t.Fatal("pre-backup attestation carries no evidence root")
	}
	if stBefore.Attestation.JobID != jobA.ID {
		t.Fatalf("pre-backup attestation job id = %q, want %q", stBefore.Attestation.JobID, jobA.ID)
	}
	// Artifact hash (preferred): the probe artifact's recorded SHA-256.
	var artifacts []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	code = apiGet(t, serverURL, adminToken, "/api/v1/runs/"+run.ID+"/artifacts", &artifacts)
	if code != 200 {
		t.Fatalf("list artifacts before backup = %d", code)
	}
	var artA *struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	for i := range artifacts {
		if artifacts[i].Name == "probe" {
			artA = &artifacts[i]
			break
		}
	}
	if artA == nil {
		t.Fatalf("probe artifact not listed before backup: %+v", artifacts)
	}
	if artA.SHA256 == "" {
		t.Fatal("probe artifact has empty sha256 before backup")
	}
	// Download the artifact bytes before the disaster so the post-restore
	// download can be compared byte-for-byte (not just the recorded hash).
	code, artBytesBefore := apiGetBytes(t, serverURL, adminToken, "/api/v1/artifacts/"+artA.ID)
	if code != 200 || len(artBytesBefore) == 0 {
		t.Fatalf("download artifact before backup = %d (%d bytes)", code, len(artBytesBefore))
	}
	artSum := sha256.Sum256(artBytesBefore)
	artDigestBefore := hex.EncodeToString(artSum[:])
	if artDigestBefore != artA.SHA256 {
		t.Fatalf("artifact bytes sha256 = %s, want recorded %s", artDigestBefore, artA.SHA256)
	}
	t.Logf("DF-DR-001 pre-backup evidence: job=%s gen=%d attDigest=%s evidenceRoot=%s artifact=%s sha256=%s",
		jobA.ID, jobA.LeaseGeneration, attDigestBefore, evidenceRootBefore, artA.Name, artA.SHA256)

	// --- backup ---
	backupDir := filepath.Join(root, "backup")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dumpPath := filepath.Join(backupDir, "db.dump")
	pgDump := resolvePG(t, "pg_dump")
	dump := exec.Command(pgDump, "--format=custom", "-f", dumpPath, pgDSN)
	if out, err := dump.CombinedOutput(); err != nil {
		t.Fatalf("pg_dump: %v\n%s", err, out)
	}
	dataBackup := filepath.Join(backupDir, "data")
	if err := copyTree(dataDir, dataBackup); err != nil {
		t.Fatalf("backup data dir: %v", err)
	}

	// --- destroy ---
	srv.kill()
	_ = os.RemoveAll(dataDir)
	psql := resolvePG(t, "psql")
	dbName := dbNameFromDSN(pgDSN)
	if out, err := exec.Command(psql, pgAdmin, "-c", "DROP DATABASE IF EXISTS "+dbName).CombinedOutput(); err != nil {
		t.Fatalf("drop database: %v\n%s", err, out)
	}

	// --- restore ---
	if out, err := exec.Command(psql, pgAdmin, "-c", "CREATE DATABASE "+dbName).CombinedOutput(); err != nil {
		t.Fatalf("recreate database: %v\n%s", err, out)
	}
	restorePGDump(t, pgDSN, dumpPath)
	dataDir2 := filepath.Join(root, "data-restored")
	if err := copyTree(dataBackup, dataDir2); err != nil {
		t.Fatalf("restore data dir: %v", err)
	}

	// --- new processes on restored state ---
	serverPort2 := freeTCPPort(t)
	serverURL2 := fmt.Sprintf("http://127.0.0.1:%d", serverPort2)
	srv2 := spawnServer(t, bin, fmt.Sprintf("127.0.0.1:%d", serverPort2), dataDir2, pgDSN, runnerToken, adminToken)
	defer srv2.kill()
	waitFor(t, "restored server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL2 + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// Historical run must still be served from restored Postgres.
	var runAfter struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	code = apiGet(t, serverURL2, adminToken, "/api/v1/runs/"+run.ID, &runAfter)
	raw = []byte{}
	if code != 200 {
		t.Fatalf("restored run query = %d: %s", code, raw)
	}
	if runAfter.ID != run.ID {
		t.Fatalf("restored run id = %q, want %q", runAfter.ID, run.ID)
	}

	var jobsAfter []struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	code = apiGet(t, serverURL2, adminToken, "/api/v1/runs/"+run.ID+"/jobs", &jobsAfter)
	raw = []byte{}
	if code != 200 || len(jobsAfter) == 0 {
		t.Fatalf("restored jobs query = %d: %s", code, raw)
	}

	// --- historical evidence MUST verify after restore (404 = fail) ---
	// Production EnvelopeRef is CAS-relative (`cas:<sha256>`), so the
	// attestation must remain reachable after a data-dir path change. A 404
	// or a mismatch is a hard failure — never a tolerated limitation.
	envAfter := fetchEvidence(t, serverURL2, adminToken, jobA.ID, jobA.LeaseGeneration)
	if len(envAfter) == 0 {
		t.Fatal("empty attestation envelope after restore (404-equivalent: historical evidence lost)")
	}
	if !bytes.Equal(envBefore, envAfter) {
		attSumAfter := sha256.Sum256(envAfter)
		t.Fatalf("attestation envelope changed across backup/restore: before=%s after=%s",
			attDigestBefore, hex.EncodeToString(attSumAfter[:]))
	}
	stAfter := verifyEvidence(t, serverURL2, envAfter)
	if stAfter.Attestation == nil {
		t.Fatal("restored statement carries no execution attestation")
	}
	if stAfter.Attestation.EvidenceRootSHA256 != evidenceRootBefore {
		t.Fatalf("evidence root after restore = %q, want %q",
			stAfter.Attestation.EvidenceRootSHA256, evidenceRootBefore)
	}
	if stAfter.Attestation.JobID != jobA.ID {
		t.Fatalf("restored attestation job id = %q, want %q", stAfter.Attestation.JobID, jobA.ID)
	}

	// --- artifact bytes must match after restore (preferred hard check) ---
	var artifactsAfter []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	code = apiGet(t, serverURL2, adminToken, "/api/v1/runs/"+run.ID+"/artifacts", &artifactsAfter)
	if code != 200 {
		t.Fatalf("list artifacts after restore = %d", code)
	}
	var artAfter *struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	for i := range artifactsAfter {
		if artifactsAfter[i].Name == "probe" {
			artAfter = &artifactsAfter[i]
			break
		}
	}
	if artAfter == nil {
		t.Fatalf("probe artifact lost after restore: %+v", artifactsAfter)
	}
	if artAfter.SHA256 != artA.SHA256 {
		t.Fatalf("artifact recorded sha256 after restore = %s, want %s", artAfter.SHA256, artA.SHA256)
	}
	code, artBytesAfter := apiGetBytes(t, serverURL2, adminToken, "/api/v1/artifacts/"+artAfter.ID)
	if code != 200 || len(artBytesAfter) == 0 {
		t.Fatalf("download artifact after restore = %d (%d bytes) — historical artifact lost", code, len(artBytesAfter))
	}
	artSumAfter := sha256.Sum256(artBytesAfter)
	artDigestAfter := hex.EncodeToString(artSumAfter[:])
	if artDigestAfter != artA.SHA256 {
		t.Fatalf("artifact bytes sha256 after restore = %s, want %s", artDigestAfter, artA.SHA256)
	}
	if !bytes.Equal(artBytesBefore, artBytesAfter) {
		t.Fatal("artifact bytes changed across backup/restore")
	}

	// --- NEW job B on the restored cluster: liveness ---
	// Schedule triggers are idempotent per nominal minute, so job B uses a
	// fresh schedule id — the restored cluster must accept NEW trusted work
	// end-to-end (enqueue → runner lease → artifact → attestation).
	workB := filepath.Join(root, "work-b")
	_ = os.MkdirAll(workB, 0o700)
	runnerB := spawnRunner(t, bin, serverURL2, runnerToken, "dr-runner-b", workB, filepath.Join(root, "id-b"))
	_ = runnerB
	waitFor(t, "runner B registered", 30*time.Second, func() bool {
		var runners []any
		return apiGet(t, serverURL2, adminToken, "/api/v1/runners", &runners) == 200 && len(runners) >= 1
	})
	schedBBody := map[string]any{
		"id":         "dr-sched-2",
		"repository": "owner/repo",
		"repo_url":   repoURL,
		"spec":       spec,
		"trusted":    true,
		"enabled":    true,
	}
	var schedB struct {
		ID string `json:"id"`
	}
	code, raw = apiPut(t, serverURL2, adminToken, "/api/v1/schedules", schedBBody, &schedB)
	if code >= 300 {
		t.Fatalf("job B schedule put = %d: %s", code, raw)
	}
	var runB struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	code, raw = apiPost(t, serverURL2, adminToken, "/api/v1/schedules/"+schedB.ID+"/trigger", map[string]any{}, &runB)
	if code >= 300 {
		t.Fatalf("trigger job B = %d: %s", code, raw)
	}
	if runB.ID == "" || runB.ID == run.ID {
		t.Fatalf("job B run id = %q, want a fresh run (pre-DR %q)", runB.ID, run.ID)
	}
	var runBOK bool
	waitFor(t, "job B completed", 120*time.Second, func() bool {
		var runView struct {
			Status string `json:"status"`
		}
		if apiGet(t, serverURL2, adminToken, "/api/v1/runs/"+runB.ID, &runView) != 200 {
			return false
		}
		if runView.Status == "success" {
			runBOK = true
			return true
		}
		return runView.Status == "failure"
	})
	if !runBOK {
		t.Fatalf("job B on restored cluster did not succeed (run %s)", runB.ID)
	}
	// Job B must also produce verifiable evidence — liveness includes the
	// evidence path, not just a green run row.
	var jobsB []struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	waitFor(t, "job B jobs listed", 30*time.Second, func() bool {
		return apiGet(t, serverURL2, adminToken, "/api/v1/runs/"+runB.ID+"/jobs", &jobsB) == 200 && len(jobsB) > 0
	})
	var jobB *struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	for i := range jobsB {
		if jobsB[i].Key == "probe" {
			jobB = &jobsB[i]
			break
		}
	}
	if jobB == nil {
		t.Fatalf("job B probe job not found: %+v", jobsB)
	}
	envB := fetchEvidence(t, serverURL2, adminToken, jobB.ID, jobB.LeaseGeneration)
	if len(envB) == 0 {
		t.Fatal("job B produced no attestation on the restored cluster")
	}
	stB := verifyEvidence(t, serverURL2, envB)
	if stB.Attestation == nil || stB.Attestation.JobID != jobB.ID {
		t.Fatalf("job B attestation mismatch: %+v", stB.Attestation)
	}

	t.Logf("DF-DR-001 production restore ok: run=%s status=%s jobs=%d dump=%s data=%s attDigest=%s evidenceRoot=%s artifactSha=%s jobB=%s",
		runAfter.ID, runAfter.Status, len(jobsAfter), dumpPath, dataDir2,
		attDigestBefore, evidenceRootBefore, artA.SHA256, runB.ID)
	_ = adminDSN
}

func dbNameFromDSN(dsn string) string {
	// postgres://user@host:port/dbname?params
	u := dsn
	if i := strings.Index(u, "?"); i >= 0 {
		u = u[:i]
	}
	slash := strings.LastIndex(u, "/")
	if slash < 0 {
		return "postgres"
	}
	name := u[slash+1:]
	if name == "" {
		return "postgres"
	}
	return name
}

func urlToPSQLAdmin(t *testing.T, dsn string) string {
	t.Helper()
	// Parse with net/url so the password survives. Hand-splitting the URL
	// dropped it and psql then prompted / failed on trust auth.
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse DSN %q: %v", dsn, err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	user := "postgres"
	if u.User != nil {
		if name := u.User.Username(); name != "" {
			user = name
		}
	}
	if pw, ok := u.User.Password(); ok && pw != "" {
		return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=postgres sslmode=disable", host, port, user, pw)
	}
	return fmt.Sprintf("host=%s port=%s user=%s dbname=postgres sslmode=disable", host, port, user)
}

// copyTree recursively copies src into dst (production object-store backup).
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

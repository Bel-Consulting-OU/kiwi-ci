package server

// Real-PostgreSQL integration tests for the server package: NewPersistent +
// SwitchToDB against a live database, driven over the HTTP handlers. Gated on
// KIWI_TEST_POSTGRES_URL (skipped when unset, and in -short mode).
//
// Every test opens its own throwaway schema (kiwi_it_<random>) by setting
// search_path on the pool and DROP SCHEMA ... CASCADE on cleanup. The
// cross-instance test runs two servers over the same database and the same
// data directory (shared CAS blobs and cluster/lease keys, the production HA
// topology) to prove leases, heartbeats, completions and artifacts flow
// across replicas.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const pgITServerPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo hi
`

const pgITServerArtifactPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - out/
        retention: 1h
    steps:
      - run: echo hi
`

// pgITServerDSN returns the integration DSN or skips the test.
func pgITServerDSN(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("postgres integration tests skipped in -short mode")
	}
	dsn := strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL integration tests")
	}
	return dsn
}

// pgITServerRandomHex returns n random lowercase hex characters.
func pgITServerRandomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return hex.EncodeToString(b)[:n]
}

// pgITServerEnv owns one per-test schema.
type pgITServerEnv struct {
	base   string
	schema string
}

func pgITServerSetup(t *testing.T) *pgITServerEnv {
	t.Helper()
	base := pgITServerDSN(t)
	schema := "kiwi_it_" + pgITServerRandomHex(t, 12)
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to KIWI_TEST_POSTGRES_URL: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create schema %s: %v", schema, err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("close admin connection: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		c, cerr := pgx.Connect(cctx, base)
		if cerr != nil {
			t.Logf("drop schema %s: connect: %v", schema, cerr)
			return
		}
		defer func() { _ = c.Close(cctx) }()
		if _, err := c.Exec(cctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
	})
	return &pgITServerEnv{base: base, schema: schema}
}

// open opens one migrated pool bound to the test schema.
func (e *pgITServerEnv) open(t *testing.T) *storage.PostgresStore {
	t.Helper()
	ctx := context.Background()
	schema := e.schema
	st, err := storage.NewPostgresOpt(ctx, e.base, func(c *pgxpool.Config) {
		if c.ConnConfig.RuntimeParams == nil {
			c.ConnConfig.RuntimeParams = map[string]string{}
		}
		c.ConnConfig.RuntimeParams["search_path"] = schema
	})
	if err != nil {
		t.Fatalf("open store on schema %s: %v", schema, err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// pgITServerWithEnv returns a started server wired to a migrated store on
// env's schema.
func pgITServerWithEnv(t *testing.T, env *pgITServerEnv, dataDir string) (*Server, *storage.PostgresStore) {
	t.Helper()
	st := env.open(t)
	s, err := NewPersistent("token", "token", dataDir)
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	if err := s.SwitchToDB(st); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	return s, st
}

// pgITServer returns a started server on a fresh schema.
func pgITServer(t *testing.T, dataDir string) (*Server, *storage.PostgresStore) {
	t.Helper()
	return pgITServerWithEnv(t, pgITServerSetup(t), dataDir)
}

// pgITServerAwaitLeadership waits until s holds the scheduler leadership
// claim. Another package's integration test can briefly hold the shared
// database-wide advisory lock, so the wait is bounded and explicit.
func pgITServerAwaitLeadership(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		if s.Sched != nil && s.Sched.IsLeader(context.Background()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for scheduler leadership")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// pgITDo serves one request against the server handler.
func pgITDo(t *testing.T, s *Server, method, path, bearer, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// pgITRegisterRunner registers a bearer runner and returns its ID.
func pgITRegisterRunner(t *testing.T, s *Server) string {
	t.Helper()
	w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatalf("decode runner: %v", err)
	}
	return ri.ID
}

// pgITSubmit submits an untrusted run and returns the decoded run.
func pgITSubmit(t *testing.T, s *Server, pipelineText string) model.Run {
	t.Helper()
	body, err := json.Marshal(SubmitRun{RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r", Ref: "refs/heads/main", SHA: "abc123", Event: "push", Pipeline: pipelineText})
	if err != nil {
		t.Fatal(err)
	}
	w := pgITDo(t, s, http.MethodPost, "/api/v1/runs", "token", string(body), nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var run model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	return run
}

// pgITNext leases the next job for runnerID, retrying briefly while the
// database-wide leadership claim is held by another integration test.
func pgITNext(t *testing.T, s *Server, runnerID string) Task {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "", nil)
		switch w.Code {
		case http.StatusOK:
			var task Task
			if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
				t.Fatalf("decode task: %v", err)
			}
			return task
		case http.StatusServiceUnavailable:
			// Standby: another instance (or another package's test) holds the
			// claim; retry until it is released.
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for a lease: %s", w.Body.String())
			}
			time.Sleep(250 * time.Millisecond)
		case http.StatusNoContent:
			t.Fatalf("no queued job to lease")
		default:
			t.Fatalf("next: %d %s", w.Code, w.Body.String())
		}
	}
}

// pgITLeaseHeaders renders the runner lease headers for a task.
func pgITLeaseHeaders(task Task, runnerID string) map[string]string {
	return map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      task.LeaseToken,
		"X-Kiwi-Lease-Generation": fmt.Sprint(task.LeaseGeneration),
	}
}

// pgITLeaseBody renders the runner lease JSON body for a task.
func pgITLeaseBody(task Task, runnerID string) string {
	b, _ := json.Marshal(map[string]any{
		"runner_id":        runnerID,
		"lease_token":      task.LeaseToken,
		"lease_generation": task.LeaseGeneration,
	})
	return string(b)
}

// TestPostgresIntegrationServerEndToEnd drives submit -> lease -> heartbeat ->
// log -> complete over the HTTP handlers against the real database and
// verifies the durable state through the store.
func TestPostgresIntegrationServerEndToEnd(t *testing.T) {
	s, st := pgITServer(t, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	run := pgITSubmit(t, s, pgITServerPipeline)

	task := pgITNext(t, s, runnerID)
	if task.Job.RunID != run.ID || task.LeaseToken == "" || task.LeaseGeneration == 0 {
		t.Fatalf("incomplete task: %+v", task)
	}
	if task.Job.ID == "" || task.Job.Status != model.StatusRunning {
		t.Fatalf("leased job = %+v, want running", task.Job)
	}
	// The lease is durable: the store sees the running job with the token
	// hash and a live expiry.
	durable, err := st.GetJob(context.Background(), task.Job.ID)
	if err != nil {
		t.Fatalf("durable job: %v", err)
	}
	if durable.Status != model.StatusRunning || durable.LeaseRunnerID != runnerID || durable.LeaseExpiresAt == nil || len(durable.LeaseTokenHash) == 0 {
		t.Fatalf("durable lease = %+v", durable)
	}

	// Heartbeat extends the lease.
	hb := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token", pgITLeaseBody(task, runnerID), nil)
	if hb.Code != http.StatusOK {
		t.Fatalf("heartbeat = %d %s", hb.Code, hb.Body.String())
	}
	// Log line lands durably.
	logBody, _ := json.Marshal(map[string]any{"runner_id": runnerID, "lease_token": task.LeaseToken, "lease_generation": task.LeaseGeneration, "job_key": "build", "step": "run", "line": "hello from integration"})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/log", "token", string(logBody), nil); w.Code != http.StatusNoContent {
		t.Fatalf("log = %d %s", w.Code, w.Body.String())
	}
	logs := pgITDo(t, s, http.MethodGet, "/api/v1/runs/"+run.ID+"/logs", "token", "", nil)
	if logs.Code != http.StatusOK || !strings.Contains(logs.Body.String(), "hello from integration") {
		t.Fatalf("logs = %d %s", logs.Code, logs.Body.String())
	}

	// Complete and verify the durable terminal state; the replay is
	// acknowledged idempotently.
	completeBody, _ := json.Marshal(map[string]any{"runner_id": runnerID, "lease_token": task.LeaseToken, "lease_generation": task.LeaseGeneration, "status": "success", "outputs": map[string]string{"out": "1"}})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(completeBody), nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(completeBody), nil); w.Code != http.StatusNoContent {
		t.Fatalf("replayed complete = %d %s", w.Code, w.Body.String())
	}
	job, err := st.GetJob(context.Background(), task.Job.ID)
	if err != nil || job.Status != model.StatusSuccess || job.LeaseRunnerID != "" {
		t.Fatalf("completed job = %+v err=%v", job, err)
	}
	if job.Outputs["out"] != "1" {
		t.Fatalf("outputs = %v", job.Outputs)
	}
	runBody := pgITDo(t, s, http.MethodGet, "/api/v1/runs/"+run.ID, "token", "", nil)
	if runBody.Code != http.StatusOK {
		t.Fatalf("get run = %d", runBody.Code)
	}
	var got model.Run
	if err := json.Unmarshal(runBody.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if got.Status != model.StatusSuccess {
		t.Fatalf("run status = %s, want success", got.Status)
	}
	// A stale generation is rejected with a conflict, not accepted.
	staleBody, _ := json.Marshal(map[string]any{"runner_id": runnerID, "lease_token": task.LeaseToken, "lease_generation": task.LeaseGeneration + 5, "status": "success"})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(staleBody), nil); w.Code != http.StatusConflict {
		t.Fatalf("stale complete = %d, want 409: %s", w.Code, w.Body.String())
	}
}

// TestPostgresIntegrationServerCrossInstance runs two servers over the same
// database and the same data directory (shared CAS and keys): the leader
// leases, the standby heartbeats, uploads an artifact and completes, and the
// leader downloads the artifact the standby wrote.
func TestPostgresIntegrationServerCrossInstance(t *testing.T) {
	dir := t.TempDir()
	env := pgITServerSetup(t)
	sA, _ := pgITServerWithEnv(t, env, dir)
	pgITServerAwaitLeadership(t, sA)

	sB, storeB := pgITServerWithEnv(t, env, dir)
	if sB.Sched.IsLeader(context.Background()) {
		t.Fatal("second instance must start as standby while the first holds the claim")
	}
	// The standby refuses to lease.
	unknownRunner := pgITServerRandomHex(t, 32)
	if w := pgITDo(t, sB, http.MethodPost, "/api/v1/runners/"+unknownRunner+"/next", "token", "", nil); w.Code != http.StatusServiceUnavailable && w.Code != http.StatusNotFound {
		t.Fatalf("standby next = %d, want 503/404: %s", w.Code, w.Body.String())
	}

	runnerID := pgITRegisterRunner(t, sA)
	run := pgITSubmit(t, sA, pgITServerArtifactPipeline)
	task := pgITNext(t, sA, runnerID)

	// The standby handles the heartbeat and the artifact upload for a lease
	// the leader issued (shared lease key + shared CAS).
	if w := pgITDo(t, sB, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token", pgITLeaseBody(task, runnerID), nil); w.Code != http.StatusOK {
		t.Fatalf("standby heartbeat = %d %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, sB, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "cross-instance-bytes", pgITLeaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
		t.Fatalf("standby upload = %d %s", w.Code, w.Body.String())
	}
	completeBody, _ := json.Marshal(map[string]any{"runner_id": runnerID, "lease_token": task.LeaseToken, "lease_generation": task.LeaseGeneration, "status": "success"})
	if w := pgITDo(t, sB, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(completeBody), nil); w.Code != http.StatusNoContent {
		t.Fatalf("standby complete = %d %s", w.Code, w.Body.String())
	}

	// The leader serves the artifact the standby staged (shared blob store).
	list := pgITDo(t, sA, http.MethodGet, "/api/v1/runs/"+run.ID+"/artifacts", "token", "", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list artifacts = %d %s", list.Code, list.Body.String())
	}
	var records []model.ArtifactRecord
	if err := json.Unmarshal(list.Body.Bytes(), &records); err != nil {
		t.Fatalf("decode artifacts: %v", err)
	}
	if len(records) != 1 || records[0].Name != "bin" {
		t.Fatalf("artifacts = %+v, want the standby-staged bin", records)
	}
	download := pgITDo(t, sA, http.MethodGet, "/api/v1/artifacts/"+records[0].ID, "token", "", nil)
	if download.Code != http.StatusOK || download.Body.String() != "cross-instance-bytes" {
		t.Fatalf("cross-instance download = %d %q", download.Code, download.Body.String())
	}
	if job, err := storeB.GetJob(context.Background(), task.Job.ID); err != nil || job.Status != model.StatusSuccess {
		t.Fatalf("durable cross-instance job = %+v err=%v", job, err)
	}
}

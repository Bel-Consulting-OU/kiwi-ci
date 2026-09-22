package server

// Cross-feature composition: rolling-version HA on an OLD-version-shaped
// database.
//
// The world is written the way the PREVIOUS binary wrote it, not through the
// current enqueue path: a running lease with services declared but no
// service_envelope_request key, an empty reservation ledger, a report row
// with no delivery receipt, snapshot rows with minimal (pre-entries)
// payloads, and a runner whose profile is selected by certificate serial
// only (no runner_profile_links row) with the old self-reported labels and
// capacity. One PostgreSQL schema per test, so the rows are real.
//
// The composition then promotes a NEW-version leader (the leadership claim
// plus its promotion gate) and asserts every path survives the missing
// fields: the reservation reconciliation conservatively charges the legacy
// service job (its own request again as the envelope) while a service-less
// job is charged exactly its request, the cert-serial-only runner still
// leases under its live profile, legacy report resends converge to one report
// and one fold per delivery, and the legacy snapshot rows list and paginate
// without a 500. Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// composeLegacyExec runs one statement inside the test's schema.
func composeLegacyExec(t *testing.T, env *pgITServerEnv, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.base)
	if err != nil {
		t.Fatalf("raw connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "SET search_path TO "+pgx.Identifier{env.schema}.Sanitize()); err != nil {
		t.Fatalf("raw search_path: %v", err)
	}
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("raw exec %q: %v", sql, err)
	}
}

// composeLegacyLedgerRow reads one job's reservation ledger row.
func composeLegacyLedgerRow(t *testing.T, env *pgITServerEnv, jobID string) (cpu float64, memory, disk int64, pids int, found bool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, env.base)
	if err != nil {
		t.Fatalf("raw connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "SET search_path TO "+pgx.Identifier{env.schema}.Sanitize()); err != nil {
		t.Fatalf("raw search_path: %v", err)
	}
	err = conn.QueryRow(ctx, `SELECT cpu, memory, disk, pids FROM job_resource_reservations WHERE job_id=$1`, jobID).
		Scan(&cpu, &memory, &disk, &pids)
	if err == pgx.ErrNoRows {
		return 0, 0, 0, 0, false
	}
	if err != nil {
		t.Fatalf("read ledger row: %v", err)
	}
	return cpu, memory, disk, pids, true
}

// composeLegacyMakeServiceJob marks one running job as an OLD-version service
// lease: its payload gains the declared services of a container job and loses
// the service_envelope_request key entirely (the legacy marker the reconcile
// charges conservatively), with the lease identity an old leader wrote and no
// reservation row.
func composeLegacyMakeServiceJob(t *testing.T, env *pgITServerEnv, runnerID, jobID string, generation int64) {
	t.Helper()
	pgITWriteOldLeaderRunningJob(t, env, runnerID, jobID, generation)
	composeLegacyExec(t, env, `UPDATE jobs SET payload = jsonb_set(payload #- '{service_envelope_request}', '{compiled_job_payload,effective_job,job,services}', '[{"name":"db","image":"postgres:16"}]'::jsonb, true) WHERE id=$1`, jobID)
}

// TestComposeLegacyWorldLeaderPromotionPG is the rolling-version over-charge
// and under-charge proof: after promotion, the legacy services-without-
// envelope job is charged its own request a second time (conservative
// envelope) while the legacy service-less job is charged exactly its request,
// and a re-run is idempotent.
func TestComposeLegacyWorldLeaderPromotionPG(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	// The legacy world's 5 GiB jobs are untrusted: the ceiling must admit
	// them for the OLD-version leader to have written them at all.
	s.UntrustedMemoryCeiling = 16 << 30
	runnerID := pgITRegisterRunner(t, s)

	// Legacy service job: container runtime, 5 GiB declared, services, and no
	// envelope key.
	serviceRun := pgITSubmit(t, s, pgITResourcePipeline)
	serviceJobID := pgITRunFirstJobID(t, s, serviceRun.ID)
	composeLegacyMakeServiceJob(t, env, runnerID, serviceJobID, 7)
	// Legacy service-less job written the same old-leader way (its payload
	// keeps the current binary's empty envelope, which is charged exactly).
	plainRun := pgITSubmit(t, s, pgITResourcePipeline)
	plainJobID := pgITRunFirstJobID(t, s, plainRun.ID)
	pgITWriteOldLeaderRunningJob(t, env, runnerID, plainJobID, 8)

	if rows := pgITReservationRows(t, env); rows != 0 {
		t.Fatalf("precondition: ledger rows = %d, want the old world's empty ledger", rows)
	}

	// Promotion: the new leader reconciles the ledger BEFORE issuing leases.
	res, err := st.ReconcileResourceReservations(context.Background())
	if err != nil {
		t.Fatalf("promotion reconcile: %v", err)
	}
	if res.Running != 2 || res.Upserted != 2 || res.Deleted != 0 {
		t.Fatalf("reconcile result = %+v, want Running/Upserted 2 and Deleted 0", res)
	}

	cpu, memory, disk, pids, found := composeLegacyLedgerRow(t, env, serviceJobID)
	if !found {
		t.Fatal("legacy service job has no reservation row after promotion")
	}
	if memory != 10<<30 {
		t.Fatalf("legacy service job reserved memory = %d, want 10GiB (own 5GiB + conservative envelope 5GiB)", memory)
	}
	plainCPU, plainMemory, plainDisk, plainPIDs, found := composeLegacyLedgerRow(t, env, plainJobID)
	if !found {
		t.Fatal("legacy service-less job has no reservation row after promotion")
	}
	if plainMemory != 5<<30 {
		t.Fatalf("legacy service-less job reserved memory = %d, want exactly its 5GiB request", plainMemory)
	}
	// The conservative envelope re-charges the WHOLE own request (every
	// dimension), so the service job's row is exactly twice the service-less
	// job's row — the documented upper bound that keeps the gate armed.
	if cpu != 2*plainCPU || disk != 2*plainDisk || pids != 2*plainPIDs {
		t.Fatalf("legacy service job reserved cpu/disk/pids = %v/%d/%d, want exactly 2x the plain job's %v/%d/%d",
			cpu, disk, pids, plainCPU, plainDisk, plainPIDs)
	}

	// Idempotence: a second promotion pass rewrites the same ledger.
	res2, err := st.ReconcileResourceReservations(context.Background())
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if res2.Running != 2 || res2.Upserted != 2 || res2.Deleted != 0 {
		t.Fatalf("second reconcile = %+v, want the same Running/Upserted and no deletions", res2)
	}
	if _, memory2, _, _, _ := composeLegacyLedgerRow(t, env, serviceJobID); memory2 != 10<<30 {
		t.Fatalf("second reconcile changed the service reservation to %d", memory2)
	}

	// The promoted leader's lease path runs the reconciliation gate without a
	// 500 on the missing envelope fields: there is nothing queued, so the
	// answer is a clean no-content.
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("promoted leader next() = %d, want 204: %s", w.Code, w.Body.String())
	}
}

// composeLegacyGPUPipeline requires the gpu label the legacy runner does not
// self-report: only the live certificate-serial profile grants it.
const composeLegacyGPUPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    runner: [gpu]
    steps:
      - run: echo hi
`

// TestComposeLegacyWorldCertSerialRunnerLeasePG pins the cert-serial-only
// profile world: a runner row written by the old binary (self-reported
// labels/capacity, no resource_capacity, no runner-ID link) still leases
// through its LIVE certificate-serial profile, so a gpu job is admitted even
// though the stored snapshot never mentions gpu — and the profile's capacity
// bound (1), not the stored 8, applies.
func TestComposeLegacyWorldCertSerialRunnerLeasePG(t *testing.T) {
	env := pgITServerSetup(t)
	s, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)

	serial := "legacy-serial-" + pgITServerRandomHex(t, 8)
	profileID := "legacy-prof-" + pgITServerRandomHex(t, 6)
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runner-profiles", "token",
		`{"id":"`+profileID+`","labels":["container","gpu"],"capabilities":["container"],"max_capacity":1,"max_memory":8589934592,"max_cpu":4}`, nil); w.Code != http.StatusCreated {
		t.Fatalf("create profile = %d %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "token", "{}", nil); w.Code != http.StatusOK {
		t.Fatalf("bind cert profile = %d %s", w.Code, w.Body.String())
	}
	w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"legacy-cert-runner","cert_serial":"`+serial+`","protocol_min":3,"protocol_max":3,"capabilities":["container"],"capacity":8,"protocol_min":3,"protocol_max":3}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register = %d %s", w.Code, w.Body.String())
	}
	var runner model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &runner); err != nil {
		t.Fatal(err)
	}

	// Rewrite the row into the old-version shape: the snapshot the old binary
	// stored (labels without gpu, capacity 8, no resource_capacity) and no
	// runner-ID binding, only the certificate-serial binding.
	composeLegacyExec(t, env, `UPDATE runners SET capacity=8, payload = jsonb_set(jsonb_set(jsonb_set(payload, '{labels}', '["container"]'::jsonb, true), '{capabilities}', '["container"]'::jsonb, true), '{resource_capacity}', '{}'::jsonb, true) WHERE id=$1`, runner.ID)
	composeLegacyExec(t, env, `DELETE FROM runner_profile_links WHERE runner_id=$1`, runner.ID)
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM runner_profile_links WHERE runner_id=$1`, runner.ID); got != 0 {
		t.Fatalf("legacy runner still has %d runner-ID binding(s)", got)
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM cert_profile_links WHERE serial=$1`, serial); got != 1 {
		t.Fatalf("certificate binding rows = %d, want 1", got)
	}

	// The gpu job leases under the live cert-serial profile: without the
	// overlay the stored snapshot's labels would deny it.
	gpuRun := pgITSubmit(t, s, composeLegacyGPUPipeline)
	task := pgITNext(t, s, runner.ID)
	if task.Job.ID != pgITRunFirstJobID(t, s, gpuRun.ID) {
		t.Fatalf("leased job %s, want the gpu job of run %s", task.Job.ID, gpuRun.ID)
	}
	if task.Job.Key != "build" {
		t.Fatalf("leased job key = %q", task.Job.Key)
	}
	// The profile's capacity bound (1) applies, not the stored 8: a second
	// gpu job finds no free slot.
	second := pgITSubmit(t, s, composeLegacyGPUPipeline)
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runner.ID+"/next", "token", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("second gpu lease = %d, want 204 under the profile's capacity 1: %s", w.Code, w.Body.String())
	}
	// The waiting job stays queued with a capacity reason (no 500 on the
	// missing resource_capacity snapshot).
	if reason := pgITJobQueueReason(t, s, second.ID); reason == "" {
		t.Fatal("waiting gpu job has no queue reason")
	}
	// Releasing the first lease frees the profile slot and the second leases.
	complete := `{"runner_id":` + jsonStr(runner.ID) + `,"lease_token":` + jsonStr(task.LeaseToken) + `,"lease_generation":` + strconv.FormatInt(task.LeaseGeneration, 10) + `,"status":"success"}`
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", complete, nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runner.ID+"/next", "token", "", nil); w.Code != http.StatusOK {
		t.Fatalf("second lease after completion = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// TestComposeLegacyWorldReportResendPG composes the pre-receipt report world
// with the legacy resend convergence: a report row that predates migration
// 0029 (no delivery receipt) plus a legacy client that resends without a
// delivery_id. The first resend claims a synthesized receipt; every later
// resend of the same bytes is an idempotent replay — exactly one NEW report
// and one fold per delivery — and the pre-existing row is never lost or
// rewritten.
func TestComposeLegacyWorldReportResendPG(t *testing.T) {
	env := pgITServerSetup(t)
	s, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	run := pgITSubmit(t, s, pgITServerPipeline)
	task := pgITNext(t, s, runnerID)
	canonical := storage.RepoIDForRun(run)
	path := "/api/v1/jobs/" + task.Job.ID + "/tests"
	body, _ := legacyReportBody(task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration,
		model.TestResult{Name: "legacy-it", Class: "C", Duration: 1, Passed: true})

	if w := pgITDo(t, s, http.MethodPost, path, "token", body, nil); w.Code != http.StatusCreated {
		t.Fatalf("first legacy upload = %d: %s", w.Code, w.Body.String())
	}
	// Downgrade the world: delete the receipt so the durable report row is
	// exactly the pre-0029 shape (a report with no delivery rows). The legacy
	// row keeps a random report ID and no stored content digest.
	composeLegacyExec(t, env, `DELETE FROM test_report_deliveries`)
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_report_deliveries`); got != 0 {
		t.Fatalf("delivery rows after the downgrade = %d, want the legacy world's zero", got)
	}
	legacyRow := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_results WHERE run_id=$1`, run.ID)
	if legacyRow != 1 {
		t.Fatalf("legacy report rows = %d, want 1", legacyRow)
	}

	// The legacy resend (no delivery_id) claims the synthesized receipt and
	// adds exactly one report; a second resend replays it.
	if w := pgITDo(t, s, http.MethodPost, path, "token", body, nil); w.Code != http.StatusCreated {
		t.Fatalf("legacy resend over a receipt-less report = %d, want 201: %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPost, path, "token", body, nil); w.Code != http.StatusOK {
		t.Fatalf("second legacy resend = %d, want idempotent 200", w.Code)
	}
	if w := pgITDo(t, s, http.MethodPost, path, "token", body, nil); w.Code != http.StatusOK {
		t.Fatalf("third legacy resend = %d, want idempotent 200", w.Code)
	}
	// Exactly one NEW report above the legacy row, and exactly one receipt.
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_results WHERE run_id=$1`, run.ID); got != legacyRow+1 {
		t.Fatalf("report rows after the resend series = %d, want the legacy row plus exactly one new report (%d)", got, legacyRow+1)
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_report_deliveries WHERE job_id=$1`, task.Job.ID); got != 1 {
		t.Fatalf("delivery receipts after the resend series = %d, want exactly 1", got)
	}
	// The fold counts each distinct delivery once: the legacy report was
	// folded by the upgrade bridge at the first new upload and the resend
	// folded once more; the replays folded nothing.
	folded := pgITServerCount(t, env, `SELECT COALESCE(SUM(runs),0)::int FROM test_history_aggregates WHERE repo_id=$1`, canonical)
	if folded != 2 {
		t.Fatalf("folded outcomes = %d, want 2 (legacy report + the single new delivery, replays folded nothing)", folded)
	}
	// A third resend through the same path cannot change anything.
	if got := pgITServerCount(t, env, `SELECT COALESCE(SUM(runs),0)::int FROM test_history_aggregates WHERE repo_id=$1`, canonical); got != folded {
		t.Fatalf("fold count changed across replays: %d -> %d", folded, got)
	}
}

// TestComposeLegacyWorldSnapshotPaginationPG seeds snapshot rows the way a
// pre-paging binary wrote them (minimal JSON payloads with no entries and
// sometimes no id/run_id inside the payload) and walks the admin page
// surface: every row is returned exactly once in oldest-first keyset order,
// empty runs answer an empty page, and nothing 500s on the absent fields.
func TestComposeLegacyWorldSnapshotPaginationPG(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)

	runID := pgITServerRandomHex(t, 32)
	itSnapshotInsertRun(t, st, runID)
	snapID := func(n int) string { return fmt.Sprintf("%032d", n) }
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	// Five rows, deliberately interleaved ids at equal timestamps so the
	// COLLATE "C" tiebreaker is exercised, with pre-entries payloads.
	seed := []struct {
		id        string
		jobID     string
		createdAt time.Time
		payload   string
	}{
		{snapID(3), "job-a", base.Add(3 * time.Minute), `{"id":"` + snapID(3) + `","run_id":"` + runID + `","job_id":"job-a","size":30,"sha256":"` + strings.Repeat("3", 64) + `","root_sha256":"` + strings.Repeat("c", 64) + `"}`},
		{snapID(1), "job-a", base.Add(1 * time.Minute), `{"id":"` + snapID(1) + `","run_id":"` + runID + `","job_id":"job-a","size":10,"sha256":"` + strings.Repeat("1", 64) + `","root_sha256":"` + strings.Repeat("a", 64) + `","path":"/var/lib/kiwi/snapshots/old/1.tar.gz"}`},
		{snapID(2), "job-a", base.Add(1 * time.Minute), `{"id":"` + snapID(2) + `","run_id":"` + runID + `","job_id":"job-a","size":20,"sha256":"` + strings.Repeat("2", 64) + `","root_sha256":"` + strings.Repeat("b", 64) + `"}`},
		{snapID(5), "job-b", base.Add(5 * time.Minute), `{"id":"` + snapID(5) + `","run_id":"` + runID + `","job_id":"job-b","size":50,"sha256":"` + strings.Repeat("5", 64) + `","root_sha256":"` + strings.Repeat("e", 64) + `"}`},
		{snapID(4), "job-b", base.Add(4 * time.Minute), `{"id":"` + snapID(4) + `","run_id":"` + runID + `","job_id":"job-b","size":40,"sha256":"` + strings.Repeat("4", 64) + `","root_sha256":"` + strings.Repeat("d", 64) + `"}`},
	}
	for _, row := range seed {
		composeLegacyExec(t, env, `INSERT INTO workspace_snapshots (id, run_id, job_id, created_at, payload) VALUES ($1,$2,$3,$4,$5::jsonb)`,
			row.id, runID, row.jobID, row.createdAt, row.payload)
	}

	// Admin walk in pages of 2: the concatenation is the keyset order
	// (created_at ASC, id COLLATE "C" ASC) and every row appears once.
	want := []string{snapID(1), snapID(2), snapID(3), snapID(4), snapID(5)}
	var walk []string
	cursor := ""
	pages := 0
	for {
		pages++
		if pages > 6 {
			t.Fatal("legacy snapshot walk did not terminate")
		}
		path := "/api/v1/runs/" + runID + "/snapshots?limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		page := pgITDo(t, s, http.MethodGet, path, "token", "", nil)
		if page.Code != http.StatusOK {
			t.Fatalf("legacy page %d = %d: %s", pages, page.Code, page.Body.String())
		}
		var recs []model.SnapshotRecord
		if err := json.Unmarshal(page.Body.Bytes(), &recs); err != nil {
			t.Fatalf("decode legacy page %d: %v", pages, err)
		}
		if len(recs) > 2 {
			t.Fatalf("legacy page %d returned %d records over the limit", pages, len(recs))
		}
		for _, rec := range recs {
			if len(rec.Entries) != 0 {
				t.Fatalf("legacy record %s unexpectedly carries entries", rec.ID)
			}
			if rec.SHA256 == "" || rec.RootSHA256 == "" {
				t.Fatalf("legacy record lost its digests: %+v", rec)
			}
			walk = append(walk, rec.ID)
		}
		cursor = page.Header().Get("X-Kiwi-Next-Cursor")
		if cursor == "" {
			break
		}
	}
	if len(walk) != len(want) {
		t.Fatalf("legacy walk returned %d rows, want %d: %v", len(walk), len(want), walk)
	}
	for i := range want {
		if walk[i] != want[i] {
			t.Fatalf("legacy walk[%d] = %s, want %s (order %v)", i, walk[i], want[i], walk)
		}
	}
	if pages != 3 {
		t.Fatalf("legacy walk took %d pages, want 3 (5 rows at limit 2, terminal page without a cursor)", pages)
	}
	// A run with no legacy rows answers an empty page.
	emptyRun := pgITServerRandomHex(t, 32)
	itSnapshotInsertRun(t, st, emptyRun)
	empty := pgITDo(t, s, http.MethodGet, "/api/v1/runs/"+emptyRun+"/snapshots", "token", "", nil)
	if empty.Code != http.StatusOK {
		t.Fatalf("empty legacy run listing = %d: %s", empty.Code, empty.Body.String())
	}
	var none []model.SnapshotRecord
	if err := json.Unmarshal(empty.Body.Bytes(), &none); err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("empty legacy run returned %d records", len(none))
	}
}

package server

// L5-B regression tests for legacy test-report delivery (a client that omits
// delivery_id): after the lease is verified the server synthesizes a
// deterministic delivery identity from the authoritative job/lease generation
// and the server-computed content digest, so a dropped response followed by a
// resend converges on exactly ONE report, ONE history fold, ONE metrics
// observation and ONE audit event — in DB mode and in fs/memory mode. A DB
// store that lacks TestReportDeliveryStore fails closed with an opaque 503
// instead of falling back to a non-idempotent insert.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// legacyReportBody renders a /tests body with NO delivery_id member (the
// older client), returning the body and the exact report payload bytes whose
// digest the server will compute.
func legacyReportBody(jobID, runnerID, leaseToken string, generation int64, cases ...model.TestResult) (string, []byte) {
	failures := 0
	for _, c := range cases {
		if !c.Passed && !c.Skipped {
			failures++
		}
	}
	rep := model.TestReport{JobID: jobID, JobKey: "build", Tests: len(cases), Failures: failures, Cases: cases}
	payload, _ := json.Marshal(rep)
	body, _ := json.Marshal(map[string]any{
		"runner_id":        runnerID,
		"lease_token":      leaseToken,
		"lease_generation": generation,
		"content_digest":   testintel.ReportContentDigest(payload),
		"report":           json.RawMessage(payload),
	})
	return string(body), payload
}

// explicitDeliveryBody renders a /tests body with an explicit delivery_id.
func explicitDeliveryBody(jobID, runnerID, leaseToken string, generation int64, deliveryID string, cases ...model.TestResult) (string, []byte) {
	failures := 0
	for _, c := range cases {
		if !c.Passed && !c.Skipped {
			failures++
		}
	}
	rep := model.TestReport{JobID: jobID, JobKey: "build", Tests: len(cases), Failures: failures, Cases: cases}
	payload, _ := json.Marshal(rep)
	body, _ := json.Marshal(map[string]any{
		"runner_id":        runnerID,
		"lease_token":      leaseToken,
		"lease_generation": generation,
		"delivery_id":      deliveryID,
		"content_digest":   testintel.ReportContentDigest(payload),
		"report":           json.RawMessage(payload),
	})
	return string(body), payload
}

// testDurationObservations counts kiwi_test_duration_seconds observations in
// the server registry.
func testDurationObservations(t *testing.T, s *Server) uint64 {
	t.Helper()
	var b strings.Builder
	s.Metrics.WritePrometheus(&b)
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "kiwi_test_duration_seconds_count ") {
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "kiwi_test_duration_seconds_count ")), 10, 64)
			if err != nil {
				t.Fatalf("parse metrics count: %v", err)
			}
			return v
		}
	}
	return 0
}

// uploadedAudits counts the tests.uploaded audit events of the fs/memory
// audit store.
func uploadedAudits(t *testing.T, s *Server) int {
	t.Helper()
	events, err := s.store.ReadAudit(200)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action == "tests.uploaded" {
			n++
		}
	}
	return n
}

// fakeUploadedAudits counts the tests.uploaded events of the DB fake store.
func fakeUploadedAudits(f *dbFakeStore) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.audit {
		if e.Action == "tests.uploaded" {
			n++
		}
	}
	return n
}

// TestTestReportLegacyResendConvergesOnce is the dropped-response contract for
// a client that sends no delivery_id: the resend must be an idempotent replay
// with exactly one report, one fold, one metrics observation and one audit.
func TestTestReportLegacyResendConvergesOnce(t *testing.T) {
	t.Run("aggregate_store", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		body, _ := legacyReportBody("job-a", "runner-a", "cache-lease-token", 5,
			model.TestResult{Name: "t", Class: "C", Duration: 1, Passed: true})
		if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusCreated {
			t.Fatalf("first legacy upload = %d: %s", w.Code, w.Body.String())
		}
		if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusOK {
			t.Fatalf("legacy resend = %d, want idempotent 200", w.Code)
		}
		f.mu.Lock()
		reports := len(f.reports)
		row := f.historyAggregates["github.com/o/repo-a"][fakeHistoryKey("build", "C", "t")]
		receipts := len(f.reportDeliveries)
		f.mu.Unlock()
		if reports != 1 {
			t.Fatalf("reports after legacy resend = %d, want 1 (the pre-fix retry double-inserted)", reports)
		}
		if row.Runs != 1 {
			t.Fatalf("history folds after legacy resend = %d, want 1", row.Runs)
		}
		if receipts != 1 {
			t.Fatalf("delivery receipts after legacy resend = %d, want 1 (the synthesized identity must be durable)", receipts)
		}
		if got := testDurationObservations(t, s); got != 1 {
			t.Fatalf("metrics observations after legacy resend = %d, want 1", got)
		}
		if got := fakeUploadedAudits(f); got != 1 {
			t.Fatalf("tests.uploaded audits after legacy resend = %d, want 1", got)
		}
	})
	t.Run("fs", func(t *testing.T) {
		dir := t.TempDir()
		s, err := NewPersistent("runner-tok", "admin-tok", dir)
		if err != nil {
			t.Fatal(err)
		}
		hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
		body, payload := legacyReportBody("job-a", "runner-a", "cache-lease-token", 5,
			model.TestResult{Name: "t", Duration: 1, Passed: true})
		if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusCreated {
			t.Fatalf("first legacy upload = %d: %s", w.Code, w.Body.String())
		}
		wantID := testintel.DeliveryReportID(synthesizedReportDeliveryID("job-a", 5, testintel.ReportContentDigest(payload)))
		s.mu.Lock()
		_, durable := s.reports[wantID]
		reports := len(s.reports)
		s.mu.Unlock()
		if !durable || reports != 1 {
			t.Fatalf("durable reports = %d (id %s present=%v), want exactly the synthesized identity", reports, wantID, durable)
		}
		if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusOK {
			t.Fatalf("legacy resend = %d, want idempotent 200", w.Code)
		}
		if runs, _, _ := e5HistoryStat(t, s, "github.com/o/repo-a", "t"); runs != 1 {
			t.Fatalf("history folds after legacy resend = %d, want 1", runs)
		}
		if got := testDurationObservations(t, s); got != 1 {
			t.Fatalf("metrics observations after legacy resend = %d, want 1", got)
		}
		if got := uploadedAudits(t, s); got != 1 {
			t.Fatalf("tests.uploaded audits after legacy resend = %d, want 1", got)
		}
		// The deterministic identity survives a restart: the durable report
		// is loaded, not re-created.
		s2, err := NewPersistent("runner-tok", "admin-tok", dir)
		if err != nil {
			t.Fatal(err)
		}
		s2.mu.Lock()
		afterRestart := len(s2.reports)
		s2.mu.Unlock()
		if afterRestart != 1 {
			t.Fatalf("reports after restart = %d, want 1", afterRestart)
		}
	})
}

// deliverylessStore hides every storage extension contract, modelling a
// production database that lacks TestReportDeliveryStore entirely.
type deliverylessStore struct{ storage.Store }

// aggregateWithoutDelivery exposes the aggregate history contract but NOT the
// delivery contract: the pre-fix handler fell back to
// InsertTestReportWithHistory on exactly this shape.
type aggregateWithoutDelivery struct {
	storage.Store
	storage.TestHistoryAggregateStore
}

// TestTestReportDeliveryStoreWithoutContractFailsClosed pins the fail-closed
// 503: neither a plain store (the old InsertTestReport fallback) nor an
// aggregate store (the old InsertTestReportWithHistory fallback) may accept a
// report it cannot deduplicate.
func TestTestReportDeliveryStoreWithoutContractFailsClosed(t *testing.T) {
	for name, wrap := range map[string]func(*dbFakeStore) storage.Store{
		"plain_store": func(f *dbFakeStore) storage.Store { return &deliverylessStore{Store: f} },
		"aggregate_store": func(f *dbFakeStore) storage.Store {
			return &aggregateWithoutDelivery{Store: f, TestHistoryAggregateStore: f}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, f, _, hdrs := cacheFixture(t)
			s.DB = wrap(f)
			body, _ := legacyReportBody("job-a", "runner-a", "cache-lease-token", 5,
				model.TestResult{Name: "t", Class: "C", Duration: 1, Passed: true})
			w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("delivery-less store upload = %d, want 503", w.Code)
			}
			f.mu.Lock()
			reports := len(f.reports)
			rows := len(f.historyAggregates)
			f.mu.Unlock()
			if reports != 0 || rows != 0 {
				t.Fatalf("delivery-less store accepted report/history state: reports=%d aggregate repos=%d", reports, rows)
			}
			if got := testDurationObservations(t, s); got != 0 {
				t.Fatalf("delivery-less store observed %d metrics, want 0", got)
			}
			if got := fakeUploadedAudits(f); got != 0 {
				t.Fatalf("delivery-less store wrote %d audits, want 0", got)
			}
		})
	}
}

// TestTestReportLegacyConflictUnderSynthesizedIdentity proves a conflicting
// payload presented under the SAME synthesized identity (the identity the
// server minted for the first no-delivery_id upload) is refused with 409 and
// changes nothing, in DB and fs mode.
func TestTestReportLegacyConflictUnderSynthesizedIdentity(t *testing.T) {
	t.Run("aggregate_store", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		path := "/api/v1/jobs/job-a/tests"
		bodyA, payloadA := legacyReportBody("job-a", "runner-a", "cache-lease-token", 5,
			model.TestResult{Name: "t", Class: "C", Duration: 1, Passed: true})
		if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", bodyA, hdrs); w.Code != http.StatusCreated {
			t.Fatalf("first legacy upload = %d: %s", w.Code, w.Body.String())
		}
		synth := synthesizedReportDeliveryID("job-a", 5, testintel.ReportContentDigest(payloadA))
		bodyB, _ := explicitDeliveryBody("job-a", "runner-a", "cache-lease-token", 5, synth,
			model.TestResult{Name: "t", Class: "C", Duration: 2, Passed: false})
		if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", bodyB, hdrs); w.Code != http.StatusConflict {
			t.Fatalf("conflicting content under the synthesized identity = %d, want 409", w.Code)
		}
		f.mu.Lock()
		reports := len(f.reports)
		row := f.historyAggregates["github.com/o/repo-a"][fakeHistoryKey("build", "C", "t")]
		f.mu.Unlock()
		if reports != 1 || row.Runs != 1 || row.Fails != 0 {
			t.Fatalf("conflict mutated state: reports=%d row=%+v", reports, row)
		}
	})
	t.Run("fs", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		path := "/api/v1/jobs/job-a/tests"
		bodyA, payloadA := legacyReportBody("job-a", "runner-a", "cache-lease-token", 5,
			model.TestResult{Name: "t", Class: "C", Duration: 1, Passed: true})
		if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", bodyA, hdrs); w.Code != http.StatusCreated {
			t.Fatalf("first legacy upload = %d: %s", w.Code, w.Body.String())
		}
		synth := synthesizedReportDeliveryID("job-a", 5, testintel.ReportContentDigest(payloadA))
		bodyB, _ := explicitDeliveryBody("job-a", "runner-a", "cache-lease-token", 5, synth,
			model.TestResult{Name: "t", Class: "C", Duration: 2, Passed: false})
		if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", bodyB, hdrs); w.Code != http.StatusConflict {
			t.Fatalf("conflicting content under the synthesized identity = %d, want 409", w.Code)
		}
		s.mu.Lock()
		reports := len(s.reports)
		s.mu.Unlock()
		if reports != 1 {
			t.Fatalf("conflict stored %d reports, want 1", reports)
		}
	})
}

// TestTestReportExplicitDeliveryIDIsPreserved proves a legacy client that DOES
// send a stable delivery_id keeps exactly that identity: the receipt (DB) and
// the deterministic report ID (fs) are the client's, never a synthesized one.
func TestTestReportExplicitDeliveryIDIsPreserved(t *testing.T) {
	const explicit = "legacy-stable-client-id"
	t.Run("aggregate_store", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		body, _ := explicitDeliveryBody("job-a", "runner-a", "cache-lease-token", 5, explicit,
			model.TestResult{Name: "t", Class: "C", Duration: 1, Passed: true})
		if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusCreated {
			t.Fatalf("explicit-id upload = %d: %s", w.Code, w.Body.String())
		}
		if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusOK {
			t.Fatalf("explicit-id resend = %d, want 200", w.Code)
		}
		f.mu.Lock()
		_, explicitReceipt := f.reportDeliveries[fakeReportDeliveryKey("job-a", 5, explicit)]
		_, synthesizedReceipt := f.reportDeliveries[fakeReportDeliveryKey("job-a", 5, synthesizedReportDeliveryID("job-a", 5, "unused"))]
		reports := len(f.reports)
		f.mu.Unlock()
		if !explicitReceipt || synthesizedReceipt || reports != 1 {
			t.Fatalf("explicit delivery identity not preserved: explicit=%v synthesized=%v reports=%d", explicitReceipt, synthesizedReceipt, reports)
		}
	})
	t.Run("fs", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		body, _ := explicitDeliveryBody("job-a", "runner-a", "cache-lease-token", 5, explicit,
			model.TestResult{Name: "t", Class: "C", Duration: 1, Passed: true})
		if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusCreated {
			t.Fatalf("explicit-id upload = %d: %s", w.Code, w.Body.String())
		}
		if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusOK {
			t.Fatalf("explicit-id resend = %d, want 200", w.Code)
		}
		wantID := testintel.DeliveryReportID(explicit)
		s.mu.Lock()
		_, ok := s.reports[wantID]
		reports := len(s.reports)
		s.mu.Unlock()
		if !ok || reports != 1 {
			t.Fatalf("explicit-id report = %q present=%v reports=%d; want the client identity", wantID, ok, reports)
		}
	})
}

// TestTestReportLegacySynthesizedIdentityIsStable pins the exact synthesized
// identity formula: the same (job, generation, digest) always yields the same
// identity, and any part change yields a different one.
func TestTestReportLegacySynthesizedIdentityIsStable(t *testing.T) {
	base := synthesizedReportDeliveryID("job-a", 5, "digest-a")
	if len(base) != 64 || !testintel.ValidReportDeliveryID(base) {
		t.Fatalf("synthesized identity %q is not a valid delivery ID", base)
	}
	if again := synthesizedReportDeliveryID("job-a", 5, "digest-a"); again != base {
		t.Fatalf("synthesized identity is not deterministic: %q != %q", again, base)
	}
	for _, other := range []string{
		synthesizedReportDeliveryID("job-b", 5, "digest-a"),
		synthesizedReportDeliveryID("job-a", 6, "digest-a"),
		synthesizedReportDeliveryID("job-a", 5, "digest-b"),
	} {
		if other == base {
			t.Fatalf("synthesized identity collided across distinct inputs: %q", other)
		}
	}
}

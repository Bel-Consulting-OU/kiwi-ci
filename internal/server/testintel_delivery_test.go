package server

// Tests for the durable test-report delivery contract on the /tests endpoint:
// stable delivery identity, idempotent replay, explicit digest conflict,
// bounded decode/payload limits and the suite-scoped flaky summary.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// deliveryReportBody renders a /tests body carrying the stable delivery
// identity. The report payload bytes are marshaled once and embedded
// verbatim, exactly like the runner does, so the computed digest matches the
// bytes the server receives.
func deliveryReportBody(jobID, runnerID, leaseToken string, generation int64, deliveryID string, cases ...model.TestResult) string {
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
	return string(body)
}

// deliveryMemoryBody renders the same body with an explicit padding path, so
// a test can size the serialized report/request precisely.
func deliveryMemoryBody(task Task, runnerID, deliveryID string, pad int, cases ...model.TestResult) (string, []byte) {
	rep := model.TestReport{RunID: task.Job.RunID, JobID: task.Job.ID, JobKey: task.Job.Key, Path: strings.Repeat("a", pad), Tests: len(cases), Cases: cases}
	payload, _ := json.Marshal(rep)
	body, _ := json.Marshal(map[string]any{
		"runner_id":        runnerID,
		"lease_token":      task.LeaseToken,
		"lease_generation": task.LeaseGeneration,
		"delivery_id":      deliveryID,
		"content_digest":   testintel.ReportContentDigest(payload),
		"report":           json.RawMessage(payload),
	})
	return string(body), payload
}

// TestTestReportDeliveryReplayIdempotent drives the DB-mode endpoint: the
// first upload commits, the identical replay is acknowledged with 200 and
// changes nothing (no second report, no second fold, no version bump, no
// duplicate audit), and a reused delivery ID with different content is a 409
// that leaves history untouched.
func TestTestReportDeliveryReplayIdempotent(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	path := "/api/v1/jobs/job-a/tests"
	body := deliveryReportBody("job-a", "runner-a", "cache-lease-token", 5, "delivery-1",
		model.TestResult{Name: "t", Class: "C", Duration: 1, Passed: true})

	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	// The classic dropped-response retry: identical body, identical delivery.
	w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("replay = %d, want idempotent 200: %s", w.Code, w.Body.String())
	}
	var replayed model.TestReport
	if err := json.Unmarshal(w.Body.Bytes(), &replayed); err != nil {
		t.Fatalf("decode replay: %v", err)
	}
	f.mu.Lock()
	reports := append([]model.TestReport(nil), f.reports...)
	version := f.historyVersions["github.com/o/repo-a"]
	audits := 0
	for _, e := range f.audit {
		if e.Action == "tests.uploaded" {
			audits++
		}
	}
	row := f.historyAggregates["github.com/o/repo-a"][fakeHistoryKey("build", "C", "t")]
	f.mu.Unlock()
	if len(reports) != 1 {
		t.Fatalf("reports after replay = %d, want 1 (the pre-fix retry double-inserted)", len(reports))
	}
	if replayed.ID != reports[0].ID {
		t.Fatalf("replay report ID = %q, want the original %q", replayed.ID, reports[0].ID)
	}
	if version != 1 {
		t.Fatalf("history version after replay = %d, want 1", version)
	}
	if row.Runs != 1 {
		t.Fatalf("history folded %d times, want 1", row.Runs)
	}
	if audits != 1 {
		t.Fatalf("tests.uploaded audits = %d, want 1 (a replay must not re-audit)", audits)
	}

	// Same delivery identity with different content: explicit conflict.
	conflict := deliveryReportBody("job-a", "runner-a", "cache-lease-token", 5, "delivery-1",
		model.TestResult{Name: "t", Class: "C", Duration: 2, Passed: false})
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", conflict, hdrs); w.Code != http.StatusConflict {
		t.Fatalf("conflict = %d, want 409: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	reports = append([]model.TestReport(nil), f.reports...)
	version = f.historyVersions["github.com/o/repo-a"]
	row = f.historyAggregates["github.com/o/repo-a"][fakeHistoryKey("build", "C", "t")]
	f.mu.Unlock()
	if len(reports) != 1 || version != 1 || row.Runs != 1 || row.Fails != 0 {
		t.Fatalf("conflict mutated state: reports=%d version=%d row=%+v", len(reports), version, row)
	}
}

// TestTestReportDeliveryConcurrentDuplicatesDB races many identical
// deliveries through the HTTP handler: exactly one commits, the rest are
// served idempotently, and one report/fold/version exists.
func TestTestReportDeliveryConcurrentDuplicatesDB(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	path := "/api/v1/jobs/job-a/tests"
	body := deliveryReportBody("job-a", "runner-a", "cache-lease-token", 5, "delivery-race",
		model.TestResult{Name: "racy", Passed: false},
		model.TestResult{Name: "racy", Passed: true})

	const workers = 8
	var wg sync.WaitGroup
	codes := make([]int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs)
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()
	created, replayed := 0, 0
	for i, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusOK:
			replayed++
		default:
			t.Fatalf("worker %d: status %d", i, code)
		}
	}
	if created != 1 || replayed != workers-1 {
		t.Fatalf("concurrent duplicates: %d created / %d replayed, want exactly one created", created, replayed)
	}
	f.mu.Lock()
	reports := len(f.reports)
	version := f.historyVersions["github.com/o/repo-a"]
	row := f.historyAggregates["github.com/o/repo-a"][fakeHistoryKey("build", "", "racy")]
	f.mu.Unlock()
	if reports != 1 || version != 1 {
		t.Fatalf("concurrent duplicates: reports=%d version=%d, want 1/1", reports, version)
	}
	if row.Runs != 2 {
		t.Fatalf("concurrent duplicate folds = %d, want exactly one report's two cases", row.Runs)
	}
}

// TestTestReportDeliveryDigestAndIDValidation pins the request-level
// integrity checks: a client digest that disagrees with the received bytes
// and a malformed delivery ID are both rejected before any state changes.
func TestTestReportDeliveryDigestAndIDValidation(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	path := "/api/v1/jobs/job-a/tests"
	change := func(body, from, to string) string {
		t.Helper()
		if !strings.Contains(body, from) {
			t.Fatalf("body does not contain %q", from)
		}
		return strings.Replace(body, from, to, 1)
	}

	valid := deliveryReportBody("job-a", "runner-a", "cache-lease-token", 5, "delivery-d",
		model.TestResult{Name: "t", Passed: true})
	var envelope struct {
		ContentDigest string `json:"content_digest"`
	}
	if err := json.Unmarshal([]byte(valid), &envelope); err != nil {
		t.Fatal(err)
	}
	badDigest := change(valid, envelope.ContentDigest, strings.Repeat("0", 64))
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", badDigest, hdrs); w.Code != http.StatusBadRequest {
		t.Fatalf("digest mismatch = %d, want 400", w.Code)
	}
	badID := change(valid, `"delivery-d"`, `"bad id!"`)
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", badID, hdrs); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid delivery id = %d, want 400", w.Code)
	}
	f.mu.Lock()
	reports := len(f.reports)
	f.mu.Unlock()
	if reports != 0 {
		t.Fatalf("validation failures wrote %d reports", reports)
	}
}

// TestTestReportDeliveryMemoryReplay proves the memory/fs fallback: there is
// no delivery table, so the delivery ID maps deterministically to the report
// ID and a replay is idempotent, while a reused ID with different content is
// a conflict.
func TestTestReportDeliveryMemoryReplay(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	path := "/api/v1/jobs/job-a/tests"
	body := deliveryReportBody("job-a", "runner-a", "cache-lease-token", 5, "delivery-mem",
		model.TestResult{Name: "m", Passed: true})

	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	firstID := ""
	s.mu.Lock()
	for id := range s.reports {
		firstID = id
	}
	s.mu.Unlock()
	w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("memory replay = %d, want 200: %s", w.Code, w.Body.String())
	}
	var out model.TestReport
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	n := len(s.reports)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("memory replay stored %d reports, want 1", n)
	}
	if out.ID != firstID {
		t.Fatalf("memory replay ID = %q, want the deterministic %q", out.ID, firstID)
	}

	conflict := deliveryReportBody("job-a", "runner-a", "cache-lease-token", 5, "delivery-mem",
		model.TestResult{Name: "m", Passed: false})
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", conflict, hdrs); w.Code != http.StatusConflict {
		t.Fatalf("memory conflict = %d, want 409", w.Code)
	}
}

// TestTestReportEndpointDecodeAndPayloadLimits is the C5-B endpoint half:
// the /tests decode cap is exactly the shared total-bytes budget (a body at
// the cap passes end-to-end, one byte over is refused), and an over-limit
// report payload that fits the byte cap is refused by the SAME
// testintel.ValidateReportPayload the runner calls.
func TestTestReportEndpointDecodeAndPayloadLimits(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	path := "/api/v1/jobs/job-a/tests"
	task := Task{Job: model.Job{ID: "job-a", RunID: "run-c", Key: "build"}, LeaseToken: "cache-lease-token", LeaseGeneration: 5}
	// Size the report payload to exactly the shared payload budget: its
	// request envelope is much smaller than the reserved allowance, so the
	// serialized body stays inside the shared request budget and the upload
	// must succeed end to end.
	basePayload := func() []byte {
		_, p := deliveryMemoryBody(task, "runner-a", "delivery-limit", 0, model.TestResult{Name: "sized", Passed: true})
		return p
	}()
	pad := testintel.MaxTestReportPayloadBytes - len(basePayload)
	if pad <= 0 {
		t.Fatalf("test premise broken: base payload is already %d bytes", len(basePayload))
	}
	bodyAt, payloadAt := deliveryMemoryBody(task, "runner-a", "delivery-limit", pad, model.TestResult{Name: "sized", Passed: true})
	if len(payloadAt) != testintel.MaxTestReportPayloadBytes {
		t.Fatalf("at-limit payload = %d bytes, want exactly %d", len(payloadAt), testintel.MaxTestReportPayloadBytes)
	}
	if len(bodyAt) > testintel.MaxTestReportRequestBytes {
		t.Fatalf("at-limit body = %d bytes, over the shared request budget %d", len(bodyAt), testintel.MaxTestReportRequestBytes)
	}
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", bodyAt, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("at-limit report = %d, want 201: %s", w.Code, w.Body.String())
	}

	// One byte over the shared PAYLOAD budget (the body still fits the
	// request cap): refused by the shared validator with the payload reason.
	bodyPayloadOver, _ := deliveryMemoryBody(task, "runner-a", "delivery-over", pad+1, model.TestResult{Name: "sized", Passed: true})
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", bodyPayloadOver, hdrs); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "payload budget") {
		t.Fatalf("over-budget payload = %d %q, want 400 payload-budget", w.Code, w.Body.String())
	}

	// A body over the shared request budget (a valid report padded past the
	// cap) is refused at decode before any report validation.
	bodyOver, _ := deliveryMemoryBody(task, "runner-a", "delivery-over-cap", pad+testintel.MaxTestReportEnvelopeBytes+1, model.TestResult{Name: "sized", Passed: true})
	if len(bodyOver) <= testintel.MaxTestReportRequestBytes {
		t.Fatalf("test premise broken: over body is %d bytes, not above the %d cap", len(bodyOver), testintel.MaxTestReportRequestBytes)
	}
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", bodyOver, hdrs); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "too large") {
		t.Fatalf("over-budget request = %d %q, want 400 body-too-large", w.Code, w.Body.String())
	}

	// Over-limit case count and message bytes are refused by the SHARED
	// validator with the same reason the runner sees.
	cases := make([]model.TestResult, testintel.MaxJobCases+1)
	for i := range cases {
		cases[i] = model.TestResult{Name: "t", Passed: true}
	}
	overCases := deliveryReportBody("job-a", "runner-a", "cache-lease-token", 5, "delivery-cases", cases...)
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", overCases, hdrs); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "case") {
		t.Fatalf("over-limit case count = %d %q, want 400 with the case reason", w.Code, w.Body.String())
	}
	overMsg := deliveryReportBody("job-a", "runner-a", "cache-lease-token", 5, "delivery-msg",
		model.TestResult{Name: "t", Passed: true, Message: strings.Repeat("x", testintel.MaxMessageBytes+1)})
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", overMsg, hdrs); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "message") {
		t.Fatalf("over-limit message = %d %q, want 400 with the message reason", w.Code, w.Body.String())
	}
}

// TestSummarizeTestIntelligenceKeepsSuiteIdentity reproduces the C5-C defect:
// two suites both contain class C name t. Suite "a" is flaky inside its own
// window; suite "b" is clean and its reports come LAST. Keying by class.name
// alone merged the windows and made the flaky test disappear; the structured
// (suite, class, name) key must keep the flaky window and still render the
// API's class.name once.
func TestSummarizeTestIntelligenceKeepsSuiteScopedOutcomes(t *testing.T) {
	base := time.Now().UTC()
	var reports []model.TestReport
	for i := 0; i < 16; i++ {
		reports = append(reports, model.TestReport{
			ID:        fmt.Sprintf("a%02d", i),
			JobKey:    "suite-a",
			CreatedAt: base.Add(time.Duration(i) * time.Second),
			Tests:     1,
			Cases:     []model.TestResult{{Name: "t", Class: "C", Passed: i%2 == 1}},
		})
	}
	for i := 0; i < 16; i++ {
		reports = append(reports, model.TestReport{
			ID:        fmt.Sprintf("b%02d", i),
			JobKey:    "suite-b",
			CreatedAt: base.Add(time.Minute).Add(time.Duration(i) * time.Second),
			Tests:     1,
			Cases:     []model.TestResult{{Name: "t", Class: "C", Passed: true}},
		})
	}
	out := summarizeTestIntelligence(reports)
	flaky, _ := out["flaky_tests"].([]string)
	if len(flaky) != 1 || flaky[0] != "C.t" {
		t.Fatalf("flaky = %v, want [C.t] (suite B's clean window must not erase suite A's flaky one)", flaky)
	}
	// A clean suite and a flaky suite with the SAME rendered name yield one
	// rendered entry, never a duplicate.
	if len(flaky) != 1 {
		t.Fatalf("rendered flaky names = %v, want a single deduplicated C.t", flaky)
	}
	// The inverse ordering is symmetric: a clean suite first, flaky second.
	flipped := summarizeTestIntelligence([]model.TestReport{reports[16], reports[0], reports[17], reports[1]})
	if got, _ := flipped["flaky_tests"].([]string); len(got) != 1 || got[0] != "C.t" {
		t.Fatalf("flipped flaky = %v, want [C.t]", got)
	}
}

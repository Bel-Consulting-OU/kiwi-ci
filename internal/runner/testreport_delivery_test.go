package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// TestBuildTestReportDeliveryStableAndBounded pins the runner-side delivery
// identity and the shared size pre-check: the same report under the same
// lease renders byte-identical body/digest/delivery ID, the lease generation
// and payload are part of the identity, and an over-limit report is refused
// before any upload with the shared ErrLimitExceeded reason.
func TestBuildTestReportDeliveryStableAndBounded(t *testing.T) {
	rep := model.TestReport{Tests: 2, Cases: []model.TestResult{
		{Name: "t", Class: "C", Duration: 1, Passed: true},
		{Name: "t", Class: "C", Duration: 2, Passed: false},
	}}
	first, err := buildTestReportDelivery("job-1", 7, "runner-1", "lease-token", rep)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	again, err := buildTestReportDelivery("job-1", 7, "runner-1", "lease-token", rep)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if first.DeliveryID != again.DeliveryID || first.Digest != again.Digest {
		t.Fatalf("delivery identity is not stable: %+v vs %+v", first, again)
	}
	if string(first.Body) != string(again.Body) {
		t.Fatal("retry body is not byte-identical")
	}
	if len(first.Body) > testintel.MaxTestReportRequestBytes {
		t.Fatalf("body = %d bytes, over the shared request budget", len(first.Body))
	}

	var wire struct {
		RunnerID      string          `json:"runner_id"`
		LeaseToken    string          `json:"lease_token"`
		Generation    int64           `json:"lease_generation"`
		DeliveryID    string          `json:"delivery_id"`
		ContentDigest string          `json:"content_digest"`
		Report        json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(first.Body, &wire); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if wire.DeliveryID != first.DeliveryID || wire.ContentDigest != first.Digest || wire.RunnerID != "runner-1" || wire.LeaseToken != "lease-token" || wire.Generation != 7 {
		t.Fatalf("wire identity = %+v, want the computed delivery identity and lease", wire)
	}
	if got := testintel.ReportContentDigest(wire.Report); got != first.Digest {
		t.Fatalf("payload digest = %s, want the advertised %s", got, first.Digest)
	}
	wantID := testintel.ReportDeliveryID("job-1", 7, first.Digest)
	if first.DeliveryID != wantID {
		t.Fatalf("delivery ID = %s, want sha256(job, generation, digest) = %s", first.DeliveryID, wantID)
	}
	// The identity binds the lease generation and the payload.
	nextGen, err := buildTestReportDelivery("job-1", 8, "runner-1", "lease-token", rep)
	if err != nil || nextGen.DeliveryID == first.DeliveryID {
		t.Fatalf("generation is not part of the delivery ID: %+v err=%v", nextGen, err)
	}
	changed := rep
	changed.Cases = append([]model.TestResult(nil), rep.Cases...)
	changed.Cases[0].Passed = false
	changedRep, err := buildTestReportDelivery("job-1", 7, "runner-1", "lease-token", changed)
	if err != nil || changedRep.DeliveryID == first.DeliveryID {
		t.Fatalf("payload is not part of the delivery ID: %+v err=%v", changedRep, err)
	}

	// The shared validator refuses over-limit payloads before any request.
	over := model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Passed: true, Message: strings.Repeat("x", testintel.MaxMessageBytes+1)}}}
	if _, err := buildTestReportDelivery("job-1", 7, "runner-1", "lease-token", over); !errors.Is(err, testintel.ErrLimitExceeded) || !strings.Contains(err.Error(), "message") {
		t.Fatalf("over-limit message err = %v, want ErrLimitExceeded message reason", err)
	}
	cases := make([]model.TestResult, testintel.MaxJobCases+1)
	for i := range cases {
		cases[i] = model.TestResult{Name: "t", Passed: true}
	}
	if _, err := buildTestReportDelivery("job-1", 7, "runner-1", "lease-token", model.TestReport{Tests: len(cases), Cases: cases}); !errors.Is(err, testintel.ErrLimitExceeded) || !strings.Contains(err.Error(), "case") {
		t.Fatalf("over-limit case err = %v, want ErrLimitExceeded case reason", err)
	}
}

// droppedReportControlPlane is the scripted response-dropping endpoint for the
// report upload: the first delivery of each (job, generation, delivery ID)
// commits to a receipt store and then kills the connection without a
// response; an identical replay is acknowledged idempotently; a reused ID
// with a different digest is a 409.
type droppedReportControlPlane struct {
	mu       sync.Mutex
	attempts []reportDeliveryAttempt
	receipts map[string]string
}

type reportDeliveryAttempt struct {
	JobID      string
	RunnerID   string
	Token      string
	Generation int64
	DeliveryID string
	Digest     string
	Status     int
}

func newDroppedReportControlPlane() *droppedReportControlPlane {
	return &droppedReportControlPlane{receipts: map[string]string{}}
}

func (s *droppedReportControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !(r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests")) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	jobID := jobIDFromPath(r.URL.Path)
	body, _ := io.ReadAll(r.Body)
	var env struct {
		RunnerID      string          `json:"runner_id"`
		LeaseToken    string          `json:"lease_token"`
		Generation    int64           `json:"lease_generation"`
		DeliveryID    string          `json:"delivery_id"`
		ContentDigest string          `json:"content_digest"`
		Report        json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The advertised digest must cover the exact payload bytes on the wire;
	// the real server recomputes and verifies this.
	if got := testintel.ReportContentDigest(env.Report); got != env.ContentDigest {
		http.Error(w, "content digest mismatch", http.StatusBadRequest)
		return
	}
	key := jobID + "\x00" + env.DeliveryID
	s.mu.Lock()
	s.attempts = append(s.attempts, reportDeliveryAttempt{
		JobID: jobID, RunnerID: env.RunnerID, Token: env.LeaseToken, Generation: env.Generation,
		DeliveryID: env.DeliveryID, Digest: env.ContentDigest,
	})
	if digest, ok := s.receipts[key]; ok {
		status := http.StatusOK
		if digest != env.ContentDigest {
			status = http.StatusConflict
		}
		if n := len(s.attempts); n > 0 {
			s.attempts[n-1].Status = status
		}
		s.mu.Unlock()
		w.WriteHeader(status)
		return
	}
	s.receipts[key] = env.ContentDigest
	if n := len(s.attempts); n > 0 {
		s.attempts[n-1].Status = http.StatusCreated
	}
	s.mu.Unlock()
	// The receipt above is durable; the acknowledgement is not.
	dropResponseWithoutWriting(w)
}

func (s *droppedReportControlPlane) snapshot() []reportDeliveryAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]reportDeliveryAttempt(nil), s.attempts...)
}

// TestExecuteTestReportDroppedResponseRetriesSameDeliveryID is the C5-A
// runner proof: the control plane commits the report and drops the response,
// and the runner's bounded redelivery must resend the IDENTICAL delivery ID
// and digest. The job still completes successfully with no upload warning,
// and exactly one delivery identity was ever created.
func TestExecuteTestReportDroppedResponseRetriesSameDeliveryID(t *testing.T) {
	cp := newDroppedReportControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	text := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
	payload := payloadWithEffectiveJob(t, text, "build", func(cj *pipeline.CompiledJob) {
		cj.Job.TestReports = []string{"report.xml"}
	})
	task := basicTask(text)
	task.Job.CompiledJobPayload = payload
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "report.xml"), []byte(testReportLeakXML), 0o644)
	}
	r.execute(context.Background(), task)

	attempts := cp.snapshot()
	if len(attempts) < 2 {
		t.Fatalf("dropped report response was sent %d time(s), want a retry with the same identity", len(attempts))
	}
	first := attempts[0]
	if first.Status != http.StatusCreated {
		t.Fatalf("first attempt status = %d, want 201 (committed before the drop)", first.Status)
	}
	if first.DeliveryID == "" || first.Digest == "" {
		t.Fatalf("first attempt lost the delivery identity: %+v", first)
	}
	if attempts[1].Status != http.StatusOK {
		t.Fatalf("retry status = %d, want the idempotent 200", attempts[1].Status)
	}
	for i, a := range attempts {
		if a.DeliveryID != first.DeliveryID || a.Digest != first.Digest {
			t.Fatalf("attempt %d changed the delivery identity: %+v vs %+v", i, a, first)
		}
		if a.Generation != 3 || a.RunnerID != "runner-1" || a.Token != "lease-token" {
			t.Fatalf("attempt %d carried the wrong lease identity: %+v", i, a)
		}
	}
	if n := len(cp.receipts); n != 1 {
		t.Fatalf("receipt store holds %d deliveries, want exactly 1", n)
	}
}

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestAsyncLogSinkNeverBlocksProducerAndFlushesAll proves the decoupling:
// a slow control plane cannot stall the pipe-side producer, and Flush
// delivers every line before completion.
func TestAsyncLogSinkNeverBlocksProducerAndFlushesAll(t *testing.T) {
	var delivered atomic.Int64
	var mu sync.Mutex
	seen := map[string]bool{}
	sink := newLogSink(nil, func(_ context.Context, batch logBatch) error {
		time.Sleep(5 * time.Millisecond) // slow endpoint
		mu.Lock()
		for _, l := range batch.Lines {
			seen[l.Line] = true
		}
		mu.Unlock()
		delivered.Add(int64(len(batch.Lines)))
		return nil
	}, nil)
	const total = 4000
	start := time.Now()
	for i := 0; i < total; i++ {
		sink.WriteLine("job", "step", fmt.Sprintf("line-%d", i))
	}
	enqueue := time.Since(start)
	if enqueue > 2*time.Second {
		t.Fatalf("producer blocked on a slow endpoint: enqueueing %d lines took %v", total, enqueue)
	}
	if remaining := sink.Flush(30 * time.Second); remaining != 0 {
		t.Fatalf("flush left %d unsent lines", remaining)
	}
	sink.Finish(time.Second)
	if delivered.Load() != total {
		t.Fatalf("delivered = %d, want %d", delivered.Load(), total)
	}
	if sink.dropped.Load() != 0 {
		t.Fatalf("dropped = %d, want 0", sink.dropped.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < total; i++ {
		if !seen[fmt.Sprintf("line-%d", i)] {
			t.Fatalf("line %d never delivered", i)
		}
	}
}

// TestAsyncLogSinkOverflowIsCounted proves overflow is explicit: when the
// bounded spool fills because delivery is stalled, the excess is counted
// (surfaced as a failed job by the caller) instead of blocking the drain
// forever or vanishing silently.
func TestAsyncLogSinkOverflowIsCounted(t *testing.T) {
	oldLimit := asyncSpoolLimit
	asyncSpoolLimit = 16
	t.Cleanup(func() { asyncSpoolLimit = oldLimit })

	release := make(chan struct{})
	sink := newLogSink(nil, func(context.Context, logBatch) error {
		<-release // stall delivery entirely
		return nil
	}, nil)
	for i := 0; i < 100; i++ {
		sink.WriteLine("job", "step", fmt.Sprintf("line-%d", i))
	}
	// The producer must not have blocked; overflow is counted, not queued.
	if got := sink.dropped.Load(); got == 0 {
		t.Fatal("overflow was not counted")
	}
	close(release)
	sink.Finish(2 * time.Second)
}

// TestAsyncLogSinkSendErrorReported proves a background delivery failure is
// surfaced (the caller fails the job) rather than swallowed.
func TestAsyncLogSinkSendErrorReported(t *testing.T) {
	// A PERMANENT (4xx-class) failure is surfaced immediately; transient
	// failures retry with backoff first.
	sink := newLogSink(nil, func(context.Context, logBatch) error {
		return PermanentDeliveryError(fmt.Errorf("control plane down"))
	}, nil)
	sink.WriteLine("job", "step", "x")
	out := sink.Finish(2 * time.Second)
	if out.Err == nil {
		t.Fatal("send error not reported")
	}
	if out.Remaining != 0 {
		t.Fatalf("remaining = %d, want 0", out.Remaining)
	}
	if !out.Stopped {
		t.Fatal("sender did not stop within the deadline")
	}
}

// TestAsyncLogSinkByteBudgetBoundsMemory proves the spool is bounded in
// BYTES, not just line count: with a tiny byte budget a handful of large
// lines must overflow and be counted instead of retaining ~100 GiB.
func TestAsyncLogSinkByteBudgetBoundsMemory(t *testing.T) {
	oldBytes, oldLines := asyncSpoolBytes, asyncSpoolLimit
	asyncSpoolBytes, asyncSpoolLimit = 4<<10, 1_000_000
	t.Cleanup(func() { asyncSpoolBytes, asyncSpoolLimit = oldBytes, oldLines })

	release := make(chan struct{})
	sink := newLogSink(nil, func(context.Context, logBatch) error {
		<-release
		return nil
	}, nil)
	big := string(make([]byte, 1024)) // 1 KiB line
	for i := 0; i < 50; i++ {
		sink.WriteLine("job", "step", big)
	}
	if got := sink.dropped.Load(); got == 0 {
		t.Fatal("byte budget did not bound the spool")
	}
	close(release)
	out := sink.Finish(3 * time.Second)
	if out.Err != nil {
		t.Fatalf("unexpected sender error: %v", out.Err)
	}
}

// TestAsyncLogSinkInFlightCountsTowardFlush proves Flush does not report
// success while the final batch is still in flight and failing.
func TestAsyncLogSinkInFlightCountsTowardFlush(t *testing.T) {
	proceed := make(chan struct{})
	var calls atomic.Int64
	sink := newLogSink(nil, func(context.Context, logBatch) error {
		calls.Add(1)
		<-proceed // hold the batch in flight
		return fmt.Errorf("delivery down")
	}, nil)
	sink.WriteLine("job", "step", "line-1")
	// Wait until the sender has taken the batch (in flight).
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("sender never picked up the batch")
	}
	// Flush with a short deadline must NOT claim success while in flight.
	if pending := sink.Flush(20 * time.Millisecond); pending == 0 {
		t.Fatal("flush reported success while a batch was still in flight")
	}
	close(proceed)
	out := sink.Finish(3 * time.Second)
	if out.Err == nil {
		t.Fatal("in-flight failure was not surfaced after the sender stopped")
	}
}

// TestAsyncLogSinkRetriesTransientFailures proves a retryable delivery
// failure is retried (with the batch retained) and a later success clears
// the error — the batch is not discarded on the first failure.
func TestAsyncLogSinkRetriesTransientFailures(t *testing.T) {
	var attempts atomic.Int64
	delivered := make(chan int, 4)
	sink := newLogSink(nil, func(_ context.Context, batch logBatch) error {
		n := attempts.Add(1)
		if n < 3 {
			return fmt.Errorf("transient 503")
		}
		delivered <- len(batch.Lines)
		return nil
	}, nil)
	sink.WriteLine("job", "step", "line-1")
	out := sink.Finish(15 * time.Second)
	select {
	case n := <-delivered:
		if n != 1 {
			t.Fatalf("delivered %d lines, want 1", n)
		}
	default:
		t.Fatal("batch was never delivered after retries")
	}
	if attempts.Load() < 3 {
		t.Fatalf("attempts = %d, want retries before success", attempts.Load())
	}
	if out.Err != nil {
		t.Fatalf("retry success must clear the error: %v", out.Err)
	}
}

// waitUntil polls cond until it holds or the timeout expires.
func waitUntil(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// batchReceiptServer mimics the control plane's /log/batch receipt. The
// FIRST request carrying a batch_id commits the lines to the store but is
// answered 503 anyway (the runner never sees the acknowledgement, i.e. the
// response is dropped); later requests for the same batch_id are answered
// 204 without committing again. Every request is recorded with its batch_id
// and batch_sequence so the test can prove the retries reused one identity.
type batchReceiptServer struct {
	mu      sync.Mutex
	records []batchReceipt
	store   map[string][]string
}

type batchReceipt struct {
	ID       string `json:"batch_id"`
	Sequence int64  `json:"batch_sequence"`
}

func newBatchReceiptServer() *batchReceiptServer {
	return &batchReceiptServer{store: map[string][]string{}}
}

func (s *batchReceiptServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BatchID       string           `json:"batch_id"`
		BatchSequence int64            `json:"batch_sequence"`
		Lines         []server.LogLine `json:"lines"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	s.records = append(s.records, batchReceipt{ID: body.BatchID, Sequence: body.BatchSequence})
	first := false
	if _, ok := s.store[body.BatchID]; !ok {
		first = true
		for _, l := range body.Lines {
			s.store[body.BatchID] = append(s.store[body.BatchID], l.Step+": "+l.Line)
		}
	}
	s.mu.Unlock()
	if first {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *batchReceiptServer) snapshot() ([]batchReceipt, map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := append([]batchReceipt(nil), s.records...)
	store := map[string][]string{}
	for id, lines := range s.store {
		store[id] = append([]string(nil), lines...)
	}
	return records, store
}

// TestLogBatchRetryReusesImmutableIdentity is the R-A regression: the batch
// identity is assigned exactly once before the first send, so a retried
// batch carries the identical batch_id and sequence, and the server-side
// receipt store holds exactly one copy of the lines. Two batches with the
// SAME payload still get distinct identities because the sequence differs.
func TestLogBatchRetryReusesImmutableIdentity(t *testing.T) {
	rsrv := newBatchReceiptServer()
	ts := httptest.NewServer(rsrv)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	sink := newLogSink(nil, r.logBatchPost(basicTask(payloadPipeline), &secrets.Masker{}), nil)

	sink.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "the first batch retry", func() bool {
		records, _ := rsrv.snapshot()
		return len(records) >= 2
	})
	// Identical payload in a NEW batch: the sink's sequence must still make
	// the identity unique.
	sink.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "the second batch commit", func() bool {
		_, store := rsrv.snapshot()
		return len(store) >= 2
	})

	out := sink.Finish(15 * time.Second)
	if out.Err != nil || out.Dropped != 0 || out.Remaining != 0 || !out.Stopped {
		t.Fatalf("delivery outcome = %+v, want a clean stop", out)
	}

	records, store := rsrv.snapshot()
	if len(records) < 4 {
		t.Fatalf("attempts = %d, want two attempts for each of two batches", len(records))
	}
	attempts := map[string]int{}
	sequences := map[string]int64{}
	for _, rec := range records {
		if rec.ID == "" {
			t.Fatal("a batch attempt carried an empty batch_id")
		}
		attempts[rec.ID]++
		if prev, ok := sequences[rec.ID]; ok && prev != rec.Sequence {
			t.Fatalf("batch %q was retried with sequence %d after %d", rec.ID, rec.Sequence, prev)
		}
		sequences[rec.ID] = rec.Sequence
	}
	if len(attempts) != 2 {
		t.Fatalf("server saw %d distinct batch ids, want 2: %v", len(attempts), attempts)
	}
	if len(store) != 2 {
		t.Fatalf("server store holds %d committed batches, want 2: %v", len(store), store)
	}
	for id, n := range attempts {
		if n < 2 {
			t.Fatalf("batch %q was sent %d time(s); the retry path was not exercised", id, n)
		}
		got := store[id]
		if len(got) != 1 || got[0] != "step: line-1" {
			t.Fatalf("store[%q] = %v, want exactly one copy of the line", id, got)
		}
	}
	if sequencesOfRecordedBatches := len(sequences); sequencesOfRecordedBatches != 2 {
		t.Fatalf("distinct sequences = %d, want 2", sequencesOfRecordedBatches)
	}
}

// TestLogBatchPostAbortsInflightOnFinish is the R-B regression: the delivery
// callback posts on the ctx the sink hands it, so Finish's cancellation
// aborts the in-flight HTTP request and the sender goroutine terminates
// instead of leaking on a hanging endpoint.
func TestLogBatchPostAbortsInflightOnFinish(t *testing.T) {
	entered := make(chan struct{})
	ctxCanceled := make(chan struct{})
	var enteredOnce, canceledOnce sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain the body: only then does net/http start the background read
		// that notices the client aborting the request.
		_, _ = io.Copy(io.Discard, r.Body)
		enteredOnce.Do(func() { close(entered) })
		<-r.Context().Done() // hang until the request context is canceled
		canceledOnce.Do(func() { close(ctxCanceled) })
	}))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	sink := newLogSink(nil, r.logBatchPost(basicTask(payloadPipeline), &secrets.Masker{}), nil)
	sink.WriteLine("build", "step", "line-1")

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never reached the hanging endpoint")
	}

	out := sink.Finish(300 * time.Millisecond)

	select {
	case <-ctxCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("Finish did not cancel the in-flight request context")
	}
	select {
	case <-sink.done:
	case <-time.After(5 * time.Second):
		t.Fatal("sender goroutine leaked after cancellation")
	}
	if out.Stopped {
		t.Fatal("Finish must report the deadline-expired sender, not a clean stop")
	}
}

// TestLogSpoolAccountingMatchesStoredCosts is the R-C regression: the
// tracked spool bytes must always equal the sum of the costs stored at
// enqueue (never the JSON-encoded size, which escaping inflates), stay
// inside the configured budget, and return exactly to zero once every batch
// drained.
func TestLogSpoolAccountingMatchesStoredCosts(t *testing.T) {
	oldBytes, oldLines := asyncSpoolBytes, asyncSpoolLimit
	asyncSpoolBytes, asyncSpoolLimit = 300_000, 1_000_000
	t.Cleanup(func() { asyncSpoolBytes, asyncSpoolLimit = oldBytes, oldLines })

	// Each post blocks until the test releases it, so every intermediate
	// state is frozen and observable (no timing race).
	started := make(chan struct{}, 16)
	release := make(chan struct{}, 16)
	sink := newLogSink(nil, func(context.Context, logBatch) error {
		started <- struct{}{}
		<-release
		return nil
	}, nil)

	// Escape-heavy line: every raw byte expands under JSON encoding (quotes,
	// backslashes, newlines, tabs, CR, and <&> become \uXXXX), so the
	// encoded size used for HTTP packing is far larger than the stored spool
	// cost. That difference is exactly what made the old decrement drift.
	line := strings.Repeat("\"<&>\\\n\t\r", 6000)

	check := func(where string) {
		sink.mu.Lock()
		tracked, spoolLen := sink.spoolBytes, len(sink.spool)
		var stored int64
		for _, l := range sink.spool {
			stored += l.spoolCost
		}
		sink.mu.Unlock()
		if tracked < 0 {
			t.Fatalf("%s: tracked spool bytes went negative: %d", where, tracked)
		}
		if tracked > asyncSpoolBytes {
			t.Fatalf("%s: tracked spool bytes %d exceed the budget %d", where, tracked, asyncSpoolBytes)
		}
		if tracked != stored {
			t.Fatalf("%s: tracked spool bytes = %d, but %d buffered lines store %d bytes (accounting drift)", where, tracked, spoolLen, stored)
		}
	}

	waitStarted := func(what string) {
		t.Helper()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %s", what)
		}
	}

	check("initial")
	// One line in flight, the spool empty.
	sink.WriteLine("build", "step", line+"0")
	waitStarted("the first batch to be sent")
	// Five more lines buffered behind the blocked sender.
	const buffered = 5
	for i := 1; i <= buffered; i++ {
		sink.WriteLine("build", "step", line+strconv.Itoa(i))
	}
	check("with five lines buffered")
	if got := sink.dropped.Load(); got != 0 {
		t.Fatalf("dropped = %d, want 0 (all lines fit the budget)", got)
	}
	// Let the first batch through: the sender dequeues the next batch (one
	// line, the encoded budget admits only one of these) and blocks again.
	// The tracked bytes MUST now equal the cost of the four remaining lines.
	release <- struct{}{}
	waitStarted("the second batch to be sent")
	check("after a batch drained")
	// Drain everything that is left.
	for i := 0; i < buffered+2; i++ {
		release <- struct{}{}
	}
	if pending := sink.Flush(10 * time.Second); pending != 0 {
		t.Fatalf("flush left %d pending", pending)
	}
	check("after drain")
	out := sink.Finish(5 * time.Second)
	if out.Err != nil {
		t.Fatalf("delivery error: %v", out.Err)
	}
	sink.mu.Lock()
	tracked := sink.spoolBytes
	sink.mu.Unlock()
	if tracked != 0 {
		t.Fatalf("tracked spool bytes = %d after draining everything, want exactly 0", tracked)
	}
}

// TestLogSpoolEncodeFailureFailsJobWithoutPartialBatch is the H2-B
// regression: the spool sizing loop used to discard the json.Marshal error
// (`encoded, _ :=`). An entry encoding/json rejects must stop the sender with
// the wrapped error surfaced on the job outcome, while the spool, its byte
// accounting and the shared memory budget stay exactly as they were: no
// partial or corrupt batch is formed, removed or sent.
func TestLogSpoolEncodeFailureFailsJobWithoutPartialBatch(t *testing.T) {
	oldEncode := encodeSpoolEntry
	t.Cleanup(func() { encodeSpoolEntry = oldEncode })

	// A genuinely non-marshallable value: encoding/json rejects it, and the
	// production call site sees exactly this error shape.
	bad := make(chan int)
	//lint:ignore SA1026 the non-marshallable value is the behavior under test
	if _, err := json.Marshal(bad); err == nil {
		t.Fatal("chan int unexpectedly marshals")
	}
	encodeSpoolEntry = func(any) ([]byte, error) {
		//lint:ignore SA1026 the non-marshallable value is the behavior under test
		return json.Marshal(bad)
	}

	var posted atomic.Int64
	sink := newLogSink(nil, func(context.Context, logBatch) error {
		posted.Add(1)
		return nil
	}, nil)
	sink.WriteLine("build", "step", "line-1")

	sink.mu.Lock()
	spooled, tracked := len(sink.spool), sink.spoolBytes
	var stored int64
	for _, l := range sink.spool {
		stored += l.spoolCost
	}
	sink.mu.Unlock()
	if spooled != 1 || tracked == 0 || tracked != stored {
		t.Fatalf("precondition: spool=%d tracked=%d stored=%d", spooled, tracked, stored)
	}

	out := sink.Finish(5 * time.Second)
	if out.Err == nil {
		t.Fatal("encoding failure did not surface on the job outcome")
	}
	if msg := out.Err.Error(); !strings.Contains(msg, "log sink: encode spool entry 0") ||
		!strings.Contains(msg, "unsupported type: chan int") {
		t.Fatalf("error = %v, want the wrapped encoding failure", out.Err)
	}
	if posted.Load() != 0 {
		t.Fatalf("posted %d batches, want none (no partial batch)", posted.Load())
	}
	if out.Remaining != 1 {
		t.Fatalf("remaining = %d, want the undelivered line reported", out.Remaining)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.spool) != 1 || sink.spool[0].Line != "line-1" {
		t.Fatalf("spool after failure = %+v, want the original line retained", sink.spool)
	}
	if sink.spoolBytes != stored {
		t.Fatalf("tracked spool bytes = %d after failure, want %d (accounting drift)", sink.spoolBytes, stored)
	}
	if charged := sink.mem.load(); charged != stored {
		t.Fatalf("shared memory budget = %d after failure, want %d (charge not kept)", charged, stored)
	}
	if sink.dropped.Load() != 0 {
		t.Fatalf("dropped = %d, want 0 (the line is retained, not dropped)", sink.dropped.Load())
	}
}

// TestLogDeliveryHTTPStatusClassification is the R-D regression: the
// callback classifies delivery failures from the typed HTTP status, not
// from parsing the error string. 400/401/403/404/409/422 are permanent
// (exactly one attempt, the failure is surfaced); 408/429/500/502/503/504
// are retryable (the retry succeeds against a server that answers 204 the
// second time).
func TestLogDeliveryHTTPStatusClassification(t *testing.T) {
	cases := []struct {
		code      int
		permanent bool
	}{
		{http.StatusBadRequest, true},
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusNotFound, true},
		{http.StatusConflict, true},
		{http.StatusUnprocessableEntity, true},
		{http.StatusRequestTimeout, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, false},
		{http.StatusGatewayTimeout, false},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.code), func(t *testing.T) {
			if got := permanentHTTPStatus(tc.code); got != tc.permanent {
				t.Fatalf("permanentHTTPStatus(%d) = %v, want %v", tc.code, got, tc.permanent)
			}
			var attempts atomic.Int64
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) == 1 {
					w.WriteHeader(tc.code)
					_, _ = w.Write([]byte("classified"))
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer ts.Close()
			r := testRunnerFor(t, ts, Config{})
			sink := newLogSink(nil, r.logBatchPost(basicTask(payloadPipeline), &secrets.Masker{}), nil)
			sink.WriteLine("build", "step", "line-1")
			out := sink.Finish(10 * time.Second)
			if tc.permanent {
				if got := attempts.Load(); got != 1 {
					t.Fatalf("permanent %d delivery was retried %d times", tc.code, got)
				}
				var httpErr *HTTPStatusError
				if !errors.As(out.Err, &httpErr) || httpErr.StatusCode != tc.code {
					t.Fatalf("permanent %d error = %v, want a typed HTTPStatusError", tc.code, out.Err)
				}
			} else {
				if got := attempts.Load(); got < 2 {
					t.Fatalf("retryable %d delivery made %d attempt(s), want a retry", tc.code, got)
				}
				if out.Err != nil {
					t.Fatalf("retryable %d delivery failed after a successful retry: %v", tc.code, out.Err)
				}
			}
		})
	}
}

// TestPostReturnsTypedHTTPStatusError proves r.post surfaces non-2xx
// responses as *HTTPStatusError (status + body), and isHTTPStatus classifies
// by type.
func TestPostReturnsTypedHTTPStatusError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("stale lease"))
	}))
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	err := r.post(context.Background(), "/api/v1/x", map[string]any{}, nil)
	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("post error = %T %v, want *HTTPStatusError", err, err)
	}
	if httpErr.StatusCode != http.StatusConflict || httpErr.Body != "stale lease" {
		t.Fatalf("HTTPStatusError = %+v", httpErr)
	}
	if !isHTTPStatus(err, http.StatusConflict) || isHTTPStatus(err, http.StatusBadRequest) {
		t.Fatalf("isHTTPStatus misclassified: %v", err)
	}
	if !permanentHTTPStatus(httpErr.StatusCode) {
		t.Fatal("409 must classify as permanent")
	}
}

// --- FB-3: unified in-memory budget ----------------------------------------

// TestLogSinkSharedMemoryBudgetSpansSpoolAndJournal proves the spool AND the
// journal-resident backlog are charged against the SAME documented bound: a
// blocked delivery journals its batch (resident bytes), and the spool only
// accepts what remains of the budget. Excess is counted as dropped and
// surfaced, never silently lost, and the charged sum never exceeds the bound.
func TestLogSinkSharedMemoryBudgetSpansSpoolAndJournal(t *testing.T) {
	oldBytes := asyncSpoolBytes
	asyncSpoolBytes = 4096
	t.Cleanup(func() { asyncSpoolBytes = oldBytes })

	j := openTestJournal(t, t.TempDir(), "job-1", 3)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var delivered atomic.Int64
	sink := newJournaledAsyncLogSink(nil, func(_ context.Context, batch logBatch) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		delivered.Add(int64(len(batch.Lines)))
		return nil
	}, j)

	line := strings.Repeat("y", 1024)
	sink.WriteLine("build", "step", line+"0")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first batch never reached the post callback")
	}
	if resident := j.residentBytes(); resident <= 0 {
		t.Fatalf("journal-resident bytes = %d, want the blocked batch charged", resident)
	}
	const total = 50
	for i := 1; i < total; i++ {
		sink.WriteLine("build", "step", line+strconv.Itoa(i))
	}
	if sink.dropped.Load() == 0 {
		t.Fatal("the shared budget was not enforced: the journal backlog did not shrink the spool capacity")
	}
	sink.mu.Lock()
	spooled := sink.spoolBytes
	sink.mu.Unlock()
	if resident := j.residentBytes(); spooled+resident > asyncSpoolBytes {
		t.Fatalf("resident bytes = %d spool + %d journal, over the %d byte bound", spooled, resident, asyncSpoolBytes)
	}
	close(release)
	out := sink.Finish(10 * time.Second)
	if out.Err != nil {
		t.Fatalf("delivery error after release: %v", out.Err)
	}
	if out.Remaining != 0 {
		t.Fatalf("remaining = %d after release, want 0", out.Remaining)
	}
	if got := delivered.Load() + out.Dropped; got != total {
		t.Fatalf("delivered(%d) + dropped(%d) = %d, want %d (no silent loss)", delivered.Load(), out.Dropped, got, total)
	}
}

// TestLogSinkJournalMemoryOverflowFailsExplicitly proves a batch whose
// durable record cannot fit the shared memory budget is never posted and
// never silently dropped: the job fails explicitly and the line stays in the
// spool (Remaining), with no record left behind.
func TestLogSinkJournalMemoryOverflowFailsExplicitly(t *testing.T) {
	line := strings.Repeat("z", 1024)
	// Room for the line's spool cost but not for its serialized record
	// (identity fields + escaping overhead), so the spool accepts the line
	// and the journal append fails explicitly.
	oldBytes := asyncSpoolBytes
	asyncSpoolBytes = int64(len("build")+len("step")+len(line)) + 1
	t.Cleanup(func() { asyncSpoolBytes = oldBytes })

	j := openTestJournal(t, t.TempDir(), "job-1", 3)
	var attempts atomic.Int64
	sink := newJournaledAsyncLogSink(nil, func(context.Context, logBatch) error {
		attempts.Add(1)
		return nil
	}, j)
	sink.WriteLine("build", "step", line)
	out := sink.Finish(5 * time.Second)
	if out.Err == nil || !strings.Contains(out.Err.Error(), "memory budget") {
		t.Fatalf("outcome error = %v, want an explicit journal memory budget error", out.Err)
	}
	if attempts.Load() != 0 {
		t.Fatalf("an unjournaled batch was posted %d time(s)", attempts.Load())
	}
	if out.Dropped != 0 {
		t.Fatalf("journal memory overflow dropped lines: %+v", out)
	}
	if out.Remaining == 0 {
		t.Fatalf("the line was neither delivered nor retained: %+v", out)
	}
	if got := j.pendingBatches(); len(got) != 0 {
		t.Fatalf("the failed append left a durable record: %+v", got)
	}
}

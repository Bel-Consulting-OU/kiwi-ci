package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
)

// asyncLogSink decouples pipe draining from network delivery.
//
// Pipe readers must never block on a slow control plane: a blocked emit
// stalls the drain, and once the post-reap grace expires the remaining tail
// output would be lost silently. Instead every line lands in a bounded
// in-memory spool that a dedicated sender goroutine drains into batched
// HTTP posts; the pipes only ever block when the spool itself is full.
//
// Overflow is never silent: the sink counts dropped lines, reports them on
// the job's completion error, and emits a final marker so a build can never
// be reported green while its logs were lost.
type asyncLogSink struct {
	inner logging.Sink
	post  func(ctx context.Context, batch logBatch) error

	// ctx is cancelled by Finish at its deadline, aborting any in-flight
	// delivery instead of letting it run on the job's parent context. The
	// post callback receives exactly this ctx.
	ctx    context.Context
	cancel context.CancelFunc

	// journal is the durable per-(job, generation) batch journal. When set,
	// every batch is journaled before its first POST attempt, acked only
	// after a confirmed delivery, and unconsumed records are replayed with
	// their original identities before any new batch is formed. nil means
	// no durable state directory is configured.
	journal *logJournal
	// pending holds the unconsumed journal records the sender must replay
	// first, in sequence order. Guarded by the sender goroutine: only
	// newLogSink and run touch it.
	pending []logBatch
	// mem is the shared in-memory byte budget. A journaled sink adopts the
	// journal's budget so the spool AND the journal-resident pending records
	// are charged against the documented asyncSpoolBytes bound; a
	// journal-less sink gets its own.
	mem *logMemBudget

	// batchSeq assigns every batch its immutable sequence when the sink
	// forms the batch — once, before the first send — so retries of that
	// batch reuse the same sequence and identity. A journaled sink starts
	// it after the persisted maximum so a restart never regresses the
	// sequence.
	batchSeq atomic.Int64

	mu         sync.Mutex
	spool      []logLine
	spoolBytes int64
	inFlight   int
	closed     bool
	cond       *sync.Cond

	dropped atomic.Int64

	// First delivery error, guarded by mu. A plain error field (not
	// atomic.Value) is deliberate: storing heterogeneous error types in an
	// atomic.Value panics, which would take down the runner from its own
	// logging goroutine.
	sendErr       error
	senderStopped bool

	done chan struct{}
}

// logOutcome is the sender's final state at job end.
type logOutcome struct {
	Dropped   int64
	Remaining int
	Err       error
	// Stopped is false when the bounded close deadline expired with the
	// sender still running (a slow in-flight request); the job still fails
	// explicitly via Remaining/Err.
	Stopped bool
}

type logLine struct {
	Job  string
	Step string
	Line string
	// spoolCost is this line's accounting cost, computed exactly ONCE at
	// enqueue. The spool budget check and the drain decrement both use this
	// stored value, so the tracked byte count can never drift from the
	// buffered payload. The JSON-ENCODED size is a different quantity,
	// computed separately and used solely for HTTP batch packing (escaping
	// can multiply it).
	spoolCost int64
}

// logBatch is an immutable unit of delivery. Its identity (Sequence and ID)
// is assigned exactly once when the sink forms the batch and every retry
// re-sends the identical values, so the control plane's (job, generation,
// batch_id) receipt can dedupe a retried delivery.
type logBatch struct {
	Sequence int64
	ID       string
	Lines    []logLine
}

// logBatchID derives a batch's deterministic identity from the sequence
// assigned by the sink and the batch payload: the sequence distinguishes
// identical payloads in different batches, the payload binds the identity to
// the bytes.
func logBatchID(sequence int64, lines []logLine) string {
	h := sha256.New()
	h.Write([]byte(strconv.FormatInt(sequence, 10)))
	h.Write([]byte{0})
	for _, l := range lines {
		h.Write([]byte(l.Job))
		h.Write([]byte{0})
		h.Write([]byte(l.Step))
		h.Write([]byte{0})
		h.Write([]byte(l.Line))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// asyncSpoolLimit bounds the in-memory spool; at 64 bytes per line average
// this is a few MiB, far below the memory a stalled sender could otherwise
// accumulate over a long step.
// The spool is bounded in BOTH lines and bytes: a line can be up to ~1 MiB,
// so a line-only cap would allow ~100 GiB of retained payload. The byte
// budget is the binding constraint in practice.
var (
	asyncSpoolLimit = 100_000
	asyncSpoolBytes = int64(32 << 20)
)

// asyncPostBytes bounds one batched request; asyncPostBatch bounds its line
// count. Both feed the server's /log/batch limits (1 MiB, 2000 lines).
const (
	asyncPostBytes = 256 << 10
	asyncPostBatch = 200
)

// newJournaledAsyncLogSink builds a sink whose batches are durable before
// they are sent. The journal's unconsumed records are loaded at construction
// and replayed, with their original batch ids and sequences, before the sink
// forms any new batch.
func newJournaledAsyncLogSink(inner logging.Sink, post func(context.Context, logBatch) error, journal *logJournal) *asyncLogSink {
	return newLogSink(inner, post, journal)
}

func newLogSink(inner logging.Sink, post func(context.Context, logBatch) error, journal *logJournal) *asyncLogSink {
	ctx, cancel := context.WithCancel(context.Background())
	s := &asyncLogSink{inner: inner, post: post, journal: journal, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	if journal != nil {
		// The journal owns the shared memory budget; moving the loaded
		// records out of the journal keeps exactly one in-memory copy, still
		// charged until each batch is acked.
		s.mem = journal.mem
		s.pending = journal.takePendingBatches()
		s.batchSeq.Store(journal.maxSequence())
		// Replay counts as work in flight so Flush/Finish never report a
		// clean stop while unconsumed records are still being delivered.
		s.inFlight = len(s.pending)
	} else {
		s.mem = &logMemBudget{}
	}
	go s.run()
	return s
}

// permanentDeliveryError marks a 4xx-class failure: retrying cannot help, so
// the batch fails immediately and the job reports the loss explicitly.
type permanentDeliveryError struct{ err error }

func (e *permanentDeliveryError) Error() string { return e.err.Error() }
func (e *permanentDeliveryError) Unwrap() error { return e.err }

// PermanentDeliveryError wraps err so the sink classifies it as
// non-retryable (used by the runner's post callback for HTTP 4xx).
func PermanentDeliveryError(err error) error {
	if err == nil {
		return nil
	}
	return &permanentDeliveryError{err: err}
}

// WriteLine implements logging.Sink. It never blocks on the network: when
// the spool is full in lines OR the shared memory budget (spool +
// journal-resident records) cannot fit the line, the line is dropped
// (counted, surfaced later) instead of stalling the drain that feeds it.
func (s *asyncLogSink) WriteLine(job, step, line string) {
	if s.inner != nil {
		s.inner.WriteLine(job, step, line)
	}
	// The spool cost is computed once here and stored with the line; the
	// drain decrements by exactly this value.
	l := logLine{Job: job, Step: step, Line: line, spoolCost: int64(len(job) + len(step) + len(line))}
	s.mu.Lock()
	if s.closed || len(s.spool) >= asyncSpoolLimit {
		s.mu.Unlock()
		if !s.closed {
			s.dropped.Add(1)
		}
		return
	}
	if !s.mem.reserve(l.spoolCost) {
		s.mu.Unlock()
		s.dropped.Add(1)
		return
	}
	s.spool = append(s.spool, l)
	s.spoolBytes += l.spoolCost
	s.cond.Signal()
	s.mu.Unlock()
}

// run replays any unconsumed journal records first, then drains the spool
// into batched posts until Close. Every new batch is journaled before its
// first POST attempt and acked after a confirmed delivery; a journal failure
// leaves the batch in the spool and stops the sender (fail closed).
//
// Delivery failures stop the sender (fail closed) as well: continuing could
// ack a LATER batch and advance the single ack watermark past a sequence the
// control plane never received, which a restart would then treat as consumed
// and silently discard. Stopping keeps the watermark the highest CONTIGUOUS
// acked sequence, so the failed journaled batch always replays.
func (s *asyncLogSink) run() {
	defer close(s.done)
	// Recovery: the records were journaled by an earlier process and carry
	// original (job, generation, batch_id) identities, so replaying them is
	// idempotent server-side and reproduces the persisted batch boundaries
	// byte-for-byte. This runs before any new batch is formed and before any
	// newly spooled line can be sent, so ordering across the restart holds.
	for i := range s.pending {
		batch := s.pending[i]
		err := s.postWithRetries(batch)
		if err == nil && s.journal != nil {
			// Deliver ack only after the server confirmed the delivery.
			err = s.journal.ack(batch.Sequence, batch.ID)
		}
		if err != nil {
			// Stop with the record still on disk: it stays available for
			// the next same-(job, generation) resume.
			s.recordSendErr(err)
			return
		}
		// Release the replay buffer slot after the ack so the shared memory
		// budget drops with the record.
		s.pending[i] = logBatch{}
		s.mu.Lock()
		s.inFlight--
		s.cond.Broadcast()
		s.mu.Unlock()
	}
	s.pending = nil

	for {
		s.mu.Lock()
		for len(s.spool) == 0 && !s.closed {
			s.cond.Wait()
		}
		if len(s.spool) == 0 && s.closed {
			s.mu.Unlock()
			return
		}
		if s.ctx.Err() != nil {
			// Cancelled (Finish deadline or job cancellation): form no new
			// batches; whatever is still spooled stays for the job outcome.
			s.mu.Unlock()
			return
		}
		// Fill one BATCH up to both the line and byte budget, measuring the
		// MARSHALED JSON size (escaping can multiply a line's encoded size).
		// This encoded size bounds the HTTP request only; spool accounting
		// uses the per-line costs stored at enqueue.
		n := 0
		var encodedBytes int64
		for n < len(s.spool) && n < asyncPostBatch {
			encoded, _ := json.Marshal(s.spool[n])
			add := int64(len(encoded))
			if n > 0 && encodedBytes+add > asyncPostBytes {
				break
			}
			encodedBytes += add
			n++
		}
		// Identity is assigned exactly ONCE, when the batch is formed and
		// before the first send; every retry below reuses this same batch.
		batch := logBatch{Sequence: s.batchSeq.Add(1), Lines: append([]logLine(nil), s.spool[:n]...)}
		batch.ID = logBatchID(batch.Sequence, batch.Lines)
		var removed int64
		for _, l := range batch.Lines {
			removed += l.spoolCost
		}
		s.spool = append([]logLine(nil), s.spool[n:]...)
		s.spoolBytes -= removed
		s.inFlight++
		s.mem.release(removed)
		s.mu.Unlock()

		if s.journal != nil {
			if jerr := s.journal.append(batch); jerr != nil {
				// No POST may leave the process for a batch that is not
				// durably journaled. Restore the exact per-line costs (under
				// the same shared budget: a line that no longer fits is
				// counted, never silently dropped), stop the sender, and
				// surface the failure on the job outcome.
				s.mu.Lock()
				var restored []logLine
				for _, l := range batch.Lines {
					if s.mem.reserve(l.spoolCost) {
						restored = append(restored, l)
						s.spoolBytes += l.spoolCost
					} else {
						s.dropped.Add(1)
					}
				}
				s.spool = append(restored, s.spool...)
				s.inFlight--
				s.mu.Unlock()
				s.recordSendErr(jerr)
				return
			}
		}

		err := s.postWithRetries(batch)
		if err == nil && s.journal != nil {
			// The record is deleted only after the ack was received. A
			// failed delete leaves the record for an idempotent replay and
			// is surfaced as a delivery failure.
			err = s.journal.ack(batch.Sequence, batch.ID)
		}
		s.mu.Lock()
		s.inFlight--
		if err != nil && s.sendErr == nil {
			s.sendErr = err
		}
		s.cond.Broadcast()
		s.mu.Unlock()
		if err != nil {
			// Fail closed: stop before any later batch can be acked past
			// the failed sequence (see the run doc comment). Lines still
			// spooled stay pending and are reported as Remaining.
			return
		}
		if s.ctx.Err() != nil {
			return
		}
	}
}

// postWithRetries sends one batch. Retryable failures are retried with
// bounded exponential backoff + jitter while the sink's context is alive; a
// permanent (4xx-class) failure fails immediately. Re-sending a batch is
// SAFE: the server's batch receipts dedupe by (job, generation, batch_id)
// and the batch identity is immutable.
func (s *asyncLogSink) postWithRetries(batch logBatch) error {
	err := s.post(s.ctx, batch)
	if err == nil {
		return nil
	}
	var perm *permanentDeliveryError
	if errors.As(err, &perm) {
		return err
	}
	backoff := 100 * time.Millisecond
	for attempt := 0; attempt < 6 && s.ctx.Err() == nil; attempt++ {
		jitter := time.Duration(time.Now().UnixNano() % int64(backoff/2+1))
		select {
		case <-time.After(backoff + jitter):
		case <-s.ctx.Done():
		}
		if s.ctx.Err() != nil {
			break
		}
		if rerr := s.post(s.ctx, batch); rerr == nil {
			return nil
		} else if errors.As(rerr, &perm) {
			return rerr
		} else {
			err = rerr
		}
		backoff *= 2
		if backoff > 2*time.Second {
			backoff = 2 * time.Second
		}
	}
	return err
}

// recordSendErr stores the FIRST sender error and wakes Flush waiters.
func (s *asyncLogSink) recordSendErr(err error) {
	s.mu.Lock()
	if err != nil && s.sendErr == nil {
		s.sendErr = err
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Flush waits until the spool is empty AND no batch is in flight (or the
// deadline passes). Waiting only for an empty spool would return success
// while the final POST is still running, hiding its failure. A sender that
// has already stopped (journal failure, or a clean closed drain) cannot make
// further progress, so the wait ends immediately with the remaining count.
func (s *asyncLogSink) Flush(deadline time.Duration) int {
	end := time.Now().Add(deadline)
	for {
		s.mu.Lock()
		pending := len(s.spool) + s.inFlight
		s.mu.Unlock()
		if pending == 0 || time.Now().After(end) {
			return pending
		}
		select {
		case <-s.done:
			return pending
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Finish stops the sender with a deadline and reports the final state. The
// in-flight request is given up to deadline to complete; if the deadline
// expires the outcome reports Stopped=false and the remaining work, and the
// job must fail explicitly rather than claim a clean completion. Before the
// outcome is reported, any batched acks are flushed durably so a clean stop
// leaves the watermark covering every confirmed delivery.
func (s *asyncLogSink) Finish(deadline time.Duration) logOutcome {
	s.Flush(deadline)
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
	stopped := true
	select {
	case <-s.done:
	case <-time.After(deadline):
		// Deadline reached: CANCEL the in-flight delivery so it does not
		// outlive the job, then give the sender a moment to unwind.
		stopped = false
		s.cancel()
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
		}
	}
	if s.journal != nil {
		// Surface a failed ack flush explicitly instead of reporting a
		// clean stop while confirmed acks are not yet durable.
		if err := s.journal.flushAcks(); err != nil {
			s.recordSendErr(err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.senderStopped = stopped
	return logOutcome{Dropped: s.dropped.Load(), Remaining: len(s.spool) + s.inFlight, Err: s.sendErr, Stopped: stopped}
}

var _ logging.Sink = (*asyncLogSink)(nil)

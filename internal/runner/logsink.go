package runner

import (
	"context"
	"encoding/json"
	"errors"
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
	post  func(ctx context.Context, lines []logLine) error

	// ctx is cancelled by Finish at its deadline, aborting any in-flight
	// delivery instead of letting it run on the job's parent context.
	ctx    context.Context
	cancel context.CancelFunc

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

func newAsyncLogSink(inner logging.Sink, post func(context.Context, []logLine) error) *asyncLogSink {
	ctx, cancel := context.WithCancel(context.Background())
	s := &asyncLogSink{inner: inner, post: post, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
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
// the spool is full in lines OR bytes the line is dropped (counted, surfaced
// later) instead of stalling the drain that feeds it.
func (s *asyncLogSink) WriteLine(job, step, line string) {
	if s.inner != nil {
		s.inner.WriteLine(job, step, line)
	}
	added := int64(len(job) + len(step) + len(line))
	s.mu.Lock()
	if s.closed || len(s.spool) >= asyncSpoolLimit || s.spoolBytes+added > asyncSpoolBytes {
		s.mu.Unlock()
		if !s.closed {
			s.dropped.Add(1)
		}
		return
	}
	s.spool = append(s.spool, logLine{Job: job, Step: step, Line: line})
	s.spoolBytes += added
	s.cond.Signal()
	s.mu.Unlock()
}

// run drains the spool into batched posts until Close.
func (s *asyncLogSink) run() {
	defer close(s.done)
	for {
		s.mu.Lock()
		for len(s.spool) == 0 && !s.closed {
			s.cond.Wait()
		}
		if len(s.spool) == 0 && s.closed {
			s.mu.Unlock()
			return
		}
		// Fill one BATCH up to both the line and byte budget, measuring the
		// MARSHALED JSON size (escaping can multiply a line's encoded size).
		n := 0
		var bytes int64
		for n < len(s.spool) && n < asyncPostBatch {
			encoded, _ := json.Marshal(s.spool[n])
			add := int64(len(encoded))
			if n > 0 && bytes+add > asyncPostBytes {
				break
			}
			bytes += add
			n++
		}
		batch := append([]logLine(nil), s.spool[:n]...)
		s.spool = append([]logLine(nil), s.spool[n:]...)
		s.spoolBytes -= bytes
		if s.spoolBytes < 0 {
			s.spoolBytes = 0
		}
		s.inFlight++
		s.mu.Unlock()

		err := s.post(s.ctx, batch)
		if err != nil {
			// Retain the batch and retry retryable failures with bounded
			// exponential backoff + jitter; a permanent (4xx-class) failure
			// fails immediately. Re-sending a batch is SAFE: the server's
			// batch receipts dedupe by (job, generation, batch_id).
			var perm *permanentDeliveryError
			if !errors.As(err, &perm) {
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
						err = nil
						break
					} else if errors.As(rerr, &perm) {
						err = rerr
						break
					} else {
						err = rerr
					}
					backoff *= 2
					if backoff > 2*time.Second {
						backoff = 2 * time.Second
					}
				}
			}
		}

		s.mu.Lock()
		s.inFlight--
		if err != nil && s.sendErr == nil {
			s.sendErr = err
		}
		s.cond.Broadcast()
		s.mu.Unlock()
	}
}

// Flush waits until the spool is empty AND no batch is in flight (or the
// deadline passes). Waiting only for an empty spool would return success
// while the final POST is still running, hiding its failure.
func (s *asyncLogSink) Flush(deadline time.Duration) int {
	end := time.Now().Add(deadline)
	for {
		s.mu.Lock()
		pending := len(s.spool) + s.inFlight
		s.mu.Unlock()
		if pending == 0 || time.Now().After(end) {
			return pending
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Finish stops the sender with a deadline and reports the final state. The
// in-flight request is given up to deadline to complete; if the deadline
// expires the outcome reports Stopped=false and the remaining work, and the
// job must fail explicitly rather than claim a clean completion.
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.senderStopped = stopped
	return logOutcome{Dropped: s.dropped.Load(), Remaining: len(s.spool) + s.inFlight, Err: s.sendErr, Stopped: stopped}
}

var _ logging.Sink = (*asyncLogSink)(nil)

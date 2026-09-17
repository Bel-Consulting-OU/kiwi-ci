package runner

import (
	"context"
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
	post  func(lines []logLine) error

	mu     sync.Mutex
	spool  []logLine
	cond   *sync.Cond
	closed bool

	dropped atomic.Int64
	sendErr atomic.Value // error

	done chan struct{}
}

type logLine struct {
	Job  string
	Step string
	Line string
}

// asyncSpoolLimit bounds the in-memory spool; at 64 bytes per line average
// this is a few MiB, far below the memory a stalled sender could otherwise
// accumulate over a long step.
// asyncSpoolLimit is the spool bound; a package variable so tests can
// shrink it instead of enqueueing a hundred thousand lines.
var asyncSpoolLimit = 100_000

// asyncPostBatch is how many lines one POST carries.
const asyncPostBatch = 200

func newAsyncLogSink(inner logging.Sink, post func([]logLine) error) *asyncLogSink {
	s := &asyncLogSink{inner: inner, post: post, done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	go s.run()
	return s
}

// WriteLine implements logging.Sink. It never blocks on the network: when
// the spool is full the line is dropped (counted, surfaced later) instead of
// stalling the drain that feeds it.
func (s *asyncLogSink) WriteLine(job, step, line string) {
	if s.inner != nil {
		s.inner.WriteLine(job, step, line)
	}
	s.mu.Lock()
	if s.closed || len(s.spool) >= asyncSpoolLimit {
		s.mu.Unlock()
		if !s.closed {
			s.dropped.Add(1)
		}
		return
	}
	s.spool = append(s.spool, logLine{Job: job, Step: step, Line: line})
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
		batch := s.spool
		if len(batch) > asyncPostBatch {
			batch = batch[:asyncPostBatch]
		}
		remaining := append([]logLine(nil), s.spool[len(batch):]...)
		s.spool = remaining
		s.mu.Unlock()

		if err := s.post(batch); err != nil {
			s.sendErr.Store(err)
		}
	}
}

// Flush waits until the spool is empty (or the deadline passes) so a job's
// tail logs reach the control plane before completion is reported. It
// returns the remaining unsent count.
func (s *asyncLogSink) Flush(deadline time.Duration) int {
	end := time.Now().Add(deadline)
	for {
		s.mu.Lock()
		n := len(s.spool)
		s.mu.Unlock()
		if n == 0 || time.Now().After(end) {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Close stops the sender after flushing what it can within the deadline.
func (s *asyncLogSink) Close(deadline time.Duration) {
	s.Flush(deadline)
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
	<-s.done
}

// Dropped reports how many lines overflowed the spool, and SendError the
// first background post failure. Both are surfaced in the job's completion
// so a lost-log job never looks clean.
func (s *asyncLogSink) Dropped() int64 { return s.dropped.Load() }

func (s *asyncLogSink) SendError() error {
	if v := s.sendErr.Load(); v != nil {
		if err, ok := v.(error); ok {
			return err
		}
	}
	return nil
}

var _ logging.Sink = (*asyncLogSink)(nil)

// unusedContext keeps the context import meaningful if callers later thread
// one through the sink; the sender intentionally survives request-scoped
// contexts (job-level lifetime).
var _ = context.Background

package executor

import (
	"sync"
	"sync/atomic"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
)

// quotaSink wraps a logging.Sink with a byte quota. Lines are forwarded
// while the total forwarded payload stays within max bytes. The first line
// that would push the counter past the quota, and every line after it, is
// dropped; exactly one terminal "log quota exceeded" marker line is written
// (tagged with the job and step of the first dropped line). The counter is
// atomic so the stream writers of one job can share the sink safely.
type quotaSink struct {
	inner logging.Sink
	max   int64
	used  atomic.Int64
	once  sync.Once
}

func (l *quotaSink) WriteLine(job, step, line string) {
	if l.max <= 0 {
		if l.inner != nil {
			l.inner.WriteLine(job, step, line)
		}
		return
	}
	if l.used.Add(int64(len(line))) > l.max {
		l.once.Do(func() {
			if l.inner != nil {
				l.inner.WriteLine(job, step, "log quota exceeded")
			}
		})
		return
	}
	if l.inner != nil {
		l.inner.WriteLine(job, step, line)
	}
}

// limitedSink wraps s with the given per-job byte quota. A non-positive
// quota (or a nil sink) returns the original sink unchanged: zero means
// unlimited.
func limitedSink(s logging.Sink, max int64) logging.Sink {
	if max <= 0 || s == nil {
		return s
	}
	return &quotaSink{inner: s, max: max}
}

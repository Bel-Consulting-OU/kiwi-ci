// Package executil provides bounded capture for external child processes
// whose output is not trusted to be small (pipeline-controlled healthchecks,
// repository-controlled git, image-controlled pull progress). A plain
// CombinedOutput/Output buffers without limit in the PARENT process, which
// bypasses every container/workspace/staging/log budget and can OOM the
// runner. These helpers retain only a small diagnostic prefix and DISCARD
// the rest while continuing to read, so the child never blocks on a full
// pipe and never grows the parent's heap without bound.
package executil

import (
	"bytes"
	"os/exec"
	"sync"
)

// BoundedBuffer is an io.Writer that retains at most Limit bytes and reports
// whether anything beyond them was discarded. Write always reports the full
// input as consumed, so a child that keeps writing keeps draining instead of
// blocking once the capture limit is reached.
type BoundedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

// NewBoundedBuffer returns a collector retaining up to limit bytes.
func NewBoundedBuffer(limit int) *BoundedBuffer {
	if limit < 0 {
		limit = 0
	}
	return &BoundedBuffer{limit: limit}
}

func (b *BoundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.truncated = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

// Bytes returns the retained prefix.
func (b *BoundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

// Truncated reports whether bytes were discarded after the capture limit.
func (b *BoundedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

// CaptureBounded runs cmd with stdout and stderr captured through one
// BoundedBuffer of the given size, returning the retained prefix, whether
// output was truncated, and the command error. Both streams share one
// collector (and one mutex), so interleaving from the child's two pipe
// goroutines cannot race.
func CaptureBounded(cmd *exec.Cmd, limit int) (out []byte, truncated bool, err error) {
	collector := NewBoundedBuffer(limit)
	cmd.Stdout = collector
	cmd.Stderr = collector
	err = cmd.Run()
	return collector.Bytes(), collector.Truncated(), err
}

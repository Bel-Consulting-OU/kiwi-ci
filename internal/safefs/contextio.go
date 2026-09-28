package safefs

import (
	"context"
	"errors"
	"io"
)

// ErrWriterStopped reports a write refused because the writer's context
// ended. Callers that distinguish cancellation from I/O failure can match it
// with errors.Is; the returned error otherwise wraps ctx.Err() so
// errors.Is(err, context.Canceled/DeadlineExceeded) also holds.
var ErrWriterStopped = errors.New("safefs: writer stopped by context")

// ErrReaderStopped reports a read refused because the reader's context
// ended, mirroring ErrWriterStopped for the consuming side.
var ErrReaderStopped = errors.New("safefs: reader stopped by context")

// ContextReader wraps r so every Read first observes ctx: once the context
// is done, reads fail immediately with ctx.Err() (wrapped with
// ErrReaderStopped) instead of continuing a long hash/extract pass the
// caller already abandoned. It is the reader-side counterpart of
// ContextWriter; archive verification and extraction stream through it.
type ContextReader struct {
	ctx context.Context
	r   io.Reader
}

// NewContextReader returns r wrapped with a context check. A nil ctx or nil
// r leaves r unwrapped (nil r is the caller's problem, as usual).
func NewContextReader(ctx context.Context, r io.Reader) io.Reader {
	if ctx == nil || r == nil {
		return r
	}
	return &ContextReader{ctx: ctx, r: r}
}

func (c *ContextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, errors.Join(ErrReaderStopped, err)
	}
	return c.r.Read(p)
}

// ContextWriter wraps w so every Write first observes ctx: once the context
// is done, writes fail immediately with ctx.Err() (wrapped with
// ErrWriterStopped) instead of continuing a long archive traversal or
// compression pass that the caller already abandoned.
//
// It exists for archive producers (cache save, artifact capture): a tar/gzip
// stream writes at least one header per entry, so a context check per Write
// gives per-entry (and per-chunk) cancellation granularity without changing
// the producer's traversal code.
type ContextWriter struct {
	ctx context.Context
	w   io.Writer
}

// NewContextWriter returns w wrapped with a context check. A nil ctx or nil
// w leaves w unwrapped (nil w is the caller's problem, as usual).
func NewContextWriter(ctx context.Context, w io.Writer) io.Writer {
	if ctx == nil || w == nil {
		return w
	}
	return &ContextWriter{ctx: ctx, w: w}
}

func (c *ContextWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, errors.Join(ErrWriterStopped, err)
	}
	return c.w.Write(p)
}

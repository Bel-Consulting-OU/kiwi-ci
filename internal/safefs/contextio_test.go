package safefs

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// TestContextWriterPassesThroughWhileAlive pins the transparent case: a live
// context writes through the wrapper unchanged.
func TestContextWriterPassesThroughWhileAlive(t *testing.T) {
	var buf bytes.Buffer
	w := NewContextWriter(context.Background(), &buf)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "hello" {
		t.Fatalf("wrote %q", buf.String())
	}
}

// TestContextWriterStopsOnContextEnd pins the cancellation contract archive
// producers rely on: once the context is done, every write fails with the
// context error (matched both directly and via ErrWriterStopped) and no
// bytes reach the underlying writer.
func TestContextWriterStopsOnContextEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var buf bytes.Buffer
	w := NewContextWriter(ctx, &buf)
	n, err := w.Write([]byte("should not land"))
	if n != 0 {
		t.Fatalf("wrote %d bytes with a canceled context", n)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if !errors.Is(err, ErrWriterStopped) {
		t.Fatalf("error = %v, want ErrWriterStopped", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("bytes reached the underlying writer: %q", buf.String())
	}
}

// TestContextWriterNilPassthrough proves the helper is safe to call
// unconditionally: a nil context or writer leaves the writer unchanged.
func TestContextWriterNilPassthrough(t *testing.T) {
	var buf bytes.Buffer
	var nilCtx context.Context
	if got := NewContextWriter(nilCtx, &buf); got != &buf {
		t.Fatal("nil context did not pass the writer through")
	}
	if got := NewContextWriter(context.Background(), nil); got != nil {
		t.Fatal("nil writer did not pass through")
	}
}

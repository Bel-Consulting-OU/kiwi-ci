package safefs

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// countingEOFSource counts reads and reports EOF.
type countingEOFSource struct{ reads int }

func (c *countingEOFSource) Read(p []byte) (int, error) {
	c.reads++
	return 0, io.EOF
}

// TestBoundedArchiveReaderNegativeBudgetAndLatchedEOF pins two edges of the
// compressed-archive budget: a negative budget clamps to zero (so not a single
// byte is ever delivered), and a clean zero-byte probe latches the EOF so a
// further read never touches the source again.
func TestBoundedArchiveReaderNegativeBudgetAndLatchedEOF(t *testing.T) {
	neg := newBoundedArchiveReader(strings.NewReader("x"), -5)
	if neg.max != 0 {
		t.Fatalf("negative budget = %d, want clamped to 0", neg.max)
	}
	out, err := io.ReadAll(neg)
	if !errors.Is(err, ErrLimits) {
		t.Fatalf("negative-budget read = %v, want ErrLimits", err)
	}
	if len(out) != 0 {
		t.Fatalf("negative budget delivered %q, want nothing", out)
	}

	src := &countingEOFSource{}
	b := newBoundedArchiveReader(src, 0)
	out, err = io.ReadAll(b)
	if err != nil || len(out) != 0 {
		t.Fatalf("empty source = (%q, %v), want clean EOF", out, err)
	}
	if src.reads != 1 {
		t.Fatalf("probe reads = %d, want exactly one", src.reads)
	}
	if _, err := b.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("latched read = %v, want io.EOF", err)
	}
	if src.reads != 1 {
		t.Fatalf("latched EOF re-read the source (%d reads)", src.reads)
	}
}

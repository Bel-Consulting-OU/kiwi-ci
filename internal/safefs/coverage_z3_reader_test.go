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

// zeroProgressSource returns (0, nil) for every read and counts the attempts:
// an abnormal reader that neither transfers bytes nor reports an error.
type zeroProgressSource struct{ reads int }

func (z *zeroProgressSource) Read(p []byte) (int, error) {
	z.reads++
	return 0, nil
}

// TestBoundedArchiveReaderNoProgress pins W5-C: a (0, nil) source answer
// latches io.ErrNoProgress after exactly one read, at the bound and below it,
// instead of permitting indefinite re-probing.
func TestBoundedArchiveReaderNoProgress(t *testing.T) {
	// Budget already spent: the next read is the single at-bound probe.
	src := &zeroProgressSource{}
	b := newBoundedArchiveReader(src, 0)
	if _, err := b.Read(make([]byte, 4)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("at-bound no-progress read = %v, want io.ErrNoProgress", err)
	}
	if src.reads != 1 {
		t.Fatalf("probe reads = %d, want exactly one", src.reads)
	}
	for i := 0; i < 3; i++ {
		if _, err := b.Read(make([]byte, 4)); !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("latched read %d = %v, want io.ErrNoProgress", i, err)
		}
	}
	if src.reads != 1 {
		t.Fatalf("latched no-progress re-probed the source (%d reads)", src.reads)
	}

	// Below the bound the same no-progress discipline applies.
	src2 := &zeroProgressSource{}
	b2 := newBoundedArchiveReader(src2, 8)
	if _, err := b2.Read(make([]byte, 4)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("below-bound no-progress read = %v, want io.ErrNoProgress", err)
	}
	if src2.reads != 1 {
		t.Fatalf("below-bound reads = %d, want exactly one", src2.reads)
	}
	if _, err := b2.Read(make([]byte, 4)); !errors.Is(err, io.ErrNoProgress) || src2.reads != 1 {
		t.Fatalf("below-bound latched read = (%v, %d reads), want latched io.ErrNoProgress", err, src2.reads)
	}
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

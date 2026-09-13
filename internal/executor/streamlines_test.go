package executor

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestStreamLinesLongLineNoDeadlock feeds a single 5 MiB line through an
// io.Pipe. streamLines must drain every byte (the writer may never block on a
// full pipe), emit the truncated prefix with a marker, and return.
func TestStreamLinesLongLineNoDeadlock(t *testing.T) {
	const total = 5 << 20
	pr, pw := io.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		buf := bytes.Repeat([]byte{'a'}, total)
		buf = append(buf, '\n')
		_, err := pw.Write(buf)
		if cerr := pw.Close(); err == nil {
			err = cerr
		}
		writeDone <- err
	}()
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		streamLines(pr, 1<<20, func(line string) { lines = append(lines, line) })
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("streamLines did not drain the pipe within 10s")
	}
	if err := <-writeDone; err != nil && err != io.ErrClosedPipe {
		t.Fatalf("writer failed (pipe not drained?): %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("expected exactly one emitted line, got %d", len(lines))
	}
	if len(lines[0]) != (1<<20)+len("[line truncated: 4194304 bytes]") {
		t.Fatalf("unexpected emitted length %d", len(lines[0]))
	}
	if !strings.HasPrefix(lines[0], strings.Repeat("a", 1<<20)) {
		t.Fatal("truncated line does not keep the first maxLine bytes")
	}
	if !strings.HasSuffix(lines[0], "[line truncated: 4194304 bytes]") {
		t.Fatalf("missing truncation marker: %q", lines[0][len(lines[0])-64:])
	}
}

// TestStreamLinesRuneBoundary verifies truncation stays on a UTF-8 rune
// boundary and the emitted line remains valid UTF-8.
func TestStreamLinesRuneBoundary(t *testing.T) {
	input := "h\xc3\xa9llo-world\n" // "héllo-world"
	var got []string
	streamLines(strings.NewReader(input), 4, func(line string) { got = append(got, line) })
	if len(got) != 1 {
		t.Fatalf("expected one line, got %d", len(got))
	}
	if !utf8.ValidString(got[0]) {
		t.Fatalf("emitted line is not valid UTF-8: %q", got[0])
	}
	if !strings.HasPrefix(got[0], "h\xc3\xa9l") {
		t.Fatalf("line did not truncate at a rune boundary: %q", got[0])
	}
	if !strings.HasSuffix(got[0], "[line truncated: 8 bytes]") {
		t.Fatalf("missing marker: %q", got[0])
	}
}

// TestStreamLinesMultipleLines confirms normal line splitting is unchanged.
func TestStreamLinesMultipleLines(t *testing.T) {
	var got []string
	streamLines(strings.NewReader("a\nbb\r\nccc\n"), 1<<20, func(line string) { got = append(got, line) })
	want := []string{"a", "bb", "ccc"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

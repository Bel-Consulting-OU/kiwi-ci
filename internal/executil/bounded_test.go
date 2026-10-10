package executil

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestNewBoundedBufferNegativeLimitCollectsNothing(t *testing.T) {
	b := NewBoundedBuffer(-1)
	n, err := b.Write([]byte("abc"))
	if n != 3 || err != nil {
		t.Fatalf("Write = (%d, %v), want (3, nil)", n, err)
	}
	if got := b.Bytes(); len(got) != 0 {
		t.Fatalf("Bytes = %q, want empty (negative limit clamps to 0)", got)
	}
	if !b.Truncated() {
		t.Fatal("Truncated = false after discarding output with a zero-size limit")
	}
}

func TestBoundedBufferRetainsPrefixExactlyOnce(t *testing.T) {
	b := NewBoundedBuffer(5)
	if n, err := b.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("Write(abc) = (%d, %v)", n, err)
	}
	if got := string(b.Bytes()); got != "abc" {
		t.Fatalf("Bytes = %q, want abc", got)
	}
	if b.Truncated() {
		t.Fatal("Truncated = true before the limit was reached")
	}
	if n, err := b.Write([]byte("de")); n != 2 || err != nil {
		t.Fatalf("Write(de) = (%d, %v)", n, err)
	}
	if got := string(b.Bytes()); got != "abcde" {
		t.Fatalf("Bytes = %q, want abcde", got)
	}
	if b.Truncated() {
		t.Fatal("Truncated = true at an exact fit")
	}
	if n, err := b.Write([]byte("f")); n != 1 || err != nil {
		t.Fatalf("Write(f) = (%d, %v)", n, err)
	}
	if got := string(b.Bytes()); got != "abcde" {
		t.Fatalf("Bytes = %q, want abcde", got)
	}
	if !b.Truncated() {
		t.Fatal("Truncated = false after discarding bytes past the limit")
	}
	b.Write(nil)
	if !b.Truncated() {
		t.Fatal("Truncated = false after a no-op write on a full buffer")
	}
}

func TestBoundedBufferZeroLimit(t *testing.T) {
	b := NewBoundedBuffer(0)
	b.Write(nil)
	if b.Truncated() {
		t.Fatal("an empty write against a zero limit must not report truncation")
	}
	if len(b.Bytes()) != 0 {
		t.Fatalf("Bytes = %q, want empty", b.Bytes())
	}
	b.Write([]byte("x"))
	if !b.Truncated() {
		t.Fatal("Truncated = false after writing past a zero limit")
	}
}

func TestBoundedBufferSplitsWriteAtLimit(t *testing.T) {
	b := NewBoundedBuffer(4)
	n, err := b.Write([]byte("abcdef"))
	if n != 6 || err != nil {
		t.Fatalf("Write = (%d, %v), want full input consumed", n, err)
	}
	if got := string(b.Bytes()); got != "abcd" {
		t.Fatalf("Bytes = %q, want abcd", got)
	}
	if !b.Truncated() {
		t.Fatal("Truncated = false after a partial write")
	}
}

func TestBoundedBufferBytesReturnsCopy(t *testing.T) {
	b := NewBoundedBuffer(8)
	b.Write([]byte("hello"))
	got := b.Bytes()
	got[0] = 'X'
	if again := string(b.Bytes()); again != "hello" {
		t.Fatalf("Bytes = %q after mutating the returned slice, want hello", again)
	}
}

// helperModeEnv selects the helper-process behavior; the helper is this test
// binary re-executed with the variable set. CaptureBounded runs a real child,
// so the command under test is a real process on every platform.
const helperModeEnv = "KIWI_EXECUTIL_TEST_HELPER"

// TestExecutilHelperProcess is not a test: it is the entry point the
// CaptureBounded tests re-execute. Without the mode variable it returns
// immediately so a normal `go test` pass sees no side effects.
func TestExecutilHelperProcess(t *testing.T) {
	mode := os.Getenv(helperModeEnv)
	switch mode {
	case "":
		return
	case "ok":
		os.Stdout.WriteString("stdout-payload")
		os.Stderr.WriteString("stderr-payload")
	case "big":
		os.Stdout.WriteString(strings.Repeat("x", 100))
		os.Stderr.WriteString(strings.Repeat("y", 100))
	case "fail":
		os.Stdout.WriteString("before-failure")
		os.Exit(3)
	default:
		os.Exit(90)
	}
}

func helperCommand(mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecutilHelperProcess$")
	cmd.Env = append(os.Environ(), helperModeEnv+"="+mode)
	return cmd
}

func TestCaptureBoundedKeepsBothStreams(t *testing.T) {
	out, truncated, err := CaptureBounded(helperCommand("ok"), 1024)
	if err != nil {
		t.Fatalf("CaptureBounded = %v, want success", err)
	}
	if truncated {
		t.Fatal("Truncated = true for output under the limit")
	}
	got := string(out)
	if !strings.Contains(got, "stdout-payload") || !strings.Contains(got, "stderr-payload") {
		t.Fatalf("captured %q, want both streams", got)
	}
}

func TestCaptureBoundedTruncatesLargeOutput(t *testing.T) {
	out, truncated, err := CaptureBounded(helperCommand("big"), 10)
	if err != nil {
		t.Fatalf("CaptureBounded = %v, want success", err)
	}
	if !truncated {
		t.Fatal("Truncated = false for output far beyond the limit")
	}
	if len(out) != 10 {
		t.Fatalf("retained %d bytes, want exactly the 10-byte limit", len(out))
	}
}

func TestCaptureBoundedReturnsCommandError(t *testing.T) {
	out, _, err := CaptureBounded(helperCommand("fail"), 1024)
	if err == nil {
		t.Fatal("CaptureBounded = nil error for a failing child")
	}
	if !strings.Contains(string(out), "before-failure") {
		t.Fatalf("captured %q, want output written before the failure", out)
	}
}

package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestRingZeroCapacityIsClamped(t *testing.T) {
	r := NewRing[int](0)
	if r.Capacity() != 1 {
		t.Fatalf("capacity = %d, want 1", r.Capacity())
	}
	r.Append(1)
	r.Append(2)
	if got := r.Slice(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("slice = %v, want [2]", got)
	}

	// A zero-valued Ring (no buffer) must be a no-op rather than panic.
	var empty Ring[int]
	empty.Append(1)
	if empty.Len() != 0 || empty.Capacity() != 0 {
		t.Fatalf("zero Ring mutated: len=%d cap=%d", empty.Len(), empty.Capacity())
	}
	if _, ok := empty.Get(0); ok {
		t.Fatal("zero Ring Get must not report a value")
	}
	empty.Reset()
	if got := empty.Slice(); len(got) != 0 {
		t.Fatalf("zero Ring Slice = %v", got)
	}
}

func TestRingGetNegativeAndResetClears(t *testing.T) {
	r := NewRing[string](3)
	r.Append("a")
	if _, ok := r.Get(-1); ok {
		t.Fatal("Get(-1) must be !ok")
	}
	r.Reset()
	if v, ok := r.Get(0); ok || v != "" {
		t.Fatalf("Get after Reset = %q,%v", v, ok)
	}
	// Reset must clear the backing array, not just the counters.
	r.Append("b")
	r.Reset()
	r.Append("c")
	r.Append("d")
	if got := r.Slice(); len(got) != 2 || got[0] != "c" || got[1] != "d" {
		t.Fatalf("slice = %v", got)
	}
}

func TestStepName(t *testing.T) {
	cases := map[string]string{
		"job > step | line": "step",
		"job > step":        "job > step",
		"no separator":      "no separator",
		"a > b | c | d":     "b",
		" > leading | line": "leading",
		"only > | pipe":     "only > | pipe",
	}
	for in, want := range cases {
		if got := stepName(in); got != want {
			t.Errorf("stepName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderFrameEdges(t *testing.T) {
	if got := renderFrame([]string{"x"}, 0, nil, nil, 0, 80); got != nil {
		t.Fatalf("h<=0 must return nil, got %v", got)
	}
	if got := renderFrame(nil, 0, nil, nil, 5, 80); len(got) != 0 {
		t.Fatalf("empty lines = %v", got)
	}

	lines := []string{"a > s | 1", "a > s | 2", "a > s | 3"}
	// Cursor past the end clamps the window to the last line.
	frame := renderFrame(lines, 99, nil, nil, 2, 80)
	if len(frame) != 1 || !strings.Contains(frame[0], "3") {
		t.Fatalf("cursor clamp frame = %v", frame)
	}
	// Collapsing a group replaces its members with a single marker line:
	// every member line is hidden.
	got := renderFrame(lines, 2, map[string]bool{"s": true}, nil, 30, 80)
	if len(got) != 1 {
		t.Fatalf("collapsed frame = %v", got)
	}
	if !strings.Contains(got[0], "▶ s (3 lines)") {
		t.Fatalf("collapsed frame = %v", got)
	}
	// Zero width truncates every line away.
	got = renderFrame(lines, 0, nil, nil, 30, 0)
	if len(got) != 3 || got[0] != "" {
		t.Fatalf("zero-width frame = %q", got)
	}
	// Match markers use their own prefix.
	got = renderFrame(lines, 0, nil, []int{0, 2}, 30, 80)
	if !strings.HasPrefix(got[0], "» ") || !strings.HasPrefix(got[2], "» ") {
		t.Fatalf("match prefixes = %q", got)
	}
	if strings.HasPrefix(got[1], "»") {
		t.Fatalf("unmatched line marked: %q", got[1])
	}
}

func TestTruncateWidths(t *testing.T) {
	if truncate("hello", 0) != "" || truncate("hello", -1) != "" {
		t.Fatal("non-positive width must return an empty string")
	}
	if truncate("héllo", 2) != "hé" {
		t.Fatal("truncate must count runes, not bytes")
	}
	if truncate("", 5) != "" {
		t.Fatal("empty input must stay empty")
	}
}

func TestFindMatchesMultipleAndNone(t *testing.T) {
	lines := []string{"alpha", "beta", "alpha", "gamma"}
	got := findMatches(lines, "alpha")
	if len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("matches = %v", got)
	}
	if got := findMatches(lines, "zzz"); len(got) != 0 {
		t.Fatalf("no matches = %v", got)
	}
	if n := countGroup(lines, "missing"); n != 0 {
		t.Fatalf("countGroup = %d", n)
	}
}

func TestExecToolSuccessAndFailure(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok-tool")
	if err := os.WriteFile(ok, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fail := filepath.Join(dir, "fail-tool")
	if err := os.WriteFile(fail, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	if err := execTool("ok-tool", nil, "payload"); err != nil {
		t.Fatalf("execTool(ok) = %v", err)
	}
	if err := execTool("fail-tool", nil, "payload"); err == nil {
		t.Fatal("execTool must surface a non-zero exit")
	}
	if err := execTool("missing-tool", nil, "payload"); err == nil {
		t.Fatal("execTool must fail for a missing tool")
	}
}

func TestCopyPermalinkFallbacks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if copyPermalink("text") {
		t.Fatal("copyPermalink must be false when no clipboard tool exists")
	}

	// pbcopy is tried first and is used when it succeeds.
	if err := os.WriteFile(filepath.Join(dir, "pbcopy"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !copyPermalink("text") {
		t.Fatal("copyPermalink must use a working pbcopy")
	}

	// A failing pbcopy falls through to the next available tool.
	if err := os.WriteFile(filepath.Join(dir, "pbcopy"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "xsel"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !copyPermalink("text") {
		t.Fatal("copyPermalink must fall back to xsel")
	}
}

func TestRawModeAndIsTerminalNonTTY(t *testing.T) {
	if _, err := rawMode(-1); err == nil {
		t.Fatal("rawMode(-1) must fail for a non-terminal fd")
	}
	if isTerminal(^uintptr(0)) {
		t.Fatal("isTerminal(invalid fd) must be false")
	}
	if isTerminal(0) {
		// `go test` normally runs with stdin on /dev/null or a pipe; only a
		// real terminal can enter raw mode.
		ts, err := rawMode(0)
		if err != nil {
			t.Fatalf("rawMode(0) on a terminal: %v", err)
		}
		ts.Restore()
	} else if _, err := rawMode(0); err == nil {
		t.Fatal("rawMode must fail when fd 0 is not a terminal")
	}

	// A controlling terminal (if any) lets the raw-mode write path run even
	// when the standard streams are pipes.
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer f.Close()
		if isTerminal(f.Fd()) {
			ts, err := rawMode(int(f.Fd()))
			if err != nil {
				t.Fatalf("rawMode(/dev/tty): %v", err)
			}
			ts.Restore()
			ts.Restore()
		}
	}

	var nilState *termState
	nilState.Restore()

	if isTerminal(os.Stdout.Fd()) {
		ts, err := rawMode(int(os.Stdout.Fd()))
		if err != nil {
			t.Fatalf("rawMode(stdout) on a terminal: %v", err)
		}
		ts.Restore()
		ts.Restore() // idempotent
	}
}

func TestReadPlain(t *testing.T) {
	var buf bytes.Buffer
	if err := renderPlain([]string{"a", "bb", "abc"}, "", &buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "a\nbb\nabc\n" {
		t.Fatalf("plain render = %q", buf.String())
	}
	buf.Reset()
	if err := renderPlain([]string{"a", "bb", "abc"}, "b", &buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "bb\nabc\n" {
		t.Fatalf("filtered render = %q", buf.String())
	}
	if err := renderPlain([]string{"x"}, "", failWriter{}); err == nil {
		t.Fatal("renderPlain must surface write errors")
	}
	if err := renderPlain(nil, "", &buf); err != nil {
		t.Fatalf("renderPlain(nil) = %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestFormatEntryAndLogState(t *testing.T) {
	got := formatEntry(logEntry{JobKey: "build", Step: "compile", Line: "ok"})
	if got != "build > compile | ok" {
		t.Fatalf("formatEntry = %q", got)
	}

	var s logState
	if s.get() != 0 {
		t.Fatalf("initial state = %d", s.get())
	}
	s.set(5)
	s.set(3)
	if s.get() != 5 {
		t.Fatalf("state must not go backwards: %d", s.get())
	}
	s.set(9)
	if s.get() != 9 {
		t.Fatalf("state = %d", s.get())
	}
}

func TestReadKeysChunkedNormalization(t *testing.T) {
	// Every case is fed one byte per Read, so escape sequences, multi-byte
	// control sequences and the search line are split at every possible
	// boundary. No byte may be dropped or promoted to an action key.
	longSearch := "/" + strings.Repeat("y", 20) + "jf\n"
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"plain keys", "qQ\tjJfFyYnN", []string{"q", "q", "tab", "j", "j", "f", "f", "y", "y", "n", "N"}},
		{"arrows", "\x1b[A\x1b[B", []string{"up", "down"}},
		{"pgup pgdn", "\x1b[5~\x1b[6~", []string{"pgup", "pgdn"}},
		{"home end", "\x1b[H\x1b[F", []string{"home", "end"}},
		{"unknown csi ignored", "\x1b[5Z", nil},
		{"search until enter", "/abc\n", []string{"/abc"}},
		{"search until cr", "/abc\r", []string{"/abc"}},
		{"search text with action keys", longSearch, []string{"/" + strings.Repeat("y", 20) + "jf"}},
		{"lone esc at eof", "\x1b", []string{"esc"}},
		{"esc followed by key", "\x1bq", []string{"esc", "q"}},
		{"esc sequence split across reads", "\x1b[Axq", []string{"up", "q"}},
		{"search then key", "/yjf\nq", []string{"/yjf", "q"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan string, 64)
			readKeys(context.Background(), oneByte(tc.in), ch)
			close(ch)
			var got []string
			for k := range ch {
				got = append(got, k)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("keys = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("keys[%d] = %q, want %q (all %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// TestReadKeysWholeBufferNormalization drives the same inputs through a
// reader that delivers large chunks, covering the in-chunk consumption path.
func TestReadKeysWholeBufferNormalization(t *testing.T) {
	ch := make(chan string, 64)
	readKeys(context.Background(), strings.NewReader("\x1b[6~q/one two\n\x1b[5~\x1b[A"), ch)
	close(ch)
	var got []string
	for k := range ch {
		got = append(got, k)
	}
	want := []string{"pgdn", "q", "/one two", "pgup", "up"}
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestReadKeysSearchFlushesAtEOF proves a search line that never sees Enter
// is still echoed once the input ends, with all of its bytes intact.
func TestReadKeysSearchFlushesAtEOF(t *testing.T) {
	ch := make(chan string, 4)
	readKeys(context.Background(), oneByte("/fyj"), ch)
	close(ch)
	var got []string
	for k := range ch {
		got = append(got, k)
	}
	if len(got) != 1 || got[0] != "/fyj" {
		t.Fatalf("keys = %v, want [/fyj]", got)
	}
}

// TestReadKeysSearchLengthBound proves an unterminated search line cannot
// grow the pending buffer without bound.
func TestReadKeysSearchLengthBound(t *testing.T) {
	ch := make(chan string, 2)
	readKeys(context.Background(), strings.NewReader("/"+strings.Repeat("x", maxSearchBytes+100)), ch)
	close(ch)
	var got []string
	for k := range ch {
		got = append(got, k)
	}
	if len(got) != 1 || len(got[0]) != maxSearchBytes+1 {
		t.Fatalf("search key length = %d (keys %v)", len(got[0]), got)
	}
}

type oneByteReader struct {
	s string
	i int
}

func oneByte(s string) *oneByteReader { return &oneByteReader{s: s} }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	p[0] = r.s[r.i]
	r.i++
	return 1, nil
}

func TestReadKeysContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		readKeys(ctx, strings.NewReader("never read"), ch)
		close(done)
	}()
	<-done
	if len(ch) != 0 {
		t.Fatalf("cancelled readKeys emitted %v", <-ch)
	}
}

func TestEntryFromModel(t *testing.T) {
	e := entryFromModel(model.LogEntry{
		Seq: 7, RunID: "run-1", JobID: "job-1", JobKey: "build", Step: "compile", Line: "ok",
	})
	if e.Seq != 7 || e.RunID != "run-1" || e.JobID != "job-1" || e.JobKey != "build" || e.Step != "compile" || e.Line != "ok" {
		t.Fatalf("entryFromModel = %+v", e)
	}
}

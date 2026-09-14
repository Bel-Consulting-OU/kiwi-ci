package tui

import (
	"context"
	"strings"
	"testing"
)

func TestRingBounded(t *testing.T) {
	r := NewRing[int](3)
	for i := 0; i < 10; i++ {
		r.Append(i)
	}
	if r.Len() != 3 {
		t.Fatalf("len = %d, want 3", r.Len())
	}
	got := r.Slice()
	if got[0] != 7 || got[1] != 8 || got[2] != 9 {
		t.Fatalf("evicted wrong entries: %v", got)
	}
}

func TestRingGetAndCapacity(t *testing.T) {
	r := NewRing[string](2)
	r.Append("a")
	r.Append("b")
	if r.Capacity() != 2 {
		t.Fatal("capacity wrong")
	}
	if v, ok := r.Get(0); !ok || v != "a" {
		t.Fatal("Get(0) wrong")
	}
	if _, ok := r.Get(5); ok {
		t.Fatal("Get out of range must be !ok")
	}
}

func TestPaginateURL(t *testing.T) {
	got := paginateURL("https://ci.example.com/", "run1", 42, 1000)
	want := "https://ci.example.com/api/v1/runs/run1/logs?after=42&limit=1000"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	got = paginateURL("http://x", "r", 0, 0)
	if got != "http://x/api/v1/runs/r/logs" {
		t.Fatalf("bare URL wrong: %q", got)
	}
}

func TestReadSSE(t *testing.T) {
	stream := "data: {\"seq\":1}\n\ndata: {\"seq\":2}\nid: 2\n\ndata: [DONE]\n\n"
	var seqs []string
	err := readSSE(context.Background(), strings.NewReader(stream), func(data string) error {
		seqs = append(seqs, data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 2 || seqs[0] != `{"seq":1}` || seqs[1] != `{"seq":2}` {
		t.Fatalf("parsed %v", seqs)
	}
}

func TestReadSSEMalformedFrameSkipped(t *testing.T) {
	stream := "data: not-json\n\ndata: {\"seq\":9}\n\n"
	var n int
	if err := readSSE(context.Background(), strings.NewReader(stream), func(string) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("frames = %d, want 2", n)
	}
}

func TestFindMatches(t *testing.T) {
	lines := []string{"build ok", "test failed", "build failed", "lint ok"}
	m := findMatches(lines, "failed")
	if len(m) != 2 || m[0] != 1 || m[1] != 2 {
		t.Fatalf("matches %v", m)
	}
	if findMatches(lines, "") != nil {
		t.Fatal("empty pattern must match nothing")
	}
}

func TestRenderFrameCollapseAndCursor(t *testing.T) {
	lines := []string{
		"a > one | 1",
		"a > one | 2",
		"b > two | 3",
		"b > two | 4",
	}
	collapsed := map[string]bool{"one": true}
	frame := renderFrame(lines, 2, collapsed, nil, 10, 80)
	if len(frame) == 0 {
		t.Fatal("empty frame")
	}
	if !strings.Contains(frame[0], "▶ one") {
		t.Fatalf("collapsed group missing: %q", frame[0])
	}
	hasB := false
	for _, l := range frame {
		if strings.Contains(l, "two |") {
			hasB = true
		}
	}
	if !hasB {
		t.Fatalf("expanded group two missing: %v", frame)
	}
}

func TestRenderFrameMatchesMarker(t *testing.T) {
	lines := []string{"a > s | x", "a > s | panic", "a > s | y"}
	frame := renderFrame(lines, 0, nil, []int{1}, 10, 80)
	found := false
	for _, l := range frame {
		if strings.HasPrefix(l, "»") && strings.Contains(l, "panic") {
			found = true
		}
	}
	if !found {
		t.Fatalf("match marker missing: %v", frame)
	}
}

func TestTruncate(t *testing.T) {
	if truncate("hello", 3) != "hel" {
		t.Fatal("truncate wrong")
	}
	if truncate("hi", 5) != "hi" {
		t.Fatal("short string must pass through")
	}
}

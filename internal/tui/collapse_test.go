package tui

import (
	"strings"
	"testing"
)

// TestRenderCollapseHidesMembers proves a collapsed group contributes only
// its marker line, no matter how many members it has.
func TestRenderCollapseHidesMembers(t *testing.T) {
	lines := []string{
		"job > build | 1",
		"job > build | 2",
		"job > build | 3",
		"job > test | ok",
	}
	got := renderFrame(lines, 0, map[string]bool{"build": true}, nil, 20, 80)
	if len(got) != 2 {
		t.Fatalf("collapsed frame = %v", got)
	}
	if !strings.Contains(got[0], "▶ build (3 lines)") {
		t.Fatalf("marker = %q", got[0])
	}
	if !strings.Contains(got[1], "test | ok") {
		t.Fatalf("expanded group = %q", got[1])
	}
	for _, l := range got {
		if strings.Contains(l, "build | ") {
			t.Fatalf("collapsed member leaked: %v", got)
		}
	}
}

// TestRenderCollapseMatchesMapToVisibleLines locks the search-highlight
// invariant: a match on a hidden member of a collapsed group highlights the
// marker, and matches below a collapsed group are shifted by the lines the
// collapse removed.
func TestRenderCollapseMatchesMapToVisibleLines(t *testing.T) {
	lines := []string{
		"a > one | x",
		"a > one | panic here",
		"b > two | y",
		"b > two | panic too",
	}
	collapsed := map[string]bool{"one": true}
	// matches are line indices: 1 (hidden in the collapsed group) and 3.
	got := renderFrame(lines, 0, collapsed, []int{1, 3}, 10, 80)
	if len(got) != 3 {
		t.Fatalf("frame = %v", got)
	}
	if !strings.HasPrefix(got[0], "» ") || !strings.Contains(got[0], "▶ one (2 lines)") {
		t.Fatalf("collapsed match must mark the marker, got %q", got[0])
	}
	if !strings.HasPrefix(got[2], "» ") || !strings.Contains(got[2], "panic too") {
		t.Fatalf("shifted match marker wrong, got %q", got[2])
	}
	if strings.HasPrefix(got[1], "»") {
		t.Fatalf("unmatched visible line marked: %q", got[1])
	}
}

// TestRenderCollapseCursorAnchorsAtMarker proves the cursor window uses
// visible coordinates: a cursor on a hidden member scrolls to the marker.
func TestRenderCollapseCursorAnchorsAtMarker(t *testing.T) {
	lines := []string{
		"a > one | 1",
		"a > one | 2",
		"b > two | 3",
		"b > two | 4",
	}
	collapsed := map[string]bool{"one": true}
	// cursor line 1 is hidden; visible layout is [marker, 3, 4], h=2 shows
	// the marker and the first expanded line.
	got := renderFrame(lines, 1, collapsed, nil, 2, 80)
	if len(got) != 2 {
		t.Fatalf("frame = %v", got)
	}
	if !strings.Contains(got[0], "▶ one (2 lines)") || !strings.Contains(got[1], "two | 3") {
		t.Fatalf("cursor did not anchor at the marker: %v", got)
	}
}

// TestRenderCollapseExpandIsIdentity proves expanding a group restores the
// original lines (collapse state is the only variable).
func TestRenderCollapseExpandIsIdentity(t *testing.T) {
	lines := []string{"a > one | 1", "a > one | 2", "b > two | 3"}
	got := renderFrame(lines, 0, map[string]bool{"one": false}, nil, 10, 80)
	want := renderFrame(lines, 0, nil, nil, 10, 80)
	if len(got) != len(want) {
		t.Fatalf("expanded frame = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRenderCollapseSingleLineGroup checks one-member groups collapse too.
func TestRenderCollapseSingleLineGroup(t *testing.T) {
	lines := []string{"a > one | only"}
	got := renderFrame(lines, 0, map[string]bool{"one": true}, nil, 10, 80)
	if len(got) != 1 || !strings.Contains(got[0], "▶ one (1 lines)") {
		t.Fatalf("single-line collapse = %v", got)
	}
}

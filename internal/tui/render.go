package tui

import (
	"fmt"
	"strings"
)

// findMatches returns the 0-based indices of lines containing pattern
// (case-sensitive; empty pattern matches nothing).
func findMatches(lines []string, pattern string) []int {
	if pattern == "" {
		return nil
	}
	var out []int
	for i, l := range lines {
		if strings.Contains(l, pattern) {
			out = append(out, i)
		}
	}
	return out
}

// stepName extracts the step a log line belongs to, for collapsing.
func stepName(line string) string {
	// Log entries rendered as "job key > step | line" by the formatter; the
	// collapse model groups by the step token between "> " and " | ".
	if i := strings.Index(line, "> "); i >= 0 {
		rest := line[i+2:]
		if j := strings.Index(rest, " | "); j >= 0 {
			return rest[:j]
		}
	}
	return line
}

// renderFrame builds one visible screen of lines honoring collapse state,
// search matches, and the cursor. h is the frame height; w the width.
func renderFrame(lines []string, cursor int, collapsed map[string]bool, matches []int, h, w int) []string {
	if h <= 0 {
		return nil
	}
	visible := make([]string, 0, len(lines))
	group := ""
	for _, l := range lines {
		s := stepName(l)
		if s != group {
			group = s
			if collapsed[group] {
				visible = append(visible, fmt.Sprintf("▶ %s (%d lines)", group, countGroup(lines, group)))
				continue
			}
		}
		visible = append(visible, l)
	}
	matchSet := map[int]bool{}
	for _, m := range matches {
		matchSet[m] = true
	}
	start := cursor - h + 1
	if start < 0 {
		start = 0
	}
	if start > len(visible)-1 {
		start = len(visible) - 1
	}
	if start < 0 {
		start = 0
	}
	end := start + h
	if end > len(visible) {
		end = len(visible)
	}
	out := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		prefix := "  "
		if matchSet[i] {
			prefix = "» "
		}
		out = append(out, truncate(prefix+visible[i], w))
	}
	return out
}

func countGroup(lines []string, group string) int {
	n := 0
	for _, l := range lines {
		if stepName(l) == group {
			n++
		}
	}
	return n
}

func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	return string(r[:w])
}

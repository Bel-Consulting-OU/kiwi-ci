package surfacecheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEverySubmitRunWiresImageLock: every enqueue path must carry the image
// lock (or be a documented rerun that copies an already-locked pipeline).
// A SubmitRun built without ImageLock is a skip-path — the run would execute
// mutable tags even when the repo has a lockfile. This is the static
// detector for the "authority skipped on one path" bug class.
func TestEverySubmitRunWiresImageLock(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "server")
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Every SubmitRun{ literal must either set ImageLock or be inside a
	// documented exception block.
	exception := regexp.MustCompile(`(?s)//\s*rerun copies[\s\S]{0,400}SubmitRun\{`)
	blockRe := regexp.MustCompile(`SubmitRun\{`)
	sites := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, loc := range blockRe.FindAllStringIndex(src, -1) {
			sites++
			// Slice forward from the literal to the closing of the composite
			// (heuristic window: 800 chars covers every construction here).
			window := src[loc[0]:min(loc[0]+800, len(src))]
			if strings.Contains(window, "ImageLock:") {
				continue
			}
			// Documented exception: rerun copies the source run's already
			// locked canonical pipeline.
			if exception.MatchString(src[max(0, loc[0]-400) : loc[0]+50]) {
				continue
			}
			// Allow a comment immediately above naming the exception.
			prefix := src[max(0, loc[0]-200):loc[0]]
			if strings.Contains(prefix, "already-locked") || strings.Contains(prefix, "ImageLock is set") {
				continue
			}
			t.Errorf("%s:%d: SubmitRun{} does not wire ImageLock — a skip-path that would execute mutable tags", filepath.Base(f), 1+strings.Count(src[:loc[0]], "\n"))
		}
	}
	if sites < 3 {
		t.Fatalf("only %d SubmitRun sites found; the detector would be vacuous", sites)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

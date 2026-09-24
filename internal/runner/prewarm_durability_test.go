package runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// TestPrewarmSaveStateDurable is the H1-E durability regression: saveState
// must go through the shared fsutil primitive, so a failed parent-directory
// fsync after the rename is surfaced as a post-rename (Renamed) error and the
// renamed bytes stay visible, while a successful save leaves no temp file
// behind. The pre-fix WriteFile+Rename ignored the directory sync entirely,
// so the injected failure would not be reported at all.
func TestPrewarmSaveStateDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prewarm-state.json")
	p := &prewarmer{stateFile: path}
	st := prewarmState{Version: 1, Items: []prewarmItem{{Ref: "alpine@sha256:" + strings.Repeat("a", 64), Kind: "docker"}}}

	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error { return errors.New("injected directory sync failure") }})
	err := p.saveState(st)
	restore()
	if err == nil {
		t.Fatal("saveState ignored the directory-sync failure")
	}
	if !fsutil.Renamed(err) {
		t.Fatalf("saveState error is not post-rename: %v", err)
	}
	if b, rerr := os.ReadFile(path); rerr != nil || !strings.Contains(string(b), "alpine@sha256") {
		t.Fatalf("published-but-uncertain state not visible: %v, %q", rerr, string(b))
	}
	assertNoPrewarmTemp(t, dir)

	// A clean save replaces the file and leaves no scratch file.
	if err := p.saveState(prewarmState{Version: 1, Items: []prewarmItem{{Ref: "b@sha256:" + strings.Repeat("b", 64), Kind: "docker"}}}); err != nil {
		t.Fatalf("clean saveState: %v", err)
	}
	b, rerr := os.ReadFile(path)
	if rerr != nil || !strings.Contains(string(b), "sha256:") {
		t.Fatalf("state file after clean save = %q, %v", string(b), rerr)
	}
	assertNoPrewarmTemp(t, dir)
}

func assertNoPrewarmTemp(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") || strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

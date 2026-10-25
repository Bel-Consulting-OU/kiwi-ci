package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPrepareReflinkFallbackVerifiesExactCopy is the regression oracle for
// the exact-copy verifier against the darwin reflink fallback: `cp -c -R`
// materializes the run-base and then PRODUCTION STRIPS .git from the
// workspace (documented reflink semantics — audit tools don't get a second
// repository admin dir). verifyExactTree must exempt .git (and only .git)
// the way verifyStagedTree always did; demanding it turns a complete
// reflink workspace into a hard Prepare failure, and a naive file-count
// comparison that includes .git fails the same way.
func TestPrepareReflinkFallbackVerifiesExactCopy(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("reflink (cp -c) fallback is darwin-only")
	}
	src := t.TempDir()
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "config", "user.email", "t@example.com")
	runGit(t, src, "config", "user.name", "t")
	writeFile(t, filepath.Join(src, "app.txt"), "payload")
	writeFile(t, filepath.Join(src, "nested", "deep.txt"), "deep")
	runGit(t, src, "add", ".")
	runGit(t, src, "commit", "-m", "init")
	// Tracked content inside a skip-name dir: present in base, must
	// survive the reflink + verify as well.
	writeFile(t, filepath.Join(src, "dist", "asset.txt"), "asset")
	runGit(t, src, "add", "dist/asset.txt")
	runGit(t, src, "commit", "-m", "asset")

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := m.BasePath()
	if _, err := os.Lstat(filepath.Join(base, ".git")); err != nil {
		t.Fatalf("frozen base must carry .git for a normal clone: %v", err)
	}

	// Force the copyTree error so snapshotFrom falls through to `cp -c -R`.
	orig := snapshotCopyTree
	snapshotCopyTree = func(string, string, trackedIndex) error {
		return errors.New("forced copyTree failure for reflink fallback")
	}
	t.Cleanup(func() { snapshotCopyTree = orig })

	dir, cleanup, err := m.Prepare(context.Background(), "reflink-job")
	if err != nil {
		if strings.Contains(err.Error(), "workspace snapshot failed") {
			t.Skipf("reflink unavailable on this filesystem: %v", err)
		}
		t.Fatalf("prepare via reflink fallback: %v (verify must exempt the stripped .git)", err)
	}
	defer cleanup()

	if got := readFile(t, filepath.Join(dir, "app.txt")); got != "payload" {
		t.Fatalf("reflink workspace app.txt = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", "asset.txt")); err != nil {
		t.Fatalf("tracked dist content missing from reflink workspace: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
		t.Fatal("reflink path must strip .git from the job workspace (documented strategy semantics)")
	}
	// Every non-.git base entry is present with identical content.
	assertFileSetExceptGit(t, base, dir)
}

// assertFileSetExceptGit compares base and target entry sets, ignoring the
// .git subtree (reflink strips it) but requiring every other path and file
// body to match exactly.
func assertFileSetExceptGit(t *testing.T, base, target string) {
	t.Helper()
	collect := func(root string) map[string]string {
		set := map[string]string{}
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil || rel == "." {
				return nil
			}
			slash := filepath.ToSlash(rel)
			if slash == ".git" || strings.HasPrefix(slash, ".git/") {
				return nil
			}
			if info.IsDir() {
				set[slash] = "d"
			} else {
				set[slash] = "f"
			}
			return nil
		})
		return set
	}
	sb, st := collect(base), collect(target)
	for k, kind := range sb {
		got, ok := st[k]
		if !ok {
			t.Fatalf("base entry %q missing from reflink workspace", k)
		}
		if got != kind {
			t.Fatalf("%q kind mismatch: base=%s target=%s", k, kind, got)
		}
		if kind == "f" {
			b1, e1 := os.ReadFile(filepath.Join(base, filepath.FromSlash(k)))
			b2, e2 := os.ReadFile(filepath.Join(target, filepath.FromSlash(k)))
			if e1 != nil || e2 != nil {
				t.Fatalf("read %q: %v / %v", k, e1, e2)
			}
			if string(b1) != string(b2) {
				t.Fatalf("content of %q differs", k)
			}
		}
	}
	for k := range st {
		if _, ok := sb[k]; !ok {
			t.Fatalf("reflink workspace entry %q not present in the run-base", k)
		}
	}
}

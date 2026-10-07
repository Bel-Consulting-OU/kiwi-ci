package cache

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// stubCacheFSPrimitives replaces the publish/rollback filesystem seams and
// restores them when the test ends, so an injected fault can never leak into
// another test.
func stubCacheFSPrimitives(t *testing.T) {
	t.Helper()
	origRename, origRemove, origRemoveAll := renameFn, removeFn, removeAllFn
	t.Cleanup(func() {
		renameFn, removeFn, removeAllFn = origRename, origRemove, origRemoveAll
	})
}

// stagingSiblings returns the restore staging directories sitting NEXT TO ws
// (the sibling staging location). Staging must never be created inside ws.
func stagingSiblings(t *testing.T, ws string) []string {
	t.Helper()
	parent := filepath.Dir(ws)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), cacheStagePrefix) {
			out = append(out, filepath.Join(parent, e.Name()))
		}
	}
	return out
}

// TestRestorePublishRollbackFailureIsTypedDebt is fault (a): the first publish
// rename succeeds, the second fails, and the rollback removal of the first
// published path fails. The restore must fail with a *PublishRollbackError
// that names exactly the surviving path, the workspace is documented to
// contain that path (path #1), and the cleanup-debt reporter receives it.
func TestRestorePublishRollbackFailureIsTypedDebt(t *testing.T) {
	stubCacheFSPrimitives(t)
	ws := t.TempDir()
	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "rollbackkey", cacheTarGz(t, []cacheTarEntry{
		{name: "a.txt", data: []byte("a"), typeflag: tar.TypeReg},
		{name: "b.txt", data: []byte("b"), typeflag: tar.TypeReg},
	}))
	type debt struct {
		kind, path string
		err        error
	}
	var debts []debt
	s.ReportCleanupDebt = func(kind, path string, err error) { debts = append(debts, debt{kind, path, err}) }

	renames := 0
	renameFn = func(oldpath, newpath string) error {
		renames++
		if renames == 2 {
			return errors.New("injected rename fault")
		}
		return os.Rename(oldpath, newpath)
	}
	removeFn = func(name string) error {
		if filepath.Base(name) == "a.txt" {
			return errors.New("injected remove fault")
		}
		return os.Remove(name)
	}

	hit, err := s.RestoreContext(context.Background(), "rollbackkey", ws, []string{"."})
	if err == nil || hit {
		t.Fatalf("restore = hit=%t err=%v, want a failed restore", hit, err)
	}
	var residue *PublishRollbackError
	if !errors.As(err, &residue) {
		t.Fatalf("error = %v, want *PublishRollbackError", err)
	}
	if len(residue.Remaining) != 1 || residue.Remaining[0] != "a.txt" {
		t.Fatalf("Remaining = %v, want exactly [a.txt]", residue.Remaining)
	}
	if residue.PublishErr == nil || residue.RollbackErr == nil {
		t.Fatalf("PublishErr=%v RollbackErr=%v, want both set", residue.PublishErr, residue.RollbackErr)
	}
	if !strings.Contains(err.Error(), "partially restored") {
		t.Fatalf("error text %q does not warn about partially restored files", err)
	}
	// Workspace state is documented: the first published path is live; the
	// never-published second path is absent.
	if b, rerr := os.ReadFile(filepath.Join(ws, "a.txt")); rerr != nil || string(b) != "a" {
		t.Fatalf("residue a.txt = %q, %v; want %q", b, rerr, "a")
	}
	if _, serr := os.Lstat(filepath.Join(ws, "b.txt")); !os.IsNotExist(serr) {
		t.Fatalf("b.txt was published despite the failed rename: %v", serr)
	}
	// The debt reporter fired for the residue path.
	found := false
	for _, d := range debts {
		if d.kind == CleanupKindRestoreRollback && strings.HasSuffix(filepath.ToSlash(d.path), "/a.txt") && d.err != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("cleanup-debt reports = %+v, want one %s for a.txt", debts, CleanupKindRestoreRollback)
	}
	// The staging tree (which still holds b.txt) is gone.
	if got := stagingSiblings(t, ws); len(got) != 0 {
		t.Fatalf("staging siblings left behind: %v", got)
	}
}

// TestRestoreStagingRemovalFailureAfterPublishIsDebt is fault (b): the publish
// fully succeeds but staging removal fails. The restore must still report
// hit=true, err=nil, the restored file must be live, and the leftover staging
// tree must be reported as cleanup debt through the PER-CALL reporter the
// executor wires (RestoreContextWithDebt).
func TestRestoreStagingRemovalFailureAfterPublishIsDebt(t *testing.T) {
	stubCacheFSPrimitives(t)
	ws := t.TempDir()
	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "stagekey", cacheTarGz(t, []cacheTarEntry{
		{name: "c.txt", data: []byte("c"), typeflag: tar.TypeReg},
	}))
	var gotKind, gotPath string
	var gotErr error
	report := func(kind, path string, err error) {
		gotKind, gotPath, gotErr = kind, path, err
	}
	removeAllFn = func(path string) error {
		if strings.HasPrefix(filepath.Base(path), cacheStagePrefix) {
			return errors.New("injected removeAll fault")
		}
		return os.RemoveAll(path)
	}

	hit, err := s.RestoreContextWithDebt(context.Background(), "stagekey", ws, []string{"."}, report)
	if err != nil || !hit {
		t.Fatalf("restore = hit=%t err=%v, want success", hit, err)
	}
	if b, rerr := os.ReadFile(filepath.Join(ws, "c.txt")); rerr != nil || string(b) != "c" {
		t.Fatalf("restored file = %q, %v; want %q", b, rerr, "c")
	}
	if gotKind != CleanupKindStagingResidue || gotErr == nil {
		t.Fatalf("debt = (%s, %s, %v), want a %s report", gotKind, gotPath, gotErr, CleanupKindStagingResidue)
	}
	if !strings.HasPrefix(filepath.Base(gotPath), cacheStagePrefix) {
		t.Fatalf("debt path %q is not a staging tree", gotPath)
	}
	if _, serr := os.Stat(gotPath); serr != nil {
		t.Fatalf("reported staging residue %q does not exist: %v", gotPath, serr)
	}
	// Remove the intentionally left tree so the test does not leak it.
	if err := os.RemoveAll(gotPath); err != nil {
		t.Fatal(err)
	}
}

// TestRestorePublishSuccessLeavesNoStagingSibling is fault (c), success half:
// the normal path restores every member and leaves no staging directory
// anywhere (including the sibling location).
func TestRestorePublishSuccessLeavesNoStagingSibling(t *testing.T) {
	ws := t.TempDir()
	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "successkey", cacheTarGz(t, []cacheTarEntry{
		{name: "dir/", typeflag: tar.TypeDir},
		{name: "dir/one.txt", data: []byte("one"), typeflag: tar.TypeReg},
		{name: "two.txt", data: []byte("two"), typeflag: tar.TypeReg},
	}))
	hit, err := s.RestoreContext(context.Background(), "successkey", ws, []string{"."})
	if err != nil || !hit {
		t.Fatalf("restore = hit=%t err=%v, want success", hit, err)
	}
	for path, want := range map[string]string{"two.txt": "two", "dir/one.txt": "one"} {
		if b, rerr := os.ReadFile(filepath.Join(ws, filepath.FromSlash(path))); rerr != nil || string(b) != want {
			t.Fatalf("restored %s = %q, %v; want %q", path, b, rerr, want)
		}
	}
	if got := stagingDirs(t, ws); len(got) != 0 {
		t.Fatalf("staging inside the workspace: %v", got)
	}
	if got := stagingSiblings(t, ws); len(got) != 0 {
		t.Fatalf("staging siblings left behind: %v", got)
	}
}

// TestRestoreMidPublishFailureWithCompleteRollbackUnchanged is fault (c),
// failure half: a mid-publish rename fault whose rollback succeeds must leave
// the workspace byte-for-byte unchanged, return a plain (non-rollback) error,
// and leave no staging directory behind.
func TestRestoreMidPublishFailureWithCompleteRollbackUnchanged(t *testing.T) {
	stubCacheFSPrimitives(t)
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, ws)
	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "cleanrollback", cacheTarGz(t, []cacheTarEntry{
		{name: "a.txt", data: []byte("a"), typeflag: tar.TypeReg},
		{name: "b.txt", data: []byte("b"), typeflag: tar.TypeReg},
	}))
	renames := 0
	renameFn = func(oldpath, newpath string) error {
		renames++
		if renames == 2 {
			return errors.New("injected rename fault")
		}
		return os.Rename(oldpath, newpath)
	}

	hit, err := s.RestoreContext(context.Background(), "cleanrollback", ws, []string{"."})
	if err == nil || hit {
		t.Fatalf("restore = hit=%t err=%v, want a failed restore", hit, err)
	}
	var residue *PublishRollbackError
	if errors.As(err, &residue) {
		t.Fatalf("error = %v, want a plain error after a complete rollback", err)
	}
	if got := snapshotTree(t, ws); !reflect.DeepEqual(before, got) {
		t.Fatalf("workspace changed:\nbefore=%v\nafter=%v", before, got)
	}
	if got := stagingSiblings(t, ws); len(got) != 0 {
		t.Fatalf("staging siblings left behind: %v", got)
	}
}

// TestRestoreStagingIsOutsideWorkspace is fault (d): at the moment the first
// publish rename runs (with the restore about to fail on the next rename), the
// staged source is a sibling of the workspace root and the workspace contains
// no staging directory at any point.
func TestRestoreStagingIsOutsideWorkspace(t *testing.T) {
	stubCacheFSPrimitives(t)
	ws := t.TempDir()
	canonicalWS, err := filepath.EvalSymlinks(ws)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(canonicalWS)
	sep := string(os.PathSeparator)
	s := &Store{Root: t.TempDir()}
	writeCacheArchive(t, s, "outsidekey", cacheTarGz(t, []cacheTarEntry{
		{name: "a.txt", data: []byte("a"), typeflag: tar.TypeReg},
		{name: "b.txt", data: []byte("b"), typeflag: tar.TypeReg},
	}))
	sawStagingInsideWorkspace := false
	stagingWasSibling := false
	renames := 0
	renameFn = func(oldpath, newpath string) error {
		renames++
		entries, err := os.ReadDir(ws)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), cacheStagePrefix) {
				sawStagingInsideWorkspace = true
			}
		}
		stageDir := filepath.Dir(oldpath)
		if !strings.HasPrefix(oldpath, canonicalWS+sep) && filepath.Dir(stageDir) == parent {
			stagingWasSibling = true
		}
		if renames == 2 {
			return errors.New("injected rename fault")
		}
		return os.Rename(oldpath, newpath)
	}

	if _, err := s.RestoreContext(context.Background(), "outsidekey", ws, []string{"."}); err == nil {
		t.Fatal("restore succeeded despite the injected rename fault")
	}
	if sawStagingInsideWorkspace {
		t.Fatal("a .kiwi-cache-stage-* directory existed inside the live workspace during publish")
	}
	if !stagingWasSibling {
		t.Fatal("the staged source was not a sibling of the workspace root")
	}
	if got := stagingDirs(t, ws); len(got) != 0 {
		t.Fatalf("staging inside the workspace after the failure: %v", got)
	}
}

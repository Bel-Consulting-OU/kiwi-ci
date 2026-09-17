package migrations

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

// errReadFS fails every Open, so fs.ReadDir cannot list the migration tree.
type errReadFS struct{ err error }

func (e errReadFS) Open(string) (fs.File, error) { return nil, e.err }

func TestLoadReadDirError(t *testing.T) {
	sentinel := errors.New("boom")
	if _, err := load(errReadFS{err: sentinel}); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("load err = %v, want wrapping %v", err, sentinel)
	}
}

// unreadableFileFS lists an entry for Version.sql but fails to open it, which
// the embed FS cannot express (every listed entry is readable).
type unreadableFileFS struct{ dirEntries []fs.DirEntry }

func (u unreadableFileFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &unreadableDirFile{entries: u.dirEntries}, nil
	}
	return nil, errors.New("permission denied")
}

type unreadableDirFile struct {
	entries []fs.DirEntry
	done    bool
}

func (d *unreadableDirFile) Stat() (fs.FileInfo, error) { return dirInfo{}, nil }
func (d *unreadableDirFile) Close() error               { return nil }
func (d *unreadableDirFile) Read([]byte) (int, error)   { return 0, errors.New("is a directory") }
func (d *unreadableDirFile) ReadDir(int) ([]fs.DirEntry, error) {
	if d.done {
		return nil, errors.New("closed")
	}
	d.done = true
	return d.entries, nil
}

type dirInfo struct{}

func (dirInfo) Name() string       { return "." }
func (dirInfo) Size() int64        { return 0 }
func (dirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o755 }
func (dirInfo) ModTime() time.Time { return time.Time{} }
func (dirInfo) IsDir() bool        { return true }
func (dirInfo) Sys() any           { return nil }

type namedFileInfo struct{ name string }

func (n namedFileInfo) Name() string       { return n.name }
func (n namedFileInfo) Size() int64        { return 0 }
func (n namedFileInfo) Mode() fs.FileMode  { return 0o644 }
func (n namedFileInfo) ModTime() time.Time { return time.Time{} }
func (n namedFileInfo) IsDir() bool        { return false }
func (n namedFileInfo) Sys() any           { return nil }
func (n namedFileInfo) Info() (fs.FileInfo, error) {
	return n, nil
}
func (n namedFileInfo) Type() fs.FileMode { return 0o644 }

func TestLoadSkipsNonSQLAndDirs(t *testing.T) {
	ms, err := load(fstest.MapFS{
		"0001_init.sql":   &fstest.MapFile{Data: []byte("CREATE TABLE a (id int);")},
		"notes.txt":       &fstest.MapFile{Data: []byte("not a migration")},
		"sub/0002_in.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(ms) != 1 || ms[0].Version != 1 || ms[0].Name != "0001_init.sql" {
		t.Fatalf("load = %+v", ms)
	}
}

func TestLoadBadVersionName(t *testing.T) {
	if _, err := load(fstest.MapFS{"noname.sql": &fstest.MapFile{Data: []byte("SELECT 1;")}}); err == nil {
		t.Fatal("versionless name must fail")
	}
	if _, err := load(fstest.MapFS{"abc_name.sql": &fstest.MapFile{Data: []byte("SELECT 1;")}}); err == nil {
		t.Fatal("non-numeric version must fail")
	}
}

func TestLoadUnreadableMigration(t *testing.T) {
	fsys := unreadableFileFS{dirEntries: []fs.DirEntry{namedFileInfo{name: "0001_init.sql"}}}
	if _, err := load(fsys); err == nil {
		t.Fatal("unreadable listed file must fail")
	}
}

func TestLoadEmptyMigration(t *testing.T) {
	if _, err := load(fstest.MapFS{"0001_init.sql": &fstest.MapFile{Data: []byte("-- only a comment\n;;\n")}}); err == nil {
		t.Fatal("statement-less migration must fail")
	}
}

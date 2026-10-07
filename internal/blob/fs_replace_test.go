package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fsReplaceFixture seeds a fresh FS store with one object and returns the
// store, the object key, the correct bytes, and the on-disk path.
func fsReplaceFixture(t *testing.T) (*FS, string, []byte, string) {
	t.Helper()
	s := NewFS(t.TempDir())
	data := []byte("replace me payload")
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])
	if _, err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	return s, key, data, filepath.Join(s.Root, "sha256", key[:2], key)
}

// TestFSReplaceHealsExistingObject proves Replace bypasses the dedup shortcut
// and atomically rewrites a corrupted object from the supplied reader.
func TestFSReplaceHealsExistingObject(t *testing.T) {
	s, key, data, path := fsReplaceFixture(t)
	corrupt := bytes.Repeat([]byte("x"), len(data))
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	// Sanity: Put would have short-circuited to the corrupt object.
	if _, err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, corrupt) {
		t.Fatal("Put unexpectedly rewrote the corrupt object; Replace is the healing path")
	}

	obj, err := s.Replace(context.Background(), key, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if obj.Key != key || obj.SHA256 != key || obj.Size != int64(len(data)) {
		t.Fatalf("replaced object = %+v", obj)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatalf("healed content = %q, want %q", got, data)
	}
	rc, _, err := s.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got := make([]byte, len(data))
	if _, err := rc.Read(got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("Open after Replace = %q, want %q", got, data)
	}
}

// TestFSReplaceRejectsWrongContentAndLeavesDestination proves a replacement
// whose bytes do not hash to the key (or do not match the size) fails before
// the rename and never installs different bad bytes.
func TestFSReplaceRejectsWrongContentAndLeavesDestination(t *testing.T) {
	s, key, data, path := fsReplaceFixture(t)
	corrupt := bytes.Repeat([]byte("x"), len(data))
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	wrong := bytes.Repeat([]byte("y"), len(data))
	if _, err := s.Replace(context.Background(), key, bytes.NewReader(wrong), int64(len(data))); err == nil {
		t.Fatal("Replace accepted content that does not hash to the key")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, corrupt) {
		t.Fatalf("failed Replace touched the destination: %q", got)
	}

	// A size disagreement fails too, and leaves no temp file behind.
	if _, err := s.Replace(context.Background(), key, bytes.NewReader(data[:4]), int64(len(data))); err == nil {
		t.Fatal("Replace accepted a short stream")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("failed Replace left staging file %q behind", e.Name())
		}
	}
}

// TestFSReplaceInputErrors pins the validation arms shared with Put.
func TestFSReplaceInputErrors(t *testing.T) {
	s := NewFS(t.TempDir())
	if _, err := s.Replace(context.Background(), "short", bytes.NewReader(nil), 0); err == nil {
		t.Fatal("invalid key accepted")
	}
	if _, err := s.Replace(context.Background(), gapKey, bytes.NewReader(nil), -1); err == nil {
		t.Fatal("negative size accepted")
	}
	if _, err := s.Replace(context.Background(), gapKey, bytes.NewReader([]byte("abc")), 4); err == nil {
		t.Fatal("size mismatch accepted")
	}
}

// TestFSReplaceRenameFailureFailsClosed proves a failed rename while healing
// never acknowledges the wrong object that is already at the destination
// (Put's concurrent-winner policy must not leak into Replace).
func TestFSReplaceRenameFailureFailsClosed(t *testing.T) {
	s, key, data, path := fsReplaceFixture(t)
	corrupt := bytes.Repeat([]byte("x"), len(data))
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	orig := fsRename
	fsRename = func(string, string) error { return errors.New("rename refused") }
	t.Cleanup(func() { fsRename = orig })

	if _, err := s.Replace(context.Background(), key, bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("Replace acknowledged an object whose replacement rename failed")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, corrupt) {
		t.Fatalf("destination changed despite the failed rename: %q", got)
	}
}

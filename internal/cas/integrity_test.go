package cas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

// TestCASOpenVerifiesDigestOnRead corrupts a stored blob on disk and proves
// that Open's reader reports ErrDigestMismatch at EOF (and on Close for
// short reads) instead of silently serving corrupted content.
func TestCASOpenVerifiesDigestOnRead(t *testing.T) {
	dir := t.TempDir()
	c := New(blob.NewFS(dir))
	data := []byte("content addressed payload")
	obj, err := c.Put(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored blob under its own key.
	path := filepath.Join(dir, "sha256", obj.Key[:2], obj.Key)
	if err := os.WriteFile(path, []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Full read: the mismatch surfaces at EOF.
	rc, got, err := c.Open(context.Background(), obj.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != int64(len("corrupted")) {
		t.Fatalf("size = %d", got.Size)
	}
	_, err = io.ReadAll(rc)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("full read of corrupted blob = %v, want ErrDigestMismatch", err)
	}
	_ = rc.Close()

	// Short read followed by Close: the mismatch must still surface.
	rc2, _, err := c.Open(context.Background(), obj.Key)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := rc2.Read(buf); err != nil {
		t.Fatalf("short read: %v", err)
	}
	if err := rc2.Close(); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("close after short read = %v, want ErrDigestMismatch", err)
	}
}

// TestCASOpenVerifiesDigestOnCleanRead proves clean content reads through
// the verifying reader unchanged.
func TestCASOpenVerifiesDigestOnCleanRead(t *testing.T) {
	c := New(blob.NewFS(t.TempDir()))
	data := []byte("clean content")
	obj, err := c.Put(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	rc, _, err := c.Open(context.Background(), obj.Key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(b, data) {
		t.Fatal("content mismatch")
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Closing without reading must also verify (and pass) — the digest is
	// computed over zero bytes, so only an empty object passes that way.
	h := sha256.Sum256(nil)
	emptyKey := hex.EncodeToString(h[:])
	if _, err := c.Put(context.Background(), bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	erc, _, err := c.Open(context.Background(), emptyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := erc.Close(); err != nil {
		t.Fatalf("close unread empty object: %v", err)
	}
}

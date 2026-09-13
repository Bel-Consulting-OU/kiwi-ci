package cas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/kiwici/kiwi/internal/blob"
)

func TestCASPutOpen(t *testing.T) {
	c := New(blob.NewFS(t.TempDir()))
	data := []byte("content addressed payload")
	obj, err := c.Put(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	if obj.Key != hex.EncodeToString(h[:]) {
		t.Fatalf("key mismatch: %s", obj.Key)
	}
	rc, got, err := c.Open(context.Background(), obj.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	if !bytes.Equal(b, data) {
		t.Fatal("content mismatch")
	}
	if got.Size != int64(len(data)) {
		t.Fatal("size mismatch")
	}
	if _, _, err := c.Open(context.Background(), "aabb"); err == nil {
		t.Fatal("expected invalid key rejection")
	}
}

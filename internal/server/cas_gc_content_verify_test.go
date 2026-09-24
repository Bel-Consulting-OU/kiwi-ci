package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

// casGCCorruptStore serves fixed bytes whose SHA-256 differs from the digest
// the garbage collector enumerated, simulating a backend replaced after
// publication.
type casGCCorruptStore struct{ body []byte }

func (s *casGCCorruptStore) Put(context.Context, string, io.Reader, int64) (blob.Object, error) {
	return blob.Object{}, nil
}
func (s *casGCCorruptStore) Open(context.Context, string) (io.ReadCloser, blob.Object, error) {
	return io.NopCloser(bytes.NewReader(s.body)), blob.Object{Size: int64(len(s.body))}, nil
}
func (s *casGCCorruptStore) Delete(context.Context, string) error { return nil }
func (s *casGCCorruptStore) List(context.Context, func(blob.Object) error) error {
	return nil
}

// TestCASGCContentReVerifySkipsReplacedObject pins the delete-after-restat
// close: an object whose CONTENT no longer matches the enumerated digest must
// never be unlinked, while a matching object verifies cleanly.
func TestCASGCContentReVerifySkipsReplacedObject(t *testing.T) {
	want := sha256.Sum256([]byte("original"))
	digest := hex.EncodeToString(want[:])

	corrupt := &casGCCorruptStore{body: []byte("replaced-after-publication")}
	if err := verifyCASObjectContent(context.Background(), corrupt, digest, digest, ""); err == nil {
		t.Fatal("replaced object verified; the unlink window is still open")
	}
	good := &casGCCorruptStore{body: []byte("original")}
	if err := verifyCASObjectContent(context.Background(), good, digest, digest, ""); err != nil {
		t.Fatalf("matching object refused: %v", err)
	}
	// An object whose digest cannot be established is skipped, never deleted.
	if err := verifyCASObjectContent(context.Background(), good, "opaque-key", "", ""); err == nil {
		t.Fatal("unverifiable object accepted for deletion")
	}
}

// Package cas provides a content-addressed object wrapper over a blob.Store.
// Objects are addressed by their SHA-256 digest; the store verifies integrity
// on both write and read.
package cas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/kiwici/kiwi/internal/blob"
)

type CAS struct {
	Blobs blob.Store
}

func New(b blob.Store) *CAS { return &CAS{Blobs: b} }

func (c *CAS) Put(ctx context.Context, r io.Reader) (blob.Object, error) {
	tmp, err := os.CreateTemp("", "kiwi-cas-*")
	if err != nil {
		return blob.Object{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		return blob.Object{}, err
	}
	key := hex.EncodeToString(h.Sum(nil))
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return blob.Object{}, err
	}
	obj, err := c.Blobs.Put(ctx, key, tmp, n)
	if err != nil {
		return blob.Object{}, err
	}
	return blob.Object{Key: key, SHA256: obj.SHA256, Size: n}, nil
}

func (c *CAS) Open(ctx context.Context, sha256hex string) (io.ReadCloser, blob.Object, error) {
	return c.Blobs.Open(ctx, sha256hex)
}

func (c *CAS) Delete(ctx context.Context, sha256hex string) error {
	return c.Blobs.Delete(ctx, sha256hex)
}

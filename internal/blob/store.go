// Package blob provides immutable content storage with a pluggable backend
// (filesystem, S3). A blob's physical identity is its SHA-256 digest:
// sha256/<first-2>/<full-digest>. Payloads can never be mutated in place.
package blob

import (
	"context"
	"errors"
	"io"
)

var ErrNotFound = errors.New("blob: not found")

type Object struct {
	Key    string
	SHA256 string
	Size   int64
}

type Store interface {
	Put(ctx context.Context, key string, r io.Reader, size int64) (Object, error)
	Open(ctx context.Context, key string) (io.ReadCloser, Object, error)
	Delete(ctx context.Context, key string) error
}

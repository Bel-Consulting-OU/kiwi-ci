// Package blob provides immutable content storage with a pluggable backend
// (filesystem, S3). A blob's physical identity is its SHA-256 digest:
// sha256/<first-2>/<full-digest>. Payloads can never be mutated in place.
package blob

import (
	"context"
	"errors"
	"io"
	"time"
)

var ErrNotFound = errors.New("blob: not found")

type Object struct {
	Key    string
	SHA256 string
	Size   int64
	// ModTime is the object's last-write time. Put and Open leave it zero;
	// List populates it when the backend exposes one. Consumers must treat
	// a zero ModTime as "age unknown" and never make destructive decisions
	// from it.
	ModTime time.Time
}

type Store interface {
	Put(ctx context.Context, key string, r io.Reader, size int64) (Object, error)
	Open(ctx context.Context, key string) (io.ReadCloser, Object, error)
	Delete(ctx context.Context, key string) error
}

// Enumerator is the optional enumeration capability of a blob store. FS and
// S3 implement it; the reference-aware CAS garbage collector requires it and
// fails closed (collects nothing) for stores that do not. List calls fn once
// per stored object in an unspecified order, with Key, SHA256, Size and
// (when the backend reports it) ModTime populated.
//
// List returns ctx cancellation and any error returned by fn unchanged, so
// callers can abort a walk early with a sentinel. Staging files that are not
// content-addressed objects (for example the ".tmp" scratch files FS writes)
// are never reported.
type Enumerator interface {
	List(ctx context.Context, fn func(Object) error) error
}

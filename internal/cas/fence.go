// Package cas provides content-addressed storage over a blob.Store.
//
// Publication and garbage collection are serialized per digest by a Fencer:
// a writer holds the digest's fence across "publish object + commit durable
// reference", and the collector holds the same fence across "re-read
// references + delete". Without that mutual exclusion a collector that
// enumerated a long-dead digest could delete it after a concurrent writer
// re-published and referenced the very same digest, leaving durable metadata
// pointing at a missing blob.
package cas

import (
	"context"
	"sync"
)

// Fencer serializes publication and collection for one digest. WithFence
// runs fn while the fence is held; Acquire returns a release function for
// callers whose critical section cannot be expressed as one callback (an
// HTTP handler tail, for example). Release is idempotent.
type Fencer interface {
	WithFence(ctx context.Context, digest string, fn func() error) error
	Acquire(ctx context.Context, digest string) (release func(), err error)
}

// MemFencer is the in-process Fencer used by memory/fs deployments and by
// tests. DB-backed deployments use a Postgres advisory-lock fencer so the
// fence spans replicas.
//
// Entries are REFERENCE COUNTED: an entry is created on first use and
// removed only when no holder and no waiter remains. The table is never
// wholesale-reset — clearing it while a digest's mutex is held (or has
// waiters) would let a new operation for the same digest create a second
// mutex and enter concurrently, reopening the writer-versus-collector race
// the fence exists to eliminate. A long-running installation reaching any
// number of unique digests therefore cannot break mutual exclusion.
type MemFencer struct {
	mu   sync.Mutex
	keys map[string]*fenceEntry
	// maxKeys retains zero-refcount entries up to this many keys before
	// evicting idle ones (never held/waiting ones); tests shrink it.
	maxKeys int
}

type fenceEntry struct {
	mu      sync.Mutex
	refs    int // holders + waiters registered against this entry
	removed bool
}

func NewMemFencer() *MemFencer {
	return &MemFencer{keys: map[string]*fenceEntry{}, maxKeys: 4096}
}

// acquire locks the entry for digest and returns an idempotent release.
func (f *MemFencer) acquire(ctx context.Context, digest string) (*fenceEntry, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	e, ok := f.keys[digest]
	if !ok {
		e = &fenceEntry{}
		f.keys[digest] = e
	}
	e.refs++
	f.mu.Unlock()

	e.mu.Lock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			e.mu.Unlock()
			f.mu.Lock()
			e.refs--
			if e.refs == 0 && len(f.keys) > f.maxKeys {
				// Evict only genuinely idle entries, and only entries whose
				// mutex is not held: refs == 0 means no holder and no
				// waiter can be waiting on this entry, so deleting it
				// cannot race a future acquirer (which would take f.mu and
				// create a fresh entry while this one is unreferenced).
				if !e.removed {
					e.removed = true
					delete(f.keys, digest)
				}
			}
			f.mu.Unlock()
		})
	}
	return e, release, nil
}

func (f *MemFencer) Acquire(ctx context.Context, digest string) (func(), error) {
	_, release, err := f.acquire(ctx, digest)
	return release, err
}

func (f *MemFencer) WithFence(ctx context.Context, digest string, fn func() error) error {
	_, release, err := f.acquire(ctx, digest)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

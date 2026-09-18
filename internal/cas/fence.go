// Package cas provides content-addressed storage over a blob.Store.
//
// Publication and garbage collection are serialized per digest by a Fencer:
// a writer holds the digest's fence across "publish object + commit durable
// reference", and the collector holds the same fence across "re-read
// references + delete".
package cas

import (
	"context"
	"sync"
)

// Fencer serializes publication and collection for one digest. WithFence
// runs fn while the fence is held; Acquire returns a release function for
// callers whose critical section cannot be expressed as one callback. Both
// honor context cancellation while WAITING (a cancelled waiter removes its
// reference immediately).
type Fencer interface {
	WithFence(ctx context.Context, digest string, fn func() error) error
	Acquire(ctx context.Context, digest string) (release func(), err error)
}

// MemFencer is the in-process Fencer used by memory/fs deployments and by
// tests. Entries are REFERENCE COUNTED and evicted only when no holder and
// no waiter remains; the wait itself is a channel receive, so it is
// context-cancellable and a cancelled waiter cannot leave the entry pinned.
type MemFencer struct {
	mu      sync.Mutex
	keys    map[string]*fenceEntry
	maxKeys int
}

type fenceEntry struct {
	// token has capacity 1: a value in the channel means the fence is held.
	token chan struct{}
	refs  int
}

func NewMemFencer() *MemFencer {
	return &MemFencer{keys: map[string]*fenceEntry{}, maxKeys: 4096}
}

func (f *MemFencer) entryFor(digest string) *fenceEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.keys[digest]
	if !ok {
		e = &fenceEntry{token: make(chan struct{}, 1)}
		f.keys[digest] = e
	}
	e.refs++
	return e
}

func (f *MemFencer) releaseEntry(digest string, e *fenceEntry) {
	f.mu.Lock()
	e.refs--
	if e.refs == 0 && len(f.keys) > f.maxKeys {
		delete(f.keys, digest)
	}
	f.mu.Unlock()
}

func (f *MemFencer) Acquire(ctx context.Context, digest string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e := f.entryFor(digest)
	select {
	case e.token <- struct{}{}:
		// Acquired.
	case <-ctx.Done():
		// Remove our reference without ever holding the fence.
		f.releaseEntry(digest, e)
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-e.token
			f.releaseEntry(digest, e)
		})
	}, nil
}

func (f *MemFencer) WithFence(ctx context.Context, digest string, fn func() error) error {
	release, err := f.Acquire(ctx, digest)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

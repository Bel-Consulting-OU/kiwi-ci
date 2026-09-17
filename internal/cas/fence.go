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
type MemFencer struct {
	mu   sync.Mutex
	keys map[string]*sync.Mutex
}

func NewMemFencer() *MemFencer {
	return &MemFencer{keys: map[string]*sync.Mutex{}}
}

func (f *MemFencer) Acquire(ctx context.Context, digest string) (func(), error) {
	f.mu.Lock()
	m, ok := f.keys[digest]
	if !ok {
		m = &sync.Mutex{}
		f.keys[digest] = m
	}
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.Unlock()
			f.mu.Lock()
			if len(f.keys) > 4096 {
				f.keys = map[string]*sync.Mutex{}
			}
			f.mu.Unlock()
		})
	}, nil
}

func (f *MemFencer) WithFence(ctx context.Context, digest string, fn func() error) error {
	f.mu.Lock()
	m, ok := f.keys[digest]
	if !ok {
		m = &sync.Mutex{}
		f.keys[digest] = m
	}
	f.mu.Unlock()

	m.Lock()
	defer func() {
		m.Unlock()
		// Drop the entry once nobody else can hold it, so the map does not
		// grow without bound across a long-lived process.
		f.mu.Lock()
		if len(f.keys) > 4096 {
			f.keys = map[string]*sync.Mutex{}
		}
		f.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}

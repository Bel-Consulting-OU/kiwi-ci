// Package tui provides the operator terminal UI: a bounded-memory log/job
// viewer with search, step collapsing, job filtering, and jump-to-failure.
package tui

import "sync"

// Ring is a fixed-capacity ring buffer safe for concurrent use: the follow
// goroutine appends while the renderer reads Slice/Len/Get. A 10-hour build
// must not consume unbounded client memory, so appends past capacity evict
// the oldest entry.
type Ring[T any] struct {
	mu    sync.Mutex
	buf   []T
	head  int
	count int
}

func NewRing[T any](capacity int) *Ring[T] {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring[T]{buf: make([]T, capacity)}
}

func (r *Ring[T]) Append(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return
	}
	if r.count == len(r.buf) {
		r.buf[r.head] = v
		r.head = (r.head + 1) % len(r.buf)
		return
	}
	idx := (r.head + r.count) % len(r.buf)
	r.buf[idx] = v
	r.count++
}

func (r *Ring[T]) Get(i int) (T, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.get(i)
}

// get is the lock-free body of Get; callers must hold r.mu.
func (r *Ring[T]) get(i int) (T, bool) {
	var zero T
	if i < 0 || i >= r.count || len(r.buf) == 0 {
		return zero, false
	}
	return r.buf[(r.head+i)%len(r.buf)], true
}

func (r *Ring[T]) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

func (r *Ring[T]) Capacity() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}

// Reset drops every buffered entry.
func (r *Ring[T]) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.head = 0
	r.count = 0
	var zero T
	for i := range r.buf {
		r.buf[i] = zero
	}
}

// Slice returns a copy of the buffered entries from oldest to newest.
func (r *Ring[T]) Slice() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]T, 0, r.count)
	for i := 0; i < r.count; i++ {
		v, _ := r.get(i)
		out = append(out, v)
	}
	return out
}

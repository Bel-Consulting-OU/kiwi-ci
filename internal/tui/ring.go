// Package tui provides the operator terminal UI: a bounded-memory log/job
// viewer with search, step collapsing, job filtering, and jump-to-failure.
package tui

// Ring is a fixed-capacity ring buffer. A 10-hour build must not consume
// unbounded client memory, so appends past capacity evict the oldest entry.
type Ring[T any] struct {
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
	var zero T
	if i < 0 || i >= r.count {
		return zero, false
	}
	return r.buf[(r.head+i)%len(r.buf)], true
}

func (r *Ring[T]) Len() int { return r.count }

func (r *Ring[T]) Capacity() int { return len(r.buf) }

// Reset drops every buffered entry.
func (r *Ring[T]) Reset() {
	r.head = 0
	r.count = 0
	var zero T
	for i := range r.buf {
		r.buf[i] = zero
	}
}

// Slice returns the buffered entries from oldest to newest.
func (r *Ring[T]) Slice() []T {
	out := make([]T, 0, r.count)
	for i := 0; i < r.count; i++ {
		v, _ := r.Get(i)
		out = append(out, v)
	}
	return out
}

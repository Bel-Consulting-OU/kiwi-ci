package tui

import (
	"fmt"
	"sync"
	"testing"
)

// TestRingConcurrentAppendAndSlice is the regression test for the production
// data race: the follow goroutine appends while the renderer calls Slice,
// Len, Get, Capacity and renderFrame. Run with -race.
func TestRingConcurrentAppendAndSlice(t *testing.T) {
	r := NewRing[string](64)
	const iters = 4000
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			r.Append(fmt.Sprintf("build > step | line-%d", i))
		}
	}()
	for rd := 0; rd < 4; rd++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collapsed := map[string]bool{}
			for i := 0; i < iters; i++ {
				s := r.Slice()
				for j := range s {
					if _, ok := r.Get(j); !ok {
						t.Errorf("Get(%d) missing for %d entries", j, len(s))
						return
					}
				}
				_ = renderFrame(s, len(s)-1, collapsed, findMatches(s, "line-1"), 30, 132)
				_ = r.Len()
				_ = r.Capacity()
			}
		}()
	}
	wg.Wait()
	got := r.Slice()
	if len(got) != 64 {
		t.Fatalf("slice = %d entries, want 64", len(got))
	}
	for i, v := range got {
		if want := fmt.Sprintf("build > step | line-%d", iters-64+i); v != want {
			t.Fatalf("got[%d] = %q, want %q (ring eviction order broken)", i, v, want)
		}
	}
}

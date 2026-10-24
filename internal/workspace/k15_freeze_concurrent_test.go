package workspace

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentFreezeSameBase(t *testing.T) {
	src := t.TempDir()
	writeK15(t, filepath.Join(src, "a.txt"), "x")
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = m.Freeze(context.Background())
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("freeze %d: %v", i, err)
		}
	}
	if m.BasePath() == "" {
		t.Fatal("no base after concurrent freeze")
	}
}

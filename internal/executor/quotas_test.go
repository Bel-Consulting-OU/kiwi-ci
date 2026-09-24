package executor

import (
	"context"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestLimitedSinkStopsAfterMax(t *testing.T) {
	var mu sync.Mutex
	var got []string
	inner := logging.Func(func(job, step, line string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, step+":"+line)
	})
	s := limitedSink(inner, 10)
	s.WriteLine("j", "a", "hello") // 5 bytes, forwarded
	s.WriteLine("j", "a", "hello") // 10 bytes total, still within quota
	s.WriteLine("j", "a", "x")     // would exceed: dropped, marker emitted
	s.WriteLine("j", "a", "world") // dropped, no second marker
	mu.Lock()
	defer mu.Unlock()
	want := []string{"a:hello", "a:hello", "a:log quota exceeded"}
	if len(got) != len(want) {
		t.Fatalf("forwarded lines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestLimitedSinkZeroIsUnlimited(t *testing.T) {
	var mu sync.Mutex
	var got []string
	inner := logging.Func(func(job, step, line string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, line)
	})
	s := limitedSink(inner, 0)
	for i := 0; i < 100; i++ {
		s.WriteLine("j", "s", strings.Repeat("x", 10))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 100 {
		t.Fatalf("forwarded %d lines, want 100", len(got))
	}
	for _, l := range got {
		if l == "log quota exceeded" {
			t.Fatal("unlimited sink emitted a quota marker")
		}
	}
}

func TestQuotaSinkNilInner(t *testing.T) {
	// A quota sink without an inner sink must still account bytes and drop
	// over-quota lines without panicking. The nil inner sink removes every
	// observable forward, so the assertions track the accounting side of the
	// drop path: a no-op WriteLine leaves `used` at zero and fails.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil-inner quota sink panicked: %v", r)
		}
	}()
	s := &quotaSink{max: 10}
	s.WriteLine("j", "s", "hello")
	if got := s.used.Load(); got != 5 {
		t.Fatalf("used after first in-quota line = %d, want 5", got)
	}
	s.WriteLine("j", "s", "world")
	if got := s.used.Load(); got != 10 {
		t.Fatalf("used after quota-filling line = %d, want 10", got)
	}
	// Over-quota lines are charged and dropped; the terminal marker cannot be
	// forwarded (nil inner) so it must be suppressed without panicking.
	s.WriteLine("j", "s", strings.Repeat("x", 100))
	if got := s.used.Load(); got != 110 {
		t.Fatalf("used after dropped line = %d, want 110 (dropped lines are still charged)", got)
	}
	s.WriteLine("j", "s", "y")
	if got := s.used.Load(); got != 111 {
		t.Fatalf("used after a second dropped line = %d, want 111", got)
	}
}

func TestLimitedSinkConcurrentSingleMarker(t *testing.T) {
	var mu sync.Mutex
	markers := 0
	inner := logging.Func(func(job, step, line string) {
		if line == "log quota exceeded" {
			mu.Lock()
			markers++
			mu.Unlock()
		}
	})
	s := limitedSink(inner, 1)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.WriteLine("j", "s", strings.Repeat("x", 1+n%7))
		}(i)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if markers != 1 {
		t.Fatalf("marker emitted %d times, want exactly once", markers)
	}
}

func TestWorkspaceQuotaInsufficientFailsBeforeExecution(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - run: echo ran > ran.txt
`)
	// A quota far beyond any real filesystem guarantees FitsAvailable
	// reports insufficient free space.
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1, WorkspaceMaxBytes: math.MaxInt64}}
	res, _ := ex.Run(context.Background(), g)
	r := res["j"]
	if r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure (error: %s)", r.Status, r.Error)
	}
	if !strings.Contains(r.Error, "infra") || !strings.Contains(r.Error, "workspace quota") {
		t.Fatalf("job error = %q, want an infra workspace-quota error", r.Error)
	}
	assertFile(t, filepath.Join(ws, "ran.txt"), "step output", false)
}

func TestWorkspaceQuotaZeroMeansUnlimited(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - run: echo ran > ran.txt
`)
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	assertFile(t, filepath.Join(ws, "ran.txt"), "step output", true)
}

func TestLogQuotaThroughExecutor(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - run: |
          echo line-one
          echo line-two
          echo line-three
`)
	var mu sync.Mutex
	var lines []string
	sink := logging.Func(func(job, step, line string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, line)
	})
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1, Logs: sink, LogMaxBytes: 16}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	markers := 0
	var total int64
	for _, l := range lines {
		if l == "log quota exceeded" {
			markers++
			continue
		}
		total += int64(len(l))
	}
	if markers != 1 {
		t.Fatalf("quota marker emitted %d times, want exactly once (lines: %v)", markers, lines)
	}
	if total > 16 {
		t.Fatalf("forwarded %d bytes, exceeds the 16-byte quota (lines: %v)", total, lines)
	}
}

func TestLogQuotaZeroUnlimitedThroughExecutor(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - run: echo hello-quota
`)
	var mu sync.Mutex
	var lines []string
	sink := logging.Func(func(job, step, line string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, line)
	})
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1, Logs: sink}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, l := range lines {
		if l == "hello-quota" {
			found = true
		}
		if l == "log quota exceeded" {
			t.Fatal("zero quota emitted a marker")
		}
	}
	if !found {
		t.Fatalf("step output missing from logs (lines: %v)", lines)
	}
}

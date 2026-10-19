package executor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type failingLifecycle struct{ closeErr error }

func (f *failingLifecycle) Name() string { return "fake" }
func (f *failingLifecycle) Run(context.Context, Command, func(string)) error {
	return errors.New("docker daemon gone")
}
func (f *failingLifecycle) ReadFile(context.Context, string, int64) ([]byte, error) {
	return nil, errors.New("no file")
}
func (f *failingLifecycle) StartJob(context.Context, string, func(string)) error {
	return errors.New("docker daemon gone")
}
func (f *failingLifecycle) CloseJob() error { return f.closeErr }

type syncSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *syncSink) WriteLine(job, step, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, step+": "+line)
}

// TestCleanupWarningSuppressedAfterFirst: K10 — a daemon outage that makes
// both StartJob and CloseJob fail must emit ONE cleanup warning, not a pile.
func TestCleanupWarningSuppressedAfterFirst(t *testing.T) {
	sink := &syncSink{}
	fake := &failingLifecycle{closeErr: errors.New("daemon gone")}
	orig := backendForNetwork
	backendForNetwork = func(string, string, string, string) (Backend, error) {
		return fake, nil
	}
	t.Cleanup(func() { backendForNetwork = orig })

	g := envProbeSpec(nativeScript("          echo hi\n", "          echo hi\n"))
	ex := Executor{Opt: Options{Workspace: t.TempDir(), Logs: sink}}
	_, _ = ex.Run(context.Background(), g)

	var warns int
	for _, l := range sink.lines {
		if strings.Contains(l, "cleanup warning") {
			warns++
		}
	}
	if warns != 1 {
		t.Fatalf("cleanup warnings = %d, want 1:\n%s", warns, strings.Join(sink.lines, "\n"))
	}
}

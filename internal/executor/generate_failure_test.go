package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// generateSink collects every log line for the generate step.
type generateSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *generateSink) WriteLine(_, _, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
}

func (s *generateSink) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

// compileGenerateJob compiles a single-job pipeline that declares
// generate.path and pre-creates the fragment file in the workspace (the
// execution backend reads it through the live session after the steps ran).
func compileGenerateJob(t *testing.T, ws, optional string) pipeline.CompiledJob {
	t.Helper()
	doc := `version: 1
jobs:
  gen:
    generate:
      path: fragment.json
` + optional + `    steps:
      - run: echo ok > ran.txt
`
	spec, err := pipeline.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "fragment.json"), []byte(`{"jobs":{"child-a":{"steps":[{"run":"echo child"}]}},"deps":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var cj pipeline.CompiledJob
	for _, c := range g.Jobs {
		cj = c
	}
	return cj
}

// TestGenerateUploadFailureFailsJobByDefault pins HIGH-12: when a job
// declares generate.path without generate.optional, a rejected fragment
// upload (server rejection, non-2xx, network failure) fails the job with a
// clear "generated graph rejected" error instead of a silent warning.
func TestGenerateUploadFailureFailsJobByDefault(t *testing.T) {
	ws := t.TempDir()
	cj := compileGenerateJob(t, ws, "")
	sink := &generateSink{}
	var calls int
	ex := Executor{Opt: Options{
		Workspace: ws, MaxParallel: 1, Logs: sink,
		GenerateUpload: func(jobID, path string, data []byte) error {
			calls++
			if jobID != cj.ID || path != "fragment.json" || len(data) == 0 {
				t.Errorf("hook args = %q/%q/%d bytes", jobID, path, len(data))
			}
			return errors.New("generated fragment upload: 400 Bad Request: depth")
		},
	}}
	res := ex.RunCompiledJob(context.Background(), &pipeline.Spec{Version: 1}, cj)
	if res.Status != model.StatusFailure {
		t.Fatalf("status = %s, want failure (error: %s)", res.Status, res.Error)
	}
	if calls != 1 {
		t.Fatalf("GenerateUpload calls = %d, want 1", calls)
	}
	if !strings.Contains(res.Error, "generated graph rejected") {
		t.Fatalf("job error = %q, want it to mention the rejected generated graph", res.Error)
	}
	if !strings.Contains(res.Error, "400 Bad Request") {
		t.Fatalf("job error = %q, want the underlying upload error", res.Error)
	}
}

// TestGenerateUploadFailureOptionalSucceeds pins the opt-out: with
// generate.optional=true the same rejection stays a warning and the job
// succeeds with the step's side effects intact.
func TestGenerateUploadFailureOptionalSucceeds(t *testing.T) {
	ws := t.TempDir()
	cj := compileGenerateJob(t, ws, "      optional: true\n")
	sink := &generateSink{}
	ex := Executor{Opt: Options{
		Workspace: ws, MaxParallel: 1, Logs: sink,
		GenerateUpload: func(string, string, []byte) error {
			return errors.New("403 policy rejected the fragment")
		},
	}}
	res := ex.RunCompiledJob(context.Background(), &pipeline.Spec{Version: 1}, cj)
	if res.Status != model.StatusSuccess {
		t.Fatalf("status = %s, want success (error: %s)", res.Status, res.Error)
	}
	if _, err := os.Stat(filepath.Join(ws, "ran.txt")); err != nil {
		t.Fatal("steps did not run")
	}
	var warned bool
	for _, line := range sink.messages() {
		if strings.Contains(line, "warning") && strings.Contains(line, "generate.optional=true") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("optional rejection was not logged as a warning: %v", sink.messages())
	}
}

// TestGenerateUploadSuccessDefault: a successful upload keeps the job
// succeeding and never logs a rejection.
func TestGenerateUploadSuccessDefault(t *testing.T) {
	ws := t.TempDir()
	cj := compileGenerateJob(t, ws, "")
	sink := &generateSink{}
	ex := Executor{Opt: Options{
		Workspace: ws, MaxParallel: 1, Logs: sink,
		GenerateUpload: func(string, string, []byte) error { return nil },
	}}
	res := ex.RunCompiledJob(context.Background(), &pipeline.Spec{Version: 1}, cj)
	if res.Status != model.StatusSuccess {
		t.Fatalf("status = %s, want success (error: %s)", res.Status, res.Error)
	}
	for _, line := range sink.messages() {
		if strings.Contains(line, "rejected") || strings.Contains(line, "warning") {
			t.Fatalf("successful upload logged a rejection warning: %v", sink.messages())
		}
	}
}

// TestGenerateUploadNotCalledWithoutPath pins the unchanged path: a job
// without generate.path never invokes the upload hook.
func TestGenerateUploadNotCalledWithoutPath(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  plain:
    steps:
      - run: echo ok > plain.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var cj pipeline.CompiledJob
	for _, c := range g.Jobs {
		cj = c
	}
	ex := Executor{Opt: Options{
		Workspace: ws, MaxParallel: 1, Logs: logging.Func(func(_, _, _ string) {}),
		GenerateUpload: func(string, string, []byte) error {
			t.Error("GenerateUpload called for a job without generate.path")
			return nil
		},
	}}
	res := ex.RunCompiledJob(context.Background(), g.Spec, cj)
	if res.Status != model.StatusSuccess {
		t.Fatalf("status = %s, want success (error: %s)", res.Status, res.Error)
	}
}

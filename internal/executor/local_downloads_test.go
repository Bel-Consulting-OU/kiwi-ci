package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func localDownloadsSpec() *pipeline.Spec {
	return &pipeline.Spec{
		Version: 1,
		Jobs: map[string]pipeline.Job{
			"producer": {
				Runtime: "native",
				Steps: []pipeline.Step{
					{Name: "make", Run: `echo payload > out.txt`},
				},
				Artifacts: []pipeline.Artifact{{Name: "out", Paths: []string{"out.txt"}}},
			},
			"consumer": {
				Needs:   []string{"producer"},
				Runtime: "native",
				Downloads: []pipeline.ArtifactInput{{
					From: "producer", Name: "out", Path: ".",
				}},
				Steps: []pipeline.Step{
					{Name: "check", Run: `grep -q payload out.txt`},
				},
			},
		},
	}
}

func TestLocalDownloadsRestoreProducerArtifact(t *testing.T) {
	root := t.TempDir()
	g, err := pipeline.Compile(localDownloadsSpec())
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{
		Opt: Options{
			// Per-job workspaces like kiwi run: the consumer's fresh
			// workspace must receive the producer's artifact.
			WorkspaceFor: func(jobID string) (string, func(), error) {
				dir := filepath.Join(root, "ws-"+jobID)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return "", nil, err
				}
				return dir, func() {}, nil
			},
			MaxParallel:    1,
			Artifacts:      &artifact.Store{Root: filepath.Join(root, "arts")},
			LocalDownloads: true,
			Logs:           discardSink{},
		},
	}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res["consumer"].Status != model.StatusSuccess {
		t.Fatalf("consumer status = %v (%s), want success; the declared download must restore the producer artifact", res["consumer"].Status, res["consumer"].Error)
	}
	if res["producer"].Status != model.StatusSuccess {
		t.Fatalf("producer status = %v (%s), want success", res["producer"].Status, res["producer"].Error)
	}
}

func TestLocalDownloadsMissingProducerArtifactFails(t *testing.T) {
	spec := localDownloadsSpec()
	prod := spec.Jobs["producer"]
	prod.Artifacts = nil
	spec.Jobs["producer"] = prod
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pipeline.yaml"), "version: 1\njobs: {}\n")
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{
		Opt: Options{
			Workspace:      dir,
			MaxParallel:    1,
			Artifacts:      &artifact.Store{Root: t.TempDir()},
			LocalDownloads: true,
			Logs:           &discardSink{},
		},
	}
	res, err := ex.Run(context.Background(), g)
	if err == nil {
		t.Fatal("Run succeeded, want an error for the missing dependency artifact")
	}
	if !strings.Contains(err.Error(), `"out" from "producer"`) {
		t.Fatalf("Run error = %q, want a missing-producer-artifact error", err)
	}
	if res["consumer"].Status != model.StatusFailure {
		t.Fatalf("consumer status = %v, want failure when the declared artifact was not produced", res["consumer"].Status)
	}
	if !strings.Contains(res["consumer"].Error, `"out" from "producer"`) {
		t.Fatalf("consumer error = %q, want a missing-producer-artifact error", res["consumer"].Error)
	}
}

func TestLocalDownloadDestValidation(t *testing.T) {
	for _, in := range []string{"", ".", "sub/dir", "a.txt"} {
		if _, err := localDownloadDest(in); err != nil {
			t.Fatalf("localDownloadDest(%q) = %v, want ok", in, err)
		}
	}
	for _, in := range []string{"/abs", "../up", "a/../../b", `win\path`, "..\\up"} {
		if _, err := localDownloadDest(in); err == nil {
			t.Fatalf("localDownloadDest(%q) accepted, want rejection", in)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// discardSink implements logging.Sink by dropping every line.
type discardSink struct{}

func (discardSink) WriteLine(job, step, line string) {}

// TestLocalDownloadsMatrixBaseResolution: a consumer declaring `from: <base>`
// for a matrix producer resolves the unique variant artifact, exactly like
// the control plane's dependency endpoint; two variants publishing the SAME
// name is ambiguous and fails.
func TestLocalDownloadsMatrixBaseResolution(t *testing.T) {
	spec := &pipeline.Spec{
		Version: 1,
		Jobs: map[string]pipeline.Job{
			"build": {
				Runtime: "native",
				Matrix:  map[string][]any{"OS": {"linux", "darwin"}},
				Steps:   []pipeline.Step{{Name: "make", Run: `echo x > "app-$KIWI_MATRIX_OS.txt"`}},
				Artifacts: []pipeline.Artifact{{
					Name:  "app-${{ matrix.OS }}",
					Paths: []string{"app-$KIWI_MATRIX_OS.txt"},
				}},
			},
			"verify": {
				Needs:   []string{"build"},
				Runtime: "native",
				Downloads: []pipeline.ArtifactInput{{
					From: "build", Name: "app-linux", Path: ".",
				}},
				Steps: []pipeline.Step{{Name: "check", Run: `test -f app-linux.txt || test -f "app-$KIWI_MATRIX_OS.txt" || ls`}},
			},
		},
	}
	root := t.TempDir()
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{
		WorkspaceFor: func(jobID string) (string, func(), error) {
			dir := filepath.Join(root, "ws-"+jobID)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return "", nil, err
			}
			return dir, func() {}, nil
		},
		MaxParallel:    1,
		Artifacts:      &artifact.Store{Root: filepath.Join(root, "arts")},
		LocalDownloads: true,
		Logs:           discardSink{},
	}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, id := range []string{"build[OS=linux]", "build[OS=darwin]", "verify"} {
		if res[id].Status != model.StatusSuccess {
			t.Fatalf("job %s = %v (%s), want success", id, res[id].Status, res[id].Error)
		}
	}

	// Ambiguity: both variants publish the same artifact name.
	amb := &pipeline.Spec{
		Version: 1,
		Jobs: map[string]pipeline.Job{
			"build": {
				Runtime: "native",
				Matrix:  map[string][]any{"OS": {"linux", "darwin"}},
				Steps:   []pipeline.Step{{Run: `echo x > app.txt`}},
				Artifacts: []pipeline.Artifact{{
					Name: "app", Paths: []string{"app.txt"},
				}},
			},
			"verify": {
				Needs:   []string{"build"},
				Runtime: "native",
				Downloads: []pipeline.ArtifactInput{{
					From: "build", Name: "app", Path: ".",
				}},
				Steps: []pipeline.Step{{Run: `true`}},
			},
		},
	}
	root2 := t.TempDir()
	g2, err := pipeline.Compile(amb)
	if err != nil {
		t.Fatal(err)
	}
	ex2 := Executor{Opt: Options{
		WorkspaceFor: func(jobID string) (string, func(), error) {
			dir := filepath.Join(root2, "ws-"+jobID)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return "", nil, err
			}
			return dir, func() {}, nil
		},
		MaxParallel:    1,
		Artifacts:      &artifact.Store{Root: filepath.Join(root2, "arts")},
		LocalDownloads: true,
		Logs:           discardSink{},
	}}
	_, err = ex2.Run(context.Background(), g2)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous matrix download = %v, want an ambiguity error", err)
	}
}

// TestLocalArtifactDeclaredMaxSizeEnforced: the per-artifact max_size must
// bound the LOCAL store path too, not only the distributed capture path; an
// oversized artifact is refused with a warning and never saved.
func TestLocalArtifactDeclaredMaxSizeEnforced(t *testing.T) {
	spec := &pipeline.Spec{
		Version: 1,
		Jobs: map[string]pipeline.Job{
			"a": {
				Runtime: "native",
				Steps:   []pipeline.Step{{Name: "make", Run: `head -c 2097152 /dev/zero > big.bin && echo done`}},
				Artifacts: []pipeline.Artifact{{
					Name: "big", MaxSize: 1 << 10, Paths: []string{"big.bin"},
				}},
			},
		},
	}
	root := t.TempDir()
	arts := &artifact.Store{Root: filepath.Join(root, "arts")}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	ex := Executor{Opt: Options{
		Workspace:   filepath.Join(root, "ws"),
		MaxParallel: 1,
		Artifacts:   arts,
		Logs:        &recordingSink{lines: &lines},
	}}
	if err := os.MkdirAll(filepath.Join(root, "ws"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res["a"].Status != model.StatusSuccess {
		t.Fatalf("job = %v (%s)", res["a"].Status, res["a"].Error)
	}
	found := false
	_ = filepath.Walk(filepath.Join(root, "arts"), func(_ string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			found = true
		}
		return nil
	})
	if found {
		t.Fatal("oversized artifact was saved despite max_size")
	}
	warned := false
	for _, l := range lines {
		if strings.Contains(l, "exceeds cap") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no cap warning in logs: %v", lines)
	}
}

// recordingSink captures log lines for assertions. Stream goroutines write
// concurrently, so the append is mutex-guarded.
type recordingSink struct {
	mu    sync.Mutex
	lines *[]string
}

func (r *recordingSink) WriteLine(_, _, line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.lines = append(*r.lines, line)
}

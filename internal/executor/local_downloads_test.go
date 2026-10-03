package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

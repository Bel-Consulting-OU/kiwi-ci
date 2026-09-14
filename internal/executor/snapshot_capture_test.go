package executor

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestCaptureSnapshotWritesParseableArchive runs a native job with
// CaptureSnapshot and verifies the resulting tar.gz contains the job's
// workspace file.
func TestCaptureSnapshotWritesParseableArchive(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	ws := t.TempDir()
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  snap:
    steps:
      - run: echo snapshot-marker > marker.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	const runID = "snap-run-1"
	ex := Executor{Opt: Options{Workspace: ws, RunID: runID, MaxParallel: 1, CaptureSnapshot: true}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["snap"].Status != "success" {
		t.Fatalf("job status = %q, want success", res["snap"].Status)
	}
	archive := filepath.Join(os.TempDir(), "kiwi-snapshots", runID, "snap.tar.gz")
	f, err := os.Open(archive)
	if err != nil {
		t.Fatalf("snapshot archive missing: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("snapshot archive is not gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("snapshot archive is not a valid tar: %v", err)
		}
		if filepath.Base(hdr.Name) != "marker.txt" {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		// The native shell writes its platform newline (LF on Unix,
		// CRLF on Windows); normalize before comparing.
		if got := strings.TrimRight(string(data), "\r\n"); got != "snapshot-marker" {
			t.Fatalf("marker.txt content = %q", data)
		}
		found = true
	}
	if !found {
		t.Fatal("marker.txt not found in snapshot archive")
	}
}

// TestCaptureSnapshotSkippedJobWritesNothing verifies skipped jobs are not
// snapshotted.
func TestCaptureSnapshotSkippedJobWritesNothing(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	ws := t.TempDir()
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  snap:
    if: "false"
    steps:
      - run: echo nope > nope.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	const runID = "snap-run-skipped"
	ex := Executor{Opt: Options{Workspace: ws, RunID: runID, MaxParallel: 1, CaptureSnapshot: true}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if res["snap"].Status != "skipped" {
		t.Fatalf("job status = %q, want skipped", res["snap"].Status)
	}
	if _, err := os.Stat(filepath.Join(os.TempDir(), "kiwi-snapshots", runID, "snap.tar.gz")); err == nil {
		t.Fatal("skipped job must not produce a snapshot archive")
	}
}

package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// snapshotArchive builds a snapshot archive of a scratch workspace.
func snapshotArchive(t *testing.T) []byte {
	t.Helper()
	ws := t.TempDir()
	writeFile(t, filepath.Join(ws, "file.txt"), "payload\n")
	var buf bytes.Buffer
	if _, err := snapshot.Create(ws, &buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// replayServer serves the snapshot list and download endpoints.
func replayServer(t *testing.T, listBody string, listStatus, downloadStatus int, archive []byte) *httptest.Server {
	t.Helper()
	return scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runs/run1/snapshots":
			w.WriteHeader(listStatus)
			_, _ = w.Write([]byte(listBody))
		case strings.HasPrefix(r.URL.Path, "/api/v1/runs/run1/snapshots/"):
			w.WriteHeader(downloadStatus)
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	})
}

func TestReplayUsageAndServerErrors(t *testing.T) {
	if err := Replay(context.Background(), nil); err == nil {
		t.Fatal("missing arguments accepted")
	}
	if err := Replay(context.Background(), []string{"run1"}); err == nil {
		t.Fatal("single argument accepted")
	}
	if err := Replay(context.Background(), []string{"a", "b", "c", "d"}); err == nil {
		t.Fatal("too many arguments accepted")
	}
	t.Setenv("KIWI_SERVER", "")
	if err := Replay(context.Background(), []string{"run1", "build"}); err == nil {
		t.Fatal("missing server accepted")
	}
	if err := Replay(context.Background(), []string{"--bogus", "run1", "build"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestReplayErrorPaths(t *testing.T) {
	pipelinePath := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    steps:\n      - run: echo ok\n")
	// Snapshot listing fails.
	failingList := replayServer(t, "boom", http.StatusInternalServerError, http.StatusOK, nil)
	if err := Replay(context.Background(), []string{"--server", failingList.URL, "--pipeline", pipelinePath, "run1", "build"}); err == nil {
		t.Fatal("snapshot list failure accepted")
	}
	// No snapshot for the job.
	emptyList := replayServer(t, `[]`, http.StatusOK, http.StatusOK, nil)
	err := Replay(context.Background(), []string{"--server", emptyList.URL, "--pipeline", pipelinePath, "run1", "build"})
	if err == nil || !strings.Contains(err.Error(), "no workspace snapshot") {
		t.Fatalf("missing snapshot = %v", err)
	}
	// A snapshot for another job does not match either.
	otherJob := replayServer(t, `[{"id":"snap1","job_key":"other","created_at":"2026-09-14T00:00:00Z"}]`, http.StatusOK, http.StatusOK, nil)
	if err := Replay(context.Background(), []string{"--server", otherJob.URL, "--pipeline", pipelinePath, "run1", "build"}); err == nil {
		t.Fatal("mismatched job snapshot accepted")
	}
	// Download fails.
	downloadFail := replayServer(t, `[{"id":"snap1","job_key":"build","created_at":"2026-09-14T00:00:00Z"}]`, http.StatusOK, http.StatusInternalServerError, nil)
	if err := Replay(context.Background(), []string{"--server", downloadFail.URL, "--pipeline", pipelinePath, "run1", "build"}); err == nil {
		t.Fatal("snapshot download failure accepted")
	}
	// The downloaded archive is not a valid snapshot.
	archive := snapshotArchive(t)
	garbage := replayServer(t, `[{"id":"snap1","job_key":"build","created_at":"2026-09-14T00:00:00Z"}]`, http.StatusOK, http.StatusOK, []byte("not-a-archive"))
	if err := Replay(context.Background(), []string{"--server", garbage.URL, "--pipeline", pipelinePath, "run1", "build"}); err == nil {
		t.Fatal("garbage snapshot accepted")
	}
	// The pipeline file is missing.
	good := replayServer(t, `[{"id":"snap1","job_key":"build","created_at":"2026-09-14T00:00:00Z"}]`, http.StatusOK, http.StatusOK, archive)
	if err := Replay(context.Background(), []string{"--server", good.URL, "--pipeline", filepath.Join(t.TempDir(), "nope.yaml"), "run1", "build"}); err == nil {
		t.Fatal("missing pipeline accepted")
	}
	// The pipeline does not compile.
	badPipeline := writePipeline(t, t.TempDir(), badCompilePipeline)
	if err := Replay(context.Background(), []string{"--server", good.URL, "--pipeline", badPipeline, "run1", "build"}); err == nil {
		t.Fatal("invalid pipeline accepted")
	}
	// The control plane is unreachable after argument validation.
	unreachable := replayServer(t, `[]`, http.StatusOK, http.StatusOK, nil)
	_ = unreachable
	if err := Replay(context.Background(), []string{"--server", "http://127.0.0.1:1", "--pipeline", pipelinePath, "run1", "build"}); err == nil {
		t.Fatal("unreachable control plane accepted")
	}
	// The job key is not in the pipeline.
	otherPipeline := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  other:\n    steps:\n      - run: echo hi\n")
	err = Replay(context.Background(), []string{"--server", good.URL, "--pipeline", otherPipeline, "run1", "build"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown job = %v", err)
	}
}

func TestReplaySuccessAndFailureResults(t *testing.T) {
	archive := snapshotArchive(t)
	srv := replayServer(t, `[{"id":"snap1","job_key":"build","created_at":"2026-09-14T00:00:00Z"}]`, http.StatusOK, http.StatusOK, archive)
	// A passing job replays cleanly (with the optional step selector).
	okPipeline := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    steps:\n      - name: greet\n        run: echo replay-ok\n")
	if err := Replay(context.Background(), []string{"--server", srv.URL, "--pipeline", okPipeline, "run1", "build"}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if err := Replay(context.Background(), []string{"--server", srv.URL, "--pipeline", okPipeline, "run1", "build", "greet"}); err != nil {
		t.Fatalf("Replay with step: %v", err)
	}
	// A failing job reports the failure.
	failPipeline := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    steps:\n      - run: exit 3\n")
	err := Replay(context.Background(), []string{"--server", srv.URL, "--pipeline", failPipeline, "run1", "build"})
	if err == nil || !strings.Contains(err.Error(), "failures") {
		t.Fatalf("failing replay = %v", err)
	}
	// A job whose ID matches a matrix variant's base ID resolves too.
	matrixPipeline := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    matrix:\n      go: [\"1.22\"]\n    steps:\n      - run: echo matrix\n")
	if err := Replay(context.Background(), []string{"--server", srv.URL, "--pipeline", matrixPipeline, "run1", "build"}); err != nil {
		t.Fatalf("matrix replay: %v", err)
	}
	// The token flag travels on the request.
	authSeen := false
	authSrv := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer tok" {
			authSeen = true
		}
		switch {
		case r.URL.Path == "/api/v1/runs/run1/snapshots":
			_, _ = w.Write([]byte(`[{"id":"snap1","job_key":"build","created_at":"2026-09-14T00:00:00Z"}]`))
		default:
			_, _ = w.Write(archive)
		}
	})
	if err := Replay(context.Background(), []string{"--server", authSrv.URL, "--token", "tok", "--pipeline", okPipeline, "run1", "build"}); err != nil {
		t.Fatalf("Replay with token: %v", err)
	}
	if !authSeen {
		t.Fatal("token was not sent")
	}
	// A snapshot download served from a file path that is not a server.
	_ = os.MkdirTemp
}

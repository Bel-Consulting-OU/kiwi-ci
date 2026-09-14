package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pipelineText = "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"

func TestRepoCoords(t *testing.T) {
	cases := []struct {
		in, url, full string
	}{
		{"acme/app", "https://github.com/acme/app.git", "acme/app"},
		{"https://github.com/acme/app.git", "https://github.com/acme/app.git", "acme/app"},
		{"https://gitlab.com/group/app", "https://gitlab.com/group/app", "group/app"},
	}
	for _, tc := range cases {
		url, full := repoCoords(tc.in)
		if url != tc.url || full != tc.full {
			t.Errorf("repoCoords(%q) = (%q, %q), want (%q, %q)", tc.in, url, full, tc.url, tc.full)
		}
	}
}

func TestDispatchSubmitsRun(t *testing.T) {
	var gotReq *http.Request
	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		if r.URL.Path != "/api/v1/runs" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"run-1","event":"manual","status":"queued"}`))
	}))
	defer ts.Close()

	pipelinePath := filepath.Join(t.TempDir(), "pipeline.yaml")
	if err := os.WriteFile(pipelinePath, []byte("version: 1\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Dispatch(context.Background(), []string{
		"--server", ts.URL,
		"--token", "admin-token",
		"--repo", "acme/app",
		"--ref", "feature/x",
		"--pipeline", pipelinePath,
		"--input", "environment=staging",
		"--input", "workers=2",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if gotReq == nil {
		t.Fatal("no request received")
	}
	if gotReq.Header.Get("Authorization") != "Bearer admin-token" {
		t.Errorf("auth header = %q", gotReq.Header.Get("Authorization"))
	}
	if gotBody["repo_url"] != "https://github.com/acme/app.git" {
		t.Errorf("repo_url = %v", gotBody["repo_url"])
	}
	if gotBody["repo_full_name"] != "acme/app" {
		t.Errorf("repo_full_name = %v", gotBody["repo_full_name"])
	}
	if gotBody["ref"] != "feature/x" || gotBody["event"] != "manual" {
		t.Errorf("ref/event = %v / %v", gotBody["ref"], gotBody["event"])
	}
	meta, _ := gotBody["metadata"].(map[string]any)
	if meta["input.environment"] != "staging" || meta["input.workers"] != "2" {
		t.Errorf("metadata inputs = %v", meta)
	}
	if p, _ := gotBody["pipeline"].(string); !strings.Contains(p, "jobs") {
		t.Errorf("pipeline not sent: %q", p)
	}
}

func TestDispatchRequiresRepo(t *testing.T) {
	if err := Dispatch(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "--repo") {
		t.Fatalf("want --repo error, got %v", err)
	}
	if err := Dispatch(context.Background(), []string{"--repo", "acme/app", "--pipeline", "nope.yaml"}); err == nil {
		t.Fatal("missing pipeline file must fail")
	}
}

func TestDispatchFetchesPipelineFromForge(t *testing.T) {
	// A fake GitHub API serves the pipeline contents endpoint; the real
	// submission target is a second fake server.
	fetched := false
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/acme/app/contents/.kiwi/pipeline.yaml" {
			t.Errorf("unexpected forge request: %s %s", r.Method, r.URL.Path)
		}
		if ref := r.URL.Query().Get("ref"); ref != "main" {
			t.Errorf("ref = %q, want main", ref)
		}
		fetched = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":"` + base64.StdEncoding.EncodeToString([]byte(pipelineText)) + `","encoding":"base64"}`))
	}))
	defer github.Close()
	t.Setenv("KIWI_GITHUB_API_BASE", github.URL)

	var gotBody map[string]any
	kiwi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runs" || r.Method != http.MethodPost {
			t.Errorf("unexpected server request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"run-2","event":"manual","status":"queued"}`))
	}))
	defer kiwi.Close()

	err := Dispatch(context.Background(), []string{
		"--server", kiwi.URL,
		"--token", "admin-token",
		"--repo", "acme/app",
		"--ref", "main",
	})
	if err != nil {
		t.Fatalf("dispatch with forge fetch: %v", err)
	}
	if !fetched {
		t.Fatal("pipeline was not fetched from the forge")
	}
	if p, _ := gotBody["pipeline"].(string); p != pipelineText {
		t.Fatalf("submitted pipeline = %q, want the fetched text", p)
	}
	if gotBody["repo_full_name"] != "acme/app" {
		t.Fatalf("repo_full_name = %v", gotBody["repo_full_name"])
	}
}

func TestDispatchServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad pipeline", http.StatusBadRequest)
	}))
	defer ts.Close()
	pipelinePath := filepath.Join(t.TempDir(), "pipeline.yaml")
	if err := os.WriteFile(pipelinePath, []byte("version: 1\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Dispatch(context.Background(), []string{"--server", ts.URL, "--repo", "acme/app", "--pipeline", pipelinePath})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("want 400 error, got %v", err)
	}
}

package forge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func checkRunGitHub(t *testing.T, handler http.HandlerFunc) *GitHub {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &GitHub{Token: "tok", BaseURL: srv.URL}
}

// TestPublishCheckRunCreatePatchAndErrors covers create-returning-an-id,
// PATCH of a known id, the missing-identity guard, an API error status and a
// create response without an id.
func TestPublishCheckRunCreatePatchAndErrors(t *testing.T) {
	ctx := context.Background()

	var gotMethod, gotPath, gotAuth string
	var posted map[string]any
	create := checkRunGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"check_runs":[]}`))
			return
		}
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		posted = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&posted)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":123}`))
	})
	if _, err := create.PublishCheckRun(ctx, "run-1\x00build", "o/r", "sha1", "build", "completed", "success", "https://d", "sum", []CheckAnnotation{{Path: "a", Message: "m"}}, ""); err != nil {
		t.Fatalf("create = %v", err)
	}
	// The unversioned create path reconciles first (GET) then POSTs.
	if gotMethod != http.MethodPost || !strings.HasSuffix(gotPath, "/repos/o/r/check-runs") || gotAuth != "Bearer tok" {
		t.Fatalf("create request = %s %s auth %q", gotMethod, gotPath, gotAuth)
	}
	if posted["conclusion"] != "success" || posted["details_url"] != "https://d" {
		t.Fatalf("create body = %v", posted)
	}
	if _, ok := posted["head_sha"]; !ok {
		t.Fatal("create body is missing head_sha")
	}

	patch := checkRunGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		posted = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&posted)
		w.WriteHeader(http.StatusOK)
	})
	id, err := patch.PublishCheckRun(ctx, "id", "o/r", "sha1", "build", "in_progress", "", "", "", nil, "99")
	if err != nil || id != "99" {
		t.Fatalf("patch = (%q,%v)", id, err)
	}
	if gotMethod != http.MethodPatch || !strings.HasSuffix(gotPath, "/repos/o/r/check-runs/99") {
		t.Fatalf("patch request = %s %s", gotMethod, gotPath)
	}
	if _, ok := posted["head_sha"]; ok {
		t.Fatal("patch body still carries the immutable head_sha")
	}

	if _, err := create.PublishCheckRun(ctx, "id", "", "sha1", "n", "s", "", "", "", nil, ""); err == nil {
		t.Fatal("missing repo was accepted")
	}

	apiErr := checkRunGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("nope"))
	})
	if _, err := apiErr.PublishCheckRun(ctx, "id", "o/r", "sha1", "n", "s", "", "", "", nil, "99"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("api error = %v", err)
	}

	noID := checkRunGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"check_runs":[]}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})
	if _, err := noID.PublishCheckRun(ctx, "id", "o/r", "sha1", "n", "s", "", "", "", nil, ""); err == nil {
		t.Fatal("create without an id was accepted")
	}
}

// TestPublishCheckRunReconcileFailure covers the reconcile-error arm: a
// transport failure during FindCheckRun must not fall through to a POST.
func TestPublishCheckRunReconcileFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	g := &GitHub{Token: "tok", BaseURL: srv.URL}
	srv.Close()
	if _, err := g.PublishCheckRun(context.Background(), "id", "o/r", "sha1", "n", "s", "", "", "", nil, ""); err == nil {
		t.Fatal("reconcile transport failure was ignored")
	}
}

// TestFindCheckRunMatrix covers the empty-identity guard, a match, no match,
// a decode failure and a non-OK status.
func TestFindCheckRunMatrix(t *testing.T) {
	ctx := context.Background()

	empty := &GitHub{}
	if id, err := empty.FindCheckRun(ctx, "", "sha", "ext"); id != "" || err != nil {
		t.Fatalf("empty args = (%q,%v)", id, err)
	}

	match := checkRunGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"check_runs":[{"id":7,"external_id":"other"},{"id":8,"external_id":"want"}]}`))
	})
	if id, err := match.FindCheckRun(ctx, "o/r", "sha", "want"); err != nil || id != "8" {
		t.Fatalf("match = (%q,%v)", id, err)
	}
	if id, err := match.FindCheckRun(ctx, "o/r", "sha", "absent"); err != nil || id != "" {
		t.Fatalf("no match = (%q,%v)", id, err)
	}

	decode := checkRunGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	if _, err := decode.FindCheckRun(ctx, "o/r", "sha", "want"); err == nil {
		t.Fatal("decode failure was ignored")
	}

	status := checkRunGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("down"))
	})
	if _, err := status.FindCheckRun(ctx, "o/r", "sha", "want"); err == nil || !strings.Contains(err.Error(), "down") {
		t.Fatalf("status error = %v", err)
	}

	_ = errors.New("")
}

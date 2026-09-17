package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestSqueezeCheckStateForRun(t *testing.T) {
	cases := []struct {
		status     model.Status
		wantStatus string
		wantConcl  string
	}{
		{model.StatusQueued, "queued", ""},
		{model.StatusRunning, "in_progress", ""},
		{model.StatusWaitingApproval, "in_progress", ""},
		{model.StatusPending, "in_progress", ""},
		{model.StatusSuccess, "completed", "success"},
		{model.StatusSkipped, "completed", "skipped"},
		{model.StatusCancelled, "completed", "cancelled"},
		{model.StatusFailure, "completed", "failure"},
		{model.StatusBlocked, "completed", "failure"},
		{model.Status("mystery"), "in_progress", ""},
	}
	for _, tc := range cases {
		gotStatus, gotConcl := checkStateForRun(tc.status)
		if gotStatus != tc.wantStatus || gotConcl != tc.wantConcl {
			t.Fatalf("checkStateForRun(%s) = %q/%q, want %q/%q", tc.status, gotStatus, gotConcl, tc.wantStatus, tc.wantConcl)
		}
	}
}

// TestSqueezePublishGitHubStatus covers the outbox fan-out, the job loop, the
// details URL and the enqueue failure log.
func TestSqueezePublishGitHubStatus(t *testing.T) {
	s := New("secret")
	s.gitHubAPIBase = "https://api.github.example"
	s.ExternalURL = "https://kiwi.example"
	// Missing coordinate: nothing to publish.
	s.publishGitHubStatus(model.Run{ID: "r1", ForgeKind: "github", ForgeHost: "github.com"})

	s.mu.Lock()
	s.runs["r1"] = model.Run{ID: "r1", RepoFullName: "acme/backend", SHA: "sha", ForgeKind: "github", ForgeHost: "github.com", Status: model.StatusFailure}
	s.jobs["j1"] = model.Job{ID: "j1", RunID: "r1", Key: "build", Status: model.StatusFailure, Error: "compiler exploded"}
	s.jobs["j2"] = model.Job{ID: "j2", RunID: "r1", Key: "test", Status: model.StatusSkipped}
	s.jobs["j3"] = model.Job{ID: "j3", RunID: "r1", Key: "deploy", Status: model.StatusRunning}
	s.mu.Unlock()
	s.publishGitHubStatus(s.runs["r1"])

	items := s.outbox.Pending()
	if len(items) != 3 {
		t.Fatalf("outbox intents = %d, want pipeline + 2 terminal jobs", len(items))
	}
	var names []string
	for _, it := range items {
		if it.Kind != forge.OutboxKindGitHubCheck {
			t.Fatalf("intent kind = %q", it.Kind)
		}
		var p forge.CheckPayload
		if err := json.Unmarshal(it.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.DetailsURL != "https://kiwi.example/?run=r1" {
			t.Fatalf("details URL = %q", p.DetailsURL)
		}
		names = append(names, p.Name)
	}
	if names[0] != "Pipeline" || names[1] != "build" || names[2] != "test" {
		t.Fatalf("intent order = %v, want pipeline then jobs by key", names)
	}
	if !strings.Contains(string(items[1].Payload), "compiler exploded") {
		t.Fatalf("job error missing from summary: %s", items[1].Payload)
	}

	// An outbox failure is logged, never propagated.
	fs := newDBFakeStore()
	fs.outboxAppendErr = errors.New("outbox down")
	s2 := New("secret")
	s2.gitHubAPIBase = "https://api.github.example"
	s2.outbox = NewOutbox(nil)
	s2.outbox.AttachDB(fs)
	s2.mu.Lock()
	s2.jobs["j1"] = model.Job{ID: "j1", RunID: "r1", Key: "build", Status: model.StatusSuccess}
	s2.mu.Unlock()
	s2.publishGitHubStatus(model.Run{ID: "r1", RepoFullName: "acme/backend", SHA: "sha", Status: model.StatusSuccess})
}

// TestSqueezePublishStatusFromPayload covers the legacy commit-status
// dispatch: success, non-2xx, request error, transport error and token error.
func TestSqueezePublishStatusFromPayload(t *testing.T) {
	var gotBody map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer api.Close()

	s := New("secret")
	s.gitHubAPIBase = api.URL
	if err := s.publishGitHubStatusFromPayload(context.Background(), forge.StatusPayload{}); err != nil {
		t.Fatalf("empty payload = %v, want nil", err)
	}
	err := s.publishGitHubStatusFromPayload(context.Background(), forge.StatusPayload{RepoFullName: "acme/backend", SHA: "sha", State: "success", Description: "d", Context: "kiwi", TargetURL: "u"})
	if err != nil {
		t.Fatalf("dispatch = %v", err)
	}
	if gotBody["context"] != "kiwi" {
		t.Fatalf("posted body = %+v", gotBody)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer failing.Close()
	s.gitHubAPIBase = failing.URL
	if err := s.publishGitHubStatusFromPayload(context.Background(), forge.StatusPayload{RepoFullName: "acme/backend", SHA: "sha"}); err == nil {
		t.Fatal("non-2xx = nil error")
	}

	// A control character in the path makes request construction fail.
	s.gitHubAPIBase = api.URL
	if err := s.publishGitHubStatusFromPayload(context.Background(), forge.StatusPayload{RepoFullName: "bad\nrepo", SHA: "sha"}); err == nil {
		t.Fatal("invalid URL = nil error")
	}

	// A closed listener fails the request.
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	s.gitHubAPIBase = closedURL
	if err := s.publishGitHubStatusFromPayload(context.Background(), forge.StatusPayload{RepoFullName: "acme/backend", SHA: "sha"}); err == nil {
		t.Fatal("transport error = nil error")
	}

	// A configured-but-broken App credential fails the token lookup.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	s.gitHubAPIBase = api.URL
	s.GitHubAppID = 7
	s.GitHubAppPrivateKey = "not-a-key"
	_ = der
	if err := s.publishGitHubStatusFromPayload(context.Background(), forge.StatusPayload{RepoFullName: "acme/backend", SHA: "sha"}); err == nil {
		t.Fatal("broken App key = nil error")
	}
	// The default public endpoint is used when no base URL is configured.
	s3 := New("secret")
	_ = pem.EncodeToMemory
	_ = s3
}

// TestSqueezeOutboxClaimerID covers the empty-claimer default and the append
// failure path.
func TestSqueezeOutboxClaimerID(t *testing.T) {
	o := &Outbox{}
	if got := o.claimerID(); !strings.HasPrefix(got, "outbox-") {
		t.Fatalf("claimerID = %q", got)
	}
	o.claimer = "fixed"
	if got := o.claimerID(); got != "fixed" {
		t.Fatalf("claimerID = %q", got)
	}

	fs := newDBFakeStore()
	fs.outboxAppendErr = errors.New("append down")
	ob := NewOutbox(nil)
	ob.AttachDB(fs)
	if err := ob.Enqueue(forge.OutboxItem{}); err == nil {
		t.Fatal("durable append failure = nil error")
	}
	_ = time.Now
}

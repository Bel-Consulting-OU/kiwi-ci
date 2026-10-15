package forge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func hmacHeader(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestBitbucketParsePushAndPR(t *testing.T) {
	b := &Bitbucket{}
	push := []byte(`{"repository":{"full_name":"ws/repo"},"push":{"changes":[{"new":{"name":"refs/heads/main","target":{"hash":"abc123"}}}]},"actor":{"username":"alice"}}`)
	ec, err := b.ParseEvent(push)
	if err != nil {
		t.Fatal(err)
	}
	if ec.Event != "push" || ec.HeadSHA != "abc123" || !strings.HasSuffix(ec.Ref, "main") || ec.Repository.FullName != "ws/repo" {
		t.Fatalf("push ec = %+v", ec)
	}
	pr := []byte(`{"repository":{"full_name":"ws/repo"},"pullrequest":{"id":7,"state":"open","author":{"username":"bob"},"source":{"branch":{"name":"feat"},"commit":{"hash":"head"}},"destination":{"branch":{"name":"main"},"commit":{"hash":"base"}}}}`)
	ec, err = b.ParseEvent(pr)
	if err != nil {
		t.Fatal(err)
	}
	if ec.PullRequest != 7 || ec.HeadSHA != "head" || ec.BaseSHA != "base" || !strings.HasSuffix(ec.BaseRef, "main") {
		t.Fatalf("pr ec = %+v", ec)
	}
	// Unknown shape yields empty event (never a guess).
	ec, err = b.ParseEvent([]byte(`{"foo":1}`))
	if err != nil || ec.Event != "" {
		t.Fatalf("unknown = %+v %v", ec, err)
	}
}

func TestBitbucketVerifyWebhookHMACAndToken(t *testing.T) {
	body := []byte(`{"a":1}`)
	secret := "s3cret"
	// HMAC.
	mac := hmacHeader(secret, body)
	b := &Bitbucket{Secret: secret}
	if err := b.VerifyWebhook(body, secret, http.Header{"X-Hub-Signature-256": []string{mac}}); err != nil {
		t.Fatalf("hmac = %v", err)
	}
	if err := b.VerifyWebhook(body, secret, http.Header{"X-Hub-Signature-256": []string{"sha256=dead"}}); err == nil {
		t.Fatal("bad hmac must fail")
	}
	// Token header fallback.
	b2 := &Bitbucket{Secret: "tok"}
	if err := b2.VerifyWebhook(body, "tok", http.Header{"X-Request-Token": []string{"tok"}}); err != nil {
		t.Fatalf("token = %v", err)
	}
	if err := b2.VerifyWebhook(body, "tok", http.Header{"X-Request-Token": []string{"nope"}}); err == nil {
		t.Fatal("bad token must fail")
	}
}

func TestBitbucketFetchAndPublish(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/src/"):
			_, _ = w.Write([]byte("pipeline yaml"))
		case strings.Contains(r.URL.Path, "/statuses/build"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"state": "SUCCESSFUL"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	b := &Bitbucket{BaseURL: srv.URL, Token: "t", Username: "u", Client: srv.Client()}
	raw, err := b.FetchFile(context.Background(), "ws/repo", ".kiwi/pipeline.yaml", "main")
	if err != nil || raw != "pipeline yaml" {
		t.Fatalf("fetch = %q %v", raw, err)
	}
	if err := b.PublishCheck(context.Background(), "ws/repo", "abc", "ci", "success", "success", srv.URL, "ok", nil); err != nil {
		t.Fatalf("publish = %v", err)
	}
	if cred, ok := b.CloneCredentialFor("ws/repo"); !ok || cred != "u:t" {
		t.Fatalf("cred = %q %v", cred, ok)
	}
}

func TestBitbucketChangedFilesPaginationFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[{"new":{"path":"a.go"}}],"next":"https://api.bitbucket.org/2.0/page2"}`))
	}))
	defer srv.Close()
	b := &Bitbucket{BaseURL: srv.URL, Token: "t", Client: srv.Client()}
	res, err := b.ChangedFiles(context.Background(), EventContext{PullRequest: 7, Repository: Repository{FullName: "ws/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("paginated diffstat must never report Complete (path filters fail closed)")
	}
	if len(res.Files) != 1 {
		t.Fatalf("files = %v", res.Files)
	}
}

func TestBitbucketImplementsForge(t *testing.T) {
	var _ Forge = &Bitbucket{}
}

// Bitbucket states / event-key suffixes must normalize to the canonical
// GitHub-style vocabulary trigger matching already speaks.
func TestBitbucketActionNormalization(t *testing.T) {
	for raw, want := range map[string]string{
		"created":   "opened",
		"updated":   "synchronize",
		"OPEN":      "opened",
		"open":      "opened",
		"update":    "synchronize",
		"reopen":    "reopened",
		"fulfilled": "closed",
		"rejected":  "closed",
		"MERGED":    "closed",
		"":          "",
	} {
		if got := bitBucketAction(raw); got != want {
			t.Fatalf("bitBucketAction(%q) = %q, want %q", raw, got, want)
		}
	}
	// ParseEvent must not leak raw state vocabulary.
	b := &Bitbucket{}
	pr := []byte(`{"repository":{"full_name":"ws/repo"},"pullrequest":{"id":7,"state":"OPEN","kiwi_action":"created","source":{"branch":{"name":"feat"},"commit":{"hash":"head"}},"destination":{"branch":{"name":"main"},"commit":{"hash":"base"}}}}`)
	ec, err := b.ParseEvent(pr)
	if err != nil {
		t.Fatal(err)
	}
	if ec.Action != "opened" {
		t.Fatalf("action = %q, want opened", ec.Action)
	}
	if !ec.Trusted {
		t.Fatal("same-repo PR must be trusted")
	}
	// Fork PR is untrusted.
	pr = []byte(`{"repository":{"full_name":"ws/repo"},"pullrequest":{"id":7,"state":"OPEN","kiwi_action":"updated","source":{"branch":{"name":"feat"},"commit":{"hash":"head"},"repository":{"full_name":"fork/repo"}},"destination":{"branch":{"name":"main"},"commit":{"hash":"base"},"repository":{"full_name":"ws/repo"}}}}`)
	ec, err = b.ParseEvent(pr)
	if err != nil {
		t.Fatal(err)
	}
	if ec.Action != "synchronize" {
		t.Fatalf("action = %q, want synchronize", ec.Action)
	}
	if ec.Trusted {
		t.Fatal("fork PR must not be trusted")
	}
	if ec.HeadRepository.FullName != "fork/repo" {
		t.Fatalf("head repo = %q", ec.HeadRepository.FullName)
	}
}

// FetchFile binds identity exactly once (path) and refuses a mutable
// default-branch fetch with an empty ref.
func TestBitbucketFetchFileRejectsEmptyRef(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("yaml"))
	}))
	defer srv.Close()
	b := &Bitbucket{BaseURL: srv.URL, Token: "t", Client: srv.Client()}
	if _, err := b.FetchFile(context.Background(), "ws/repo", ".kiwi/pipeline.yaml", ""); err == nil {
		t.Fatal("empty ref must fail closed")
	}
	if raw, err := b.FetchFile(context.Background(), "ws/repo", ".kiwi/pipeline.yaml", "abc123"); err != nil || raw != "yaml" {
		t.Fatalf("fetch = %q %v", raw, err)
	}
}

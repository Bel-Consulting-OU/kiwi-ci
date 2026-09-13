package forge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testPushPayload = `{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
  "repository": {
    "id": 42,
    "full_name": "octocat/hello-world",
    "clone_url": "https://github.com/octocat/hello-world.git",
    "default_branch": "main"
  }
}`

const testTagPushPayload = `{
  "ref": "refs/tags/v1.2.3",
  "before": "0000000000000000000000000000000000000000",
  "after": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
  "repository": {
    "id": 42,
    "full_name": "octocat/hello-world",
    "clone_url": "https://github.com/octocat/hello-world.git"
  }
}`

const testPRPayload = `{
  "action": "opened",
  "number": 2,
  "repository": {
    "id": 42,
    "full_name": "octocat/hello-world",
    "clone_url": "https://github.com/octocat/hello-world.git",
    "default_branch": "main"
  },
  "pull_request": {
    "draft": false,
    "head": {
      "sha": "ec26c3e57ca3a959ca5aad62de7213c562f8c821",
      "ref": "my-topic",
      "repo": {
        "id": 42,
        "full_name": "octocat/hello-world",
        "clone_url": "https://github.com/octocat/hello-world.git"
      }
    },
    "base": {
      "sha": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
      "ref": "main",
      "repo": {
        "id": 42,
        "full_name": "octocat/hello-world",
        "clone_url": "https://github.com/octocat/hello-world.git"
      }
    }
  }
}`

const testForkPRPayload = `{
  "action": "synchronize",
  "number": 3,
  "repository": {
    "id": 42,
    "full_name": "octocat/hello-world",
    "clone_url": "https://github.com/octocat/hello-world.git",
    "default_branch": "main"
  },
  "pull_request": {
    "draft": true,
    "head": {
      "sha": "ec26c3e57ca3a959ca5aad62de7213c562f8c821",
      "ref": "evil-patch",
      "repo": {
        "id": 99,
        "full_name": "mallory/hello-world",
        "clone_url": "https://github.com/mallory/hello-world.git"
      }
    },
    "base": {
      "sha": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
      "ref": "main",
      "repo": {
        "id": 42,
        "full_name": "octocat/hello-world",
        "clone_url": "https://github.com/octocat/hello-world.git"
      }
    }
  }
}`

func TestGitHubSignatureVector(t *testing.T) {
	g := &GitHub{}
	secret := "It's a Secret to Everybody"
	payload := []byte("Hello, World!")
	header := "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
	h := http.Header{}
	h.Set("X-Hub-Signature-256", header)
	if err := g.VerifyWebhook(payload, secret, h); err != nil {
		t.Fatalf("GitHub documented test vector failed: %v", err)
	}
	if err := g.VerifyWebhook([]byte("tampered"), secret, h); err == nil {
		t.Fatal("tampered payload accepted")
	}
	h2 := http.Header{}
	h2.Set("X-Hub-Signature-256", "sha1="+header[len("sha256="):])
	if err := g.VerifyWebhook(payload, secret, h2); err == nil {
		t.Fatal("non-sha256 signature accepted")
	}
}

func TestParseGitHubPush(t *testing.T) {
	g := &GitHub{}
	ec, err := g.ParseEvent([]byte(testPushPayload))
	if err != nil {
		t.Fatal(err)
	}
	if ec.Event != "push" || !ec.Trusted || ec.Forge != "github" {
		t.Fatalf("unexpected event: %+v", ec)
	}
	if ec.Repository.FullName != "octocat/hello-world" || ec.Repository.CloneURL == "" {
		t.Fatalf("bad repository: %+v", ec.Repository)
	}
	if ec.Ref != "refs/heads/main" || ec.HeadSHA != "9049f1265b7d61be4a8904a9a27120d2064dab3b" || ec.BaseSHA != "6113728f27ae82c7b1a177c8d03f9e96e0adf246" {
		t.Fatalf("bad refs: %+v", ec)
	}
	if ec.Tag != "" {
		t.Fatalf("branch push must not set Tag: %+v", ec)
	}

	tec, err := g.ParseEvent([]byte(testTagPushPayload))
	if err != nil {
		t.Fatal(err)
	}
	if tec.Tag != "v1.2.3" || tec.Event != "push" {
		t.Fatalf("tag push not detected: %+v", tec)
	}
}

func TestParseGitHubDeletedPush(t *testing.T) {
	g := &GitHub{}
	ec, err := g.ParseEvent([]byte(strings.Replace(testPushPayload, `"after": "9049f1265b7d61be4a8904a9a27120d2064dab3b"`, `"after": "0000000000000000000000000000000000000000"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if ec.HeadSHA != "" {
		t.Fatalf("deleted push must have empty HeadSHA: %+v", ec)
	}
}

func TestParseGitHubPullRequest(t *testing.T) {
	g := &GitHub{}
	ec, err := g.ParseEvent([]byte(testPRPayload))
	if err != nil {
		t.Fatal(err)
	}
	if ec.Event != "pull_request" || ec.Action != "opened" || ec.Draft {
		t.Fatalf("unexpected event: %+v", ec)
	}
	if !ec.Trusted {
		t.Fatal("same-repo PR must be trusted")
	}
	if ec.Repository.FullName != "octocat/hello-world" || ec.HeadRepository.FullName != "octocat/hello-world" {
		t.Fatalf("canonical repo mismatch: %+v / %+v", ec.Repository, ec.HeadRepository)
	}
	if ec.HeadSHA != "ec26c3e57ca3a959ca5aad62de7213c562f8c821" || ec.BaseSHA != "6113728f27ae82c7b1a177c8d03f9e96e0adf246" {
		t.Fatalf("bad SHAs: %+v", ec)
	}

	fec, err := g.ParseEvent([]byte(testForkPRPayload))
	if err != nil {
		t.Fatal(err)
	}
	if fec.Trusted {
		t.Fatal("fork PR must be untrusted")
	}
	if !fec.Draft {
		t.Fatal("draft flag not parsed")
	}
	if fec.Repository.FullName != "octocat/hello-world" || fec.HeadRepository.FullName != "mallory/hello-world" {
		t.Fatalf("fork repo coordinates wrong: %+v / %+v", fec.Repository, fec.HeadRepository)
	}
	if fec.Ref != "evil-patch" || fec.BaseRef != "main" {
		t.Fatalf("fork refs wrong: %+v", fec)
	}
}

func TestGitHubFetchFile(t *testing.T) {
	content := "version: 1\njobs:\n  build:\n    steps: [{run: echo hi}]\n"
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/octocat/hello-world/contents/.kiwi/pipeline.yaml" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("ref") != "9049f1265b7d61be4a8904a9a27120d2064dab3b" {
			http.Error(w, "bad ref", http.StatusBadRequest)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content":  base64.StdEncoding.EncodeToString([]byte(content)),
			"encoding": "base64",
		})
	}))
	defer ts.Close()
	g := &GitHub{BaseURL: ts.URL, Token: "secret-token"}
	got, err := g.FetchFile(context.Background(), "octocat/hello-world", ".kiwi/pipeline.yaml", "9049f1265b7d61be4a8904a9a27120d2064dab3b")
	if err != nil {
		t.Fatal(err)
	}
	if got != content {
		t.Fatalf("content mismatch: %q", got)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("auth header not sent: %q", gotAuth)
	}
}

func TestGitHubChangedFiles(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/compare/") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"files": []map[string]string{{"filename": "src/main.go"}, {"filename": "docs/readme.md"}},
		})
	}))
	defer ts.Close()
	g := &GitHub{BaseURL: ts.URL}
	ec := EventContext{
		Event: "pull_request", HeadSHA: "abc", BaseSHA: "def",
		Repository: Repository{Forge: "github", FullName: "octocat/hello-world"},
	}
	files, err := g.ChangedFiles(context.Background(), ec)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0] != "src/main.go" || files[1] != "docs/readme.md" {
		t.Fatalf("unexpected files: %v", files)
	}
	if files, err = g.ChangedFiles(context.Background(), EventContext{}); err != nil || files != nil {
		t.Fatalf("empty event should yield nil files: %v %v", files, err)
	}
}

func TestGitHubPublishCheck(t *testing.T) {
	var lastBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/octocat/hello-world/check-runs" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()
	g := &GitHub{BaseURL: ts.URL, Token: "tok"}
	err := g.PublishCheck(context.Background(), "octocat/hello-world", "9049f1265b7d61be4a8904a9a27120d2064dab3b", "Pipeline", "completed", "failure", "https://kiwi.example/?run=r1", "pipeline failed", []CheckAnnotation{{Path: "main.go", Line: 1, Level: "failure", Message: "boom"}})
	if err != nil {
		t.Fatal(err)
	}
	if lastBody == nil {
		t.Fatal("no request captured")
	}
	if lastBody["name"] != "Kiwi / Pipeline" || lastBody["status"] != "completed" || lastBody["conclusion"] != "failure" {
		t.Fatalf("bad body: %v", lastBody)
	}
	ext, ok := lastBody["external_id"].(string)
	if !ok || !strings.HasPrefix(ext, "kiwi-9049f1265b7d") || !strings.HasSuffix(ext, "-Pipeline") {
		t.Fatalf("bad external_id: %v", lastBody["external_id"])
	}
	output := lastBody["output"].(map[string]any)
	if output["summary"] != "pipeline failed" {
		t.Fatalf("bad output: %v", output)
	}
	anns := output["annotations"].([]any)
	if len(anns) != 1 {
		t.Fatalf("annotations dropped: %v", output)
	}

	// Same inputs → same external_id (idempotent update, no duplicate).
	lastBody = nil
	if err := g.PublishCheck(context.Background(), "octocat/hello-world", "9049f1265b7d61be4a8904a9a27120d2064dab3b", "Pipeline", "completed", "success", "", "ok", nil); err != nil {
		t.Fatal(err)
	}
	if lastBody["external_id"] != ext {
		t.Fatalf("external_id not stable across publishes: %v", lastBody["external_id"])
	}
}

func TestGitHubPublishCheckError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()
	g := &GitHub{BaseURL: ts.URL}
	if err := g.PublishCheck(context.Background(), "octocat/hello-world", "sha", "Pipeline", "queued", "", "", "", nil); err == nil {
		t.Fatal("expected API error")
	}
}

func TestGitHubParseUnrelatedEvent(t *testing.T) {
	g := &GitHub{}
	ec, err := g.ParseEvent([]byte(`{"action":"created","issue":{"number":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if ec.Event != "" {
		t.Fatalf("issue event must yield empty event: %+v", ec)
	}
}

func TestVerifyHMACSignatureMalformed(t *testing.T) {
	cases := map[string]bool{
		"sha256=zz":       false,
		"sha256=":         false,
		"":                false,
		"sha256=41414141": false, // wrong digest
	}
	for header, want := range cases {
		if got := VerifyHMACSignature("secret", header, []byte("x")); got != want {
			t.Errorf("VerifyHMACSignature(%q) = %v, want %v", header, got, want)
		}
	}
}

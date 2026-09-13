package forge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testGitLabPush = `{
  "object_kind": "push",
  "ref": "refs/heads/main",
  "before": "95790bf891e76fee5e1747ab589903a6a1f80f22",
  "after": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
  "checkout_sha": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
  "project": {
    "id": 15,
    "path_with_namespace": "mike/diaspora",
    "default_branch": "main",
    "http_url_to_repo": "https://gitlab.com/mike/diaspora.git"
  },
  "repository": {
    "name": "diaspora",
    "git_http_url": "https://gitlab.com/mike/diaspora.git"
  }
}`

const testGitLabTagPush = `{
  "object_kind": "tag_push",
  "ref": "refs/tags/v1.0.0",
  "before": "0000000000000000000000000000000000000000",
  "after": "82b3d5ae55f7080f1e6022629cdb57bfae7cccc7",
  "checkout_sha": "82b3d5ae55f7080f1e6022629cdb57bfae7cccc7",
  "project": {
    "id": 15,
    "path_with_namespace": "mike/diaspora",
    "default_branch": "main",
    "http_url_to_repo": "https://gitlab.com/mike/diaspora.git"
  },
  "repository": {"name": "diaspora", "git_http_url": "https://gitlab.com/mike/diaspora.git"}
}`

const testGitLabMR = `{
  "object_kind": "merge_request",
  "project": {
    "id": 15,
    "path_with_namespace": "mike/diaspora",
    "default_branch": "main",
    "http_url_to_repo": "https://gitlab.com/mike/diaspora.git"
  },
  "object_attributes": {
    "iid": 2,
    "action": "open",
    "source_branch": "ms-viewport",
    "target_branch": "main",
    "source": {
      "path_with_namespace": "mike/diaspora",
      "default_branch": "main",
      "git_http_url": "https://gitlab.com/mike/diaspora.git"
    },
    "target": {
      "path_with_namespace": "mike/diaspora",
      "default_branch": "main",
      "git_http_url": "https://gitlab.com/mike/diaspora.git"
    },
    "last_commit": {"id": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7"},
    "diff_refs": {"base_sha": "95790bf891e76fee5e1747ab589903a6a1f80f22", "head_sha": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7", "start_sha": "95790bf891e76fee5e1747ab589903a6a1f80f22"}
  }
}`

const testGitLabForkMR = `{
  "object_kind": "merge_request",
  "project": {
    "id": 15,
    "path_with_namespace": "mike/diaspora",
    "default_branch": "main",
    "http_url_to_repo": "https://gitlab.com/mike/diaspora.git"
  },
  "object_attributes": {
    "iid": 3,
    "action": "update",
    "draft": true,
    "source_branch": "evil",
    "target_branch": "main",
    "source": {
      "path_with_namespace": "mallory/diaspora",
      "default_branch": "main",
      "git_http_url": "https://gitlab.com/mallory/diaspora.git"
    },
    "target": {
      "path_with_namespace": "mike/diaspora",
      "default_branch": "main",
      "git_http_url": "https://gitlab.com/mike/diaspora.git"
    },
    "last_commit": {"id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
    "diff_refs": {"base_sha": "95790bf891e76fee5e1747ab589903a6a1f80f22", "head_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "start_sha": "95790bf891e76fee5e1747ab589903a6a1f80f22"}
  }
}`

func TestGitLabVerifyWebhook(t *testing.T) {
	g := &GitLab{SecretToken: "s3cret"}
	h := http.Header{}
	h.Set("X-GitLab-Token", "s3cret")
	if err := g.VerifyWebhook([]byte("{}"), "s3cret", h); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	h.Set("X-GitLab-Token", "wrong")
	if err := g.VerifyWebhook([]byte("{}"), "s3cret", h); err == nil {
		t.Fatal("wrong token accepted")
	}
	if err := g.VerifyWebhook([]byte("{}"), "", h); err == nil {
		t.Fatal("missing secret accepted")
	}
}

func TestParseGitLabPush(t *testing.T) {
	g := &GitLab{}
	ec, err := g.ParseEvent([]byte(testGitLabPush))
	if err != nil {
		t.Fatal(err)
	}
	if ec.Event != "push" || !ec.Trusted || ec.Forge != "gitlab" {
		t.Fatalf("unexpected event: %+v", ec)
	}
	if ec.Repository.FullName != "mike/diaspora" || ec.Repository.CloneURL != "https://gitlab.com/mike/diaspora.git" {
		t.Fatalf("bad repository: %+v", ec.Repository)
	}
	if ec.HeadSHA != "da1560886d4f094c3e6c9ef40349f7d38b5d27d7" || ec.BaseSHA != "95790bf891e76fee5e1747ab589903a6a1f80f22" {
		t.Fatalf("bad SHAs: %+v", ec)
	}
	if ec.Tag != "" {
		t.Fatalf("branch push must not set Tag")
	}

	tec, err := g.ParseEvent([]byte(testGitLabTagPush))
	if err != nil {
		t.Fatal(err)
	}
	if tec.Tag != "v1.0.0" {
		t.Fatalf("tag push not detected: %+v", tec)
	}
}

func TestParseGitLabMergeRequest(t *testing.T) {
	g := &GitLab{}
	ec, err := g.ParseEvent([]byte(testGitLabMR))
	if err != nil {
		t.Fatal(err)
	}
	if ec.Event != "merge_request" || ec.Action != "opened" {
		t.Fatalf("unexpected event: %+v", ec)
	}
	if !ec.Trusted {
		t.Fatal("same-project MR must be trusted")
	}
	if ec.Ref != "ms-viewport" || ec.BaseRef != "main" {
		t.Fatalf("bad refs: %+v", ec)
	}

	fec, err := g.ParseEvent([]byte(testGitLabForkMR))
	if err != nil {
		t.Fatal(err)
	}
	if fec.Trusted {
		t.Fatal("fork MR must be untrusted")
	}
	if !fec.Draft {
		t.Fatal("draft flag not parsed")
	}
	if fec.Action != "synchronize" {
		t.Fatalf("action not normalized: %+v", fec)
	}
	if fec.Repository.FullName != "mike/diaspora" || fec.HeadRepository.FullName != "mallory/diaspora" {
		t.Fatalf("fork coordinates wrong: %+v / %+v", fec.Repository, fec.HeadRepository)
	}
}

func TestParseGitLabUnrelated(t *testing.T) {
	g := &GitLab{}
	ec, err := g.ParseEvent([]byte(`{"object_kind":"issue","user":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if ec.Event != "" {
		t.Fatalf("issue event must yield empty event: %+v", ec)
	}
}

func TestGitLabFetchFileAndChangedFiles(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/repository/files/") && strings.HasSuffix(r.URL.Path, "/raw"):
			if r.URL.Query().Get("ref") != "main" {
				http.Error(w, "bad ref", http.StatusBadRequest)
				return
			}
			if r.Header.Get("PRIVATE-TOKEN") != "glpat-token" {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("version: 1\njobs: {build: {steps: [{run: echo}]}}"))
		case strings.Contains(r.URL.Path, "/repository/compare"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"diffs": []map[string]string{{"old_path": "a.txt", "new_path": "b.txt"}, {"new_path": "c.txt"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	g := &GitLab{BaseURL: ts.URL, Token: "glpat-token"}
	got, err := g.FetchFile(context.Background(), "mike/diaspora", ".kiwi/pipeline.yaml", "main")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "version: 1") {
		t.Fatalf("bad content: %q", got)
	}
	files, err := g.ChangedFiles(context.Background(), EventContext{Repository: Repository{FullName: "mike/diaspora"}, BaseSHA: "a", HeadSHA: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0] != "b.txt" || files[1] != "c.txt" {
		t.Fatalf("unexpected files: %v", files)
	}
}

func TestGitLabPublishCheck(t *testing.T) {
	var got map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/statuses/") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()
	g := &GitLab{BaseURL: ts.URL}
	if err := g.PublishCheck(context.Background(), "mike/diaspora", "sha", "build", "completed", "failure", "https://kiwi.example", "failed", nil); err != nil {
		t.Fatal(err)
	}
	if got["state"] != "failed" || got["name"] != "Kiwi / build" {
		t.Fatalf("bad status body: %v", got)
	}
}

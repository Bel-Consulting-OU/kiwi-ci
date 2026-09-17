package forge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGitLabBaseURLClientAndAuth(t *testing.T) {
	var gotPath, gotToken string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotToken = r.URL.EscapedPath(), r.Header.Get("PRIVATE-TOKEN")
		_, _ = w.Write([]byte("file-content"))
	}))
	defer ts.Close()

	g := &GitLab{Token: "gltok", BaseURL: ts.URL + "/", Client: ts.Client()}
	content, err := g.FetchFile(context.Background(), "group/project", "/dir/file.yaml", "main")
	if err != nil || content != "file-content" {
		t.Fatalf("FetchFile = %q (err %v)", content, err)
	}
	if gotPath != "/api/v4/projects/group%2Fproject/repository/files/dir%2Ffile.yaml/raw" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotToken != "gltok" {
		t.Fatalf("PRIVATE-TOKEN = %q", gotToken)
	}
	if g.apiBase() != ts.URL+"/api/v4" || (&GitLab{}).apiBase() != defaultGitLabBase+"/api/v4" {
		t.Fatalf("apiBase = %q", g.apiBase())
	}

	t.Setenv("KIWI_GITLAB_TOKEN", "env-gl")
	env := &GitLab{}
	if tok := env.apiToken(); tok != "env-gl" {
		t.Fatalf("apiToken = %q", tok)
	}
	t.Setenv("KIWI_GITLAB_TOKEN", "")
	if tok := (&GitLab{}).apiToken(); tok != "" {
		t.Fatalf("apiToken = %q, want empty", tok)
	}
}

func TestGitLabVerifyWebhookUnconfigured(t *testing.T) {
	g := &GitLab{}
	if err := g.VerifyWebhook(nil, "", http.Header{}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unconfigured token = %v", err)
	}
	h := http.Header{"X-Gitlab-Token": []string{"right"}}
	if err := g.VerifyWebhook(nil, "right", h); err != nil {
		t.Fatalf("matching token = %v", err)
	}
	if err := g.VerifyWebhook(nil, "wrong", h); err == nil {
		t.Fatal("mismatched token must fail")
	}
}

func TestGitLabParsePushEdges(t *testing.T) {
	g := &GitLab{}
	ec, err := g.ParseEvent([]byte(`{"object_kind":"push","ref":"refs/tags/v1","checkout_sha":"aaa","before":"bbb","project":{"id":3,"path_with_namespace":"g/p","default_branch":"main","http_url_to_repo":"https://gl/g/p.git"}}`))
	if err != nil || ec.Tag != "v1" || ec.HeadSHA != "aaa" {
		t.Fatalf("tag push = %+v (err %v)", ec, err)
	}
	// tag_push uses the ref-derived tag even without the refs/tags prefix.
	ec, err = g.ParseEvent([]byte(`{"object_kind":"tag_push","ref":"v2","after":"ccc","project":{"id":3,"path_with_namespace":"g/p"}}`))
	if err != nil || ec.Tag != "v2" || ec.HeadSHA != "ccc" {
		t.Fatalf("tag_push = %+v (err %v)", ec, err)
	}
	// Empty checkout_sha falls back to after; an all-zero head clears it.
	ec, err = g.ParseEvent([]byte(`{"object_kind":"push","ref":"refs/heads/main","after":"ddd","project":{"id":3,"path_with_namespace":"g/p"}}`))
	if err != nil || ec.HeadSHA != "ddd" {
		t.Fatalf("after fallback = %+v (err %v)", ec, err)
	}
	ec, err = g.ParseEvent([]byte(`{"object_kind":"push","ref":"refs/heads/gone","checkout_sha":"` + strings.Repeat("0", 40) + `","project":{"id":3,"path_with_namespace":"g/p"}}`))
	if err != nil || ec.HeadSHA != "" {
		t.Fatalf("zero sha = %+v (err %v)", ec, err)
	}
	// Repository clone URL falls back to the project HTTP URL.
	ec, err = g.ParseEvent([]byte(`{"object_kind":"push","ref":"refs/heads/main","after":"e","project":{"id":3,"path_with_namespace":"g/p","http_url_to_repo":"https://gl/g/p.git"}}`))
	if err != nil || ec.Repository.CloneURL != "https://gl/g/p.git" || ec.Repository.ID != "3" {
		t.Fatalf("clone url fallback = %+v (err %v)", ec, err)
	}
	// Repository git_http_url wins when present.
	ec, err = g.ParseEvent([]byte(`{"object_kind":"push","ref":"refs/heads/main","after":"e","repository":{"git_http_url":"https://gl/g/p-git.git"},"project":{"id":3,"path_with_namespace":"g/p"}}`))
	if err != nil || ec.Repository.CloneURL != "https://gl/g/p-git.git" {
		t.Fatalf("git_http_url = %+v (err %v)", ec, err)
	}
	// No ref yields no event; malformed JSON fails.
	if ec, err = g.ParseEvent([]byte(`{"object_kind":"push","project":{}}`)); err != nil || ec.Event != "" {
		t.Fatalf("empty ref = %+v (err %v)", ec, err)
	}
	if _, err := g.ParseEvent([]byte("nope")); err == nil {
		t.Fatal("malformed body must fail")
	}
	if ec, err = g.ParseEvent([]byte(`{"object_kind":"pipeline"}`)); err != nil || ec.Event != "" {
		t.Fatalf("unrelated kind = %+v (err %v)", ec, err)
	}
}

func TestGitLabParseMergeRequestEdges(t *testing.T) {
	g := &GitLab{}
	base := `"object_attributes":{"action":"%s","source_branch":"feat","target_branch":"main","last_commit":{"id":"head1"},"diff_refs":{"base_sha":"base1","start_sha":"start1"}},"project":{"id":5,"path_with_namespace":"g/p","http_url_to_repo":"https://gl/g/p.git"}`

	ec, err := g.ParseEvent([]byte(`{"object_kind":"merge_request",` + strings.Replace(base, "%s", "open", 1) + `}`))
	if err != nil || ec.Action != "opened" || ec.HeadSHA != "head1" || ec.BaseSHA != "base1" {
		t.Fatalf("open mapping = %+v (err %v)", ec, err)
	}
	ec, err = g.ParseEvent([]byte(`{"object_kind":"merge_request",` + strings.Replace(base, "%s", "update", 1) + `}`))
	if err != nil || ec.Action != "synchronize" {
		t.Fatalf("update mapping = %+v (err %v)", ec, err)
	}
	ec, err = g.ParseEvent([]byte(`{"object_kind":"merge_request",` + strings.Replace(base, "%s", "reopen", 1) + `}`))
	if err != nil || ec.Action != "reopened" {
		t.Fatalf("reopen mapping = %+v (err %v)", ec, err)
	}
	ec, err = g.ParseEvent([]byte(`{"object_kind":"merge_request",` + strings.Replace(base, "%s", "close", 1) + `}`))
	if err != nil || ec.Action != "close" {
		t.Fatalf("unmapped action = %+v (err %v)", ec, err)
	}

	// Head falls back to the base repository; head SHA to diff_refs; base
	// SHA to start_sha; WIP sets Draft.
	ec, err = g.ParseEvent([]byte(`{"object_kind":"merge_request","object_attributes":{"action":"open","source_branch":"feat","target_branch":"main","work_in_progress":true,"diff_refs":{"head_sha":"h2","start_sha":"s2"}},"project":{"id":5,"path_with_namespace":"g/p"}}`))
	if err != nil || !ec.Trusted || ec.HeadRepository.FullName != "g/p" || ec.HeadSHA != "h2" || ec.BaseSHA != "s2" || !ec.Draft {
		t.Fatalf("fallback MR = %+v (err %v)", ec, err)
	}

	// Fork MR: source namespace differs, source URLs are used.
	ec, err = g.ParseEvent([]byte(`{"object_kind":"merge_request","object_attributes":{"action":"open","source_branch":"feat","target_branch":"main","last_commit":{"id":"h3"},"diff_refs":{"base_sha":"b3"},"source":{"path_with_namespace":"fork/p","http_url_to_repo":"https://gl/fork/p.git"}},"project":{"id":5,"path_with_namespace":"g/p"}}`))
	if err != nil || ec.Trusted || ec.HeadRepository.CloneURL != "https://gl/fork/p.git" {
		t.Fatalf("fork MR = %+v (err %v)", ec, err)
	}
	ec, err = g.ParseEvent([]byte(`{"object_kind":"merge_request","object_attributes":{"action":"open","source_branch":"feat","target_branch":"main","source":{"path_with_namespace":"fork/p","git_http_url":"https://gl/fork/p-git.git"}},"project":{"id":5,"path_with_namespace":"g/p"}}`))
	if err != nil || ec.HeadRepository.CloneURL != "https://gl/fork/p-git.git" {
		t.Fatalf("fork git_http_url = %+v (err %v)", ec, err)
	}

	// Empty action yields no event; malformed JSON fails.
	if ec, err = g.ParseEvent([]byte(`{"object_kind":"merge_request","object_attributes":{}}`)); err != nil || ec.Event != "" {
		t.Fatalf("empty action = %+v (err %v)", ec, err)
	}
	if _, err := g.ParseEvent([]byte(`{"object_kind":"merge_request","object_attributes":"nope"}`)); err == nil {
		t.Fatal("malformed MR body must fail")
	}
}

func TestGitLabFetchFileErrors(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if _, err := (&GitLab{BaseURL: closed.URL}).FetchFile(context.Background(), "g/p", "f", "main"); err == nil {
		t.Fatal("transport error must fail")
	}
	if _, err := (&GitLab{BaseURL: "http://\x7f"}).FetchFile(context.Background(), "g/p", "f", "main"); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer status.Close()
	if _, err := (&GitLab{BaseURL: status.URL}).FetchFile(context.Background(), "g/p", "f", "main"); err == nil || !strings.Contains(err.Error(), "GitLab API 403") {
		t.Fatalf("status error = %v", err)
	}
	oversize := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, maxFetchFileBytes+2))
	}))
	defer oversize.Close()
	if _, err := (&GitLab{BaseURL: oversize.URL}).FetchFile(context.Background(), "g/p", "f", "main"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestGitLabChangedFilesEdges(t *testing.T) {
	ec := EventContext{Repository: Repository{FullName: "g/p"}, BaseSHA: "b", HeadSHA: "h"}
	if res, err := (&GitLab{}).ChangedFiles(context.Background(), EventContext{}); err != nil || res.Complete || res.Files != nil {
		t.Fatalf("empty context = %+v (err %v)", res, err)
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if _, err := (&GitLab{BaseURL: closed.URL}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("transport error must fail")
	}
	if _, err := (&GitLab{BaseURL: "http://\x7f"}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}

	serverErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer serverErr.Close()
	if _, err := (&GitLab{BaseURL: serverErr.URL}).ChangedFiles(context.Background(), ec); err == nil || !strings.Contains(err.Error(), "compare API 502") {
		t.Fatalf("5xx error = %v", err)
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{nope"))
	}))
	defer badJSON.Close()
	if _, err := (&GitLab{BaseURL: badJSON.URL}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("decode error must fail")
	}

	// Two pages: the first full (100), the second short; old_path is used
	// when new_path is empty.
	var mu sync.Mutex
	page := 0
	paged := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		page++
		current := page
		mu.Unlock()
		var diffs []map[string]string
		if current == 1 {
			for i := 0; i < gitLabComparePerPage; i++ {
				diffs = append(diffs, map[string]string{"new_path": "n"})
			}
		} else {
			diffs = []map[string]string{{"old_path": "old/name.go"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"diffs": diffs})
	}))
	defer paged.Close()
	res, err := (&GitLab{BaseURL: paged.URL}).ChangedFiles(context.Background(), ec)
	if err != nil || !res.Complete || len(res.Files) != gitLabComparePerPage+1 {
		t.Fatalf("paged changed files = %+v (err %v)", res, err)
	}
	if res.Files[len(res.Files)-1] != "old/name.go" {
		t.Fatalf("old_path fallback missing: %v", res.Files[gitLabComparePerPage:])
	}
}

func TestGitLabPublishCheckStates(t *testing.T) {
	var state string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		state, _ = body["state"].(string)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()
	g := &GitLab{BaseURL: ts.URL}

	if err := g.PublishCheck(context.Background(), "", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("missing repo must fail")
	}
	if err := g.PublishCheck(context.Background(), "g/p", "", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("missing sha must fail")
	}

	cases := []struct {
		status, conclusion, want string
	}{
		{"queued", "", "pending"},
		{"in_progress", "", "running"},
		{"completed", "success", "success"},
		{"completed", "skipped", "success"},
		{"completed", "neutral", "success"},
		{"completed", "cancelled", "canceled"},
		{"completed", "failure", "failed"},
		{"completed", "timed_out", "pending"},
	}
	for _, tc := range cases {
		state = ""
		if err := g.PublishCheck(context.Background(), "g/p", "sha", "n", tc.status, tc.conclusion, "https://ci", "summary", nil); err != nil {
			t.Fatalf("%v/%v: %v", tc.status, tc.conclusion, err)
		}
		if state != tc.want {
			t.Errorf("status %q conclusion %q -> %q, want %q", tc.status, tc.conclusion, state, tc.want)
		}
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if err := (&GitLab{BaseURL: closed.URL}).PublishCheck(context.Background(), "g/p", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("transport error must fail")
	}
	if err := (&GitLab{BaseURL: "http://\x7f"}).PublishCheck(context.Background(), "g/p", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}
	statusErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer statusErr.Close()
	if err := (&GitLab{BaseURL: statusErr.URL}).PublishCheck(context.Background(), "g/p", "sha", "n", "queued", "", "", "", nil); err == nil || !strings.Contains(err.Error(), "statuses API 403") {
		t.Fatalf("status error = %v", err)
	}
}

func TestGitLabCloneCredentialAndFirstNonEmpty(t *testing.T) {
	t.Setenv("KIWI_GITLAB_TOKEN", "")
	if cred, ok := (&GitLab{}).CloneCredentialFor("g/p"); ok || cred != "" {
		t.Fatalf("no credential = %q,%v", cred, ok)
	}
	t.Setenv("KIWI_GITLAB_TOKEN", "env-gl")
	if cred, ok := (&GitLab{}).CloneCredentialFor("g/p"); !ok || cred != "env-gl" {
		t.Fatalf("env credential = %q,%v", cred, ok)
	}
	if cred, ok := (&GitLab{Token: "explicit"}).CloneCredentialFor("g/p"); !ok || cred != "explicit" {
		t.Fatalf("explicit credential = %q,%v", cred, ok)
	}
	if got := firstNonEmpty("", "", "third"); got != "third" {
		t.Fatalf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Fatalf("firstNonEmpty() = %q", got)
	}
}

func TestForgejoBaseURLClientAndParse(t *testing.T) {
	var gotPath, gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"content":"aGVsbG8=","encoding":"base64"}`))
	}))
	defer ts.Close()

	f := &Forgejo{Token: "fjtok", BaseURL: ts.URL + "/", Client: ts.Client()}
	content, err := f.FetchFile(context.Background(), "o/r", "/p.yaml", "main")
	if err != nil || content != "hello" {
		t.Fatalf("FetchFile = %q (err %v)", content, err)
	}
	if gotPath != "/api/v1/repos/o/r/contents/p.yaml" || gotAuth != "token fjtok" {
		t.Fatalf("path/auth = %q/%q", gotPath, gotAuth)
	}
	if f.apiBase() != ts.URL+"/api/v1" || (&Forgejo{}).apiBase() != defaultForgejoBase+"/api/v1" {
		t.Fatalf("apiBase = %q", f.apiBase())
	}

	t.Setenv("KIWI_FORGEJO_TOKEN", "env-fj")
	if tok := (&Forgejo{}).apiToken(); tok != "env-fj" {
		t.Fatalf("apiToken = %q", tok)
	}
	t.Setenv("KIWI_FORGEJO_TOKEN", "")
	if tok := (&Forgejo{}).apiToken(); tok != "" {
		t.Fatalf("apiToken = %q, want empty", tok)
	}

	// Push and PR events reuse the GitHub payload shapes with the forge
	// overridden.
	ec, err := f.ParseEvent([]byte(`{"ref":"refs/heads/main","after":"a","before":"b","repository":{"full_name":"o/r"}}`))
	if err != nil || ec.Forge != "forgejo" || ec.HeadSHA != "a" {
		t.Fatalf("push = %+v (err %v)", ec, err)
	}
	ec, err = f.ParseEvent([]byte(`{"ref":"refs/tags/v1","after":"a","repository":{"full_name":"o/r"}}`))
	if err != nil || ec.Tag != "v1" {
		t.Fatalf("tag push = %+v (err %v)", ec, err)
	}
	ec, err = f.ParseEvent([]byte(`{"ref":"refs/heads/gone","deleted":true,"after":"a","repository":{"full_name":"o/r"}}`))
	if err != nil || ec.HeadSHA != "" {
		t.Fatalf("deleted push = %+v (err %v)", ec, err)
	}
	ec, err = f.ParseEvent([]byte(`{"action":"opened","pull_request":{"head":{"ref":"f","sha":"h","repo":{"full_name":"o/r"}},"base":{"ref":"main","sha":"b"}},"repository":{"full_name":"o/r"}}`))
	if err != nil || ec.Forge != "forgejo" || !ec.Trusted {
		t.Fatalf("PR = %+v (err %v)", ec, err)
	}
	ec, err = f.ParseEvent([]byte(`{"action":"opened","pull_request":{"head":{"ref":"f","sha":"h","repo":{"full_name":"fork/r"}},"base":{"ref":"main","sha":"b"}},"repository":{"full_name":"o/r"}}`))
	if err != nil || ec.Trusted {
		t.Fatalf("fork PR = %+v (err %v)", ec, err)
	}
	if ec, err = f.ParseEvent([]byte(`{"repository":{"full_name":"o/r"}}`)); err != nil || ec.Event != "" {
		t.Fatalf("empty ref = %+v (err %v)", ec, err)
	}
	if ec, err = f.ParseEvent([]byte(`{"pull_request":{"number":1}}`)); err != nil || ec.Event != "" {
		t.Fatalf("empty action = %+v (err %v)", ec, err)
	}
	if _, err := f.ParseEvent([]byte("nope")); err == nil {
		t.Fatal("malformed body must fail")
	}
}

func TestForgejoFetchFileErrors(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if _, err := (&Forgejo{BaseURL: closed.URL}).FetchFile(context.Background(), "o/r", "f", "main"); err == nil {
		t.Fatal("transport error must fail")
	}
	if _, err := (&Forgejo{BaseURL: "http://\x7f"}).FetchFile(context.Background(), "o/r", "f", "main"); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}
	for name, body := range map[string]string{
		"decode":     "{nope",
		"encoding":   `{"content":"aGk=","encoding":"utf-8"}`,
		"bad base64": `{"content":"!!!","encoding":"base64"}`,
	} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		if _, err := (&Forgejo{BaseURL: ts.URL}).FetchFile(context.Background(), "o/r", "f", "main"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
		ts.Close()
	}
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer status.Close()
	if _, err := (&Forgejo{BaseURL: status.URL}).FetchFile(context.Background(), "o/r", "f", "main"); err == nil || !strings.Contains(err.Error(), "Forgejo API 410") {
		t.Fatalf("status error = %v", err)
	}
}

func TestForgejoChangedFilesAndPublishErrors(t *testing.T) {
	ec := EventContext{Repository: Repository{FullName: "o/r"}, BaseSHA: "b", HeadSHA: "h"}
	if res, err := (&Forgejo{}).ChangedFiles(context.Background(), EventContext{}); err != nil || res.Complete || res.Files != nil {
		t.Fatalf("empty context = %+v (err %v)", res, err)
	}
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if _, err := (&Forgejo{BaseURL: closed.URL}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("transport error must fail")
	}
	if _, err := (&Forgejo{BaseURL: "http://\x7f"}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{nope"))
	}))
	defer badJSON.Close()
	if _, err := (&Forgejo{BaseURL: badJSON.URL}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("decode error must fail")
	}
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusTeapot)
	}))
	defer status.Close()
	if _, err := (&Forgejo{BaseURL: status.URL}).ChangedFiles(context.Background(), ec); err == nil || !strings.Contains(err.Error(), "compare API 418") {
		t.Fatalf("status error = %v", err)
	}

	var state string
	check := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		state, _ = body["state"].(string)
		w.WriteHeader(http.StatusOK)
	}))
	defer check.Close()
	f := &Forgejo{BaseURL: check.URL}
	if err := f.PublishCheck(context.Background(), "", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("missing repo must fail")
	}
	for _, tc := range []struct {
		status, conclusion, want string
	}{
		{"queued", "", "pending"},
		{"in_progress", "", "pending"},
		{"completed", "success", "success"},
		{"completed", "neutral", "success"},
		{"completed", "cancelled", "error"},
		{"completed", "failure", "failure"},
		{"completed", "timed_out", "pending"},
	} {
		state = ""
		if err := f.PublishCheck(context.Background(), "o/r", "sha", "n", tc.status, tc.conclusion, "https://ci", "sum", nil); err != nil {
			t.Fatalf("%v/%v: %v", tc.status, tc.conclusion, err)
		}
		if state != tc.want {
			t.Errorf("status %q conclusion %q -> %q, want %q", tc.status, tc.conclusion, state, tc.want)
		}
	}
	if err := (&Forgejo{BaseURL: closed.URL}).PublishCheck(context.Background(), "o/r", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("transport error must fail")
	}
	if err := (&Forgejo{BaseURL: "http://\x7f"}).PublishCheck(context.Background(), "o/r", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}
	statusErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusBadRequest)
	}))
	defer statusErr.Close()
	if err := (&Forgejo{BaseURL: statusErr.URL}).PublishCheck(context.Background(), "o/r", "sha", "n", "queued", "", "", "", nil); err == nil || !strings.Contains(err.Error(), "statuses API 400") {
		t.Fatalf("status error = %v", err)
	}

	t.Setenv("KIWI_FORGEJO_TOKEN", "")
	if cred, ok := (&Forgejo{}).CloneCredentialFor("o/r"); ok || cred != "" {
		t.Fatalf("no credential = %q,%v", cred, ok)
	}
	t.Setenv("KIWI_FORGEJO_TOKEN", "env-fj")
	if cred, ok := (&Forgejo{}).CloneCredentialFor("o/r"); !ok || cred != "env-fj" {
		t.Fatalf("env credential = %q,%v", cred, ok)
	}
	t.Setenv("KIWI_FORGEJO_TOKEN", "")
	if cred, ok := (&Forgejo{Token: "tok"}).CloneCredentialFor("o/r"); !ok || cred != "tok" {
		t.Fatalf("explicit credential = %q,%v", cred, ok)
	}
}

func TestForgejoChangedFilesPaging(t *testing.T) {
	ec := EventContext{Repository: Repository{FullName: "o/r"}, BaseSHA: "b", HeadSHA: "h"}
	var mu sync.Mutex
	page := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		page++
		current := page
		mu.Unlock()
		files := []map[string]string{}
		if current == 1 {
			for i := 0; i < githubComparePerPage; i++ {
				files = append(files, map[string]string{"filename": "n"})
			}
		} else {
			files = append(files, map[string]string{"filename": "tail"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
	}))
	defer ts.Close()
	res, err := (&Forgejo{BaseURL: ts.URL}).ChangedFiles(context.Background(), ec)
	if err != nil || !res.Complete || len(res.Files) != githubComparePerPage+1 {
		t.Fatalf("paged changed files = %+v (err %v)", res, err)
	}
	if res.Files[len(res.Files)-1] != "tail" {
		t.Fatalf("tail missing: %v", res.Files[githubComparePerPage:])
	}
}

func TestAppSignKeyAndRequestErrors(t *testing.T) {
	app := NewApp(1, []byte("not pem"))
	if _, err := app.signKey(); err == nil || !strings.Contains(err.Error(), "not PEM") {
		t.Fatalf("non-PEM signKey = %v", err)
	}
	if _, err := app.doAppRequest(context.Background(), http.MethodGet, "/x"); err == nil {
		t.Fatal("doAppRequest with a bad key must fail")
	}

	// A PKCS#8 key that is not RSA is rejected.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	nonRSA := NewApp(1, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER}))
	if _, err := nonRSA.signKey(); err == nil || !strings.Contains(err.Error(), "not RSA") {
		t.Fatalf("non-RSA signKey = %v", err)
	}

	// Malformed PKCS#8 body.
	_, rsaKey, err := ed25519.GenerateKey(rand.Reader)
	_ = rsaKey
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	good := NewApp(1, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}))
	if _, err := good.signKey(); err != nil {
		t.Fatalf("PKCS#8 RSA key rejected: %v", err)
	}

	badBody := NewApp(1, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}))
	if _, err := badBody.signKey(); err == nil || !strings.Contains(err.Error(), "parse app private key") {
		t.Fatalf("junk PKCS#8 = %v", err)
	}

	// BaseURL overrides and client injection.
	appGood := NewApp(1, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}))
	appGood.BaseURL = "https://api.example/"
	if appGood.apiBase() != "https://api.example" {
		t.Fatalf("apiBase = %q", appGood.apiBase())
	}
	if NewApp(1, nil).apiBase() != defaultGitHubAPI {
		t.Fatalf("default apiBase = %q", NewApp(1, nil).apiBase())
	}
	cl := &http.Client{}
	appGood.Client = cl
	if appGood.httpClient() == cl {
		t.Fatal("httpClient must copy the caller's client")
	}
	if NewApp(1, nil).httpClient() == nil {
		t.Fatal("default client missing")
	}
	if _, err := (&App{AppID: 1, PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}), BaseURL: "http://\x7f"}).doAppRequest(context.Background(), http.MethodGet, "/x"); err == nil {
		t.Fatal("unbuildable app request URL must fail")
	}
}

func TestAppInstallationAndLookupErrors(t *testing.T) {
	_, pemBytes := testAppKey(t)
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{nope"))
	}))
	defer badJSON.Close()
	app := NewApp(1, pemBytes)
	app.BaseURL = badJSON.URL
	if _, _, err := app.InstallationToken(context.Background(), 7); err == nil {
		t.Fatal("decode error must fail")
	}
	if _, err := app.LookupInstallation(context.Background(), "o/r"); err == nil {
		t.Fatal("lookup decode error must fail")
	}

	noToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "", "expires_at": time.Now()})
	}))
	defer noToken.Close()
	app = NewApp(1, pemBytes)
	app.BaseURL = noToken.URL
	if _, _, err := app.InstallationToken(context.Background(), 7); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("empty token = %v", err)
	}

	noID := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 0})
	}))
	defer noID.Close()
	app = NewApp(1, pemBytes)
	app.BaseURL = noID.URL
	if _, err := app.LookupInstallation(context.Background(), "o/r"); err == nil || !strings.Contains(err.Error(), "no id") {
		t.Fatalf("zero id = %v", err)
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	app = NewApp(1, pemBytes)
	app.BaseURL = closed.URL
	if _, _, err := app.InstallationToken(context.Background(), 7); err == nil {
		t.Fatal("transport error must fail")
	}
	if _, err := app.LookupInstallation(context.Background(), "o/r"); err == nil {
		t.Fatal("lookup transport error must fail")
	}
}

// TestAppTokenForSingleFlightCancellation waits on an in-flight token mint
// and cancels the second caller's context.
func TestAppTokenForSingleFlightCancellation(t *testing.T) {
	_, pemBytes := testAppKey(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 7})
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			started <- struct{}{}
			<-release
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "tok", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	app := NewApp(1, pemBytes)
	app.BaseURL = ts.URL

	go func() {
		_, _ = app.TokenFor(context.Background(), "o/r")
	}()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := app.TokenFor(ctx, "o/r"); err == nil {
		t.Fatal("a cancelled waiter must fail")
	}
	close(release)
}

func TestAppTokenForErrorPropagatesToWaiters(t *testing.T) {
	_, pemBytes := testAppKey(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			started <- struct{}{}
			<-release
			http.Error(w, "nope", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	app := NewApp(1, pemBytes)
	app.BaseURL = ts.URL

	errs := make(chan error, 2)
	go func() { _, err := app.TokenFor(context.Background(), "o/r"); errs <- err }()
	<-started
	go func() { _, err := app.TokenFor(context.Background(), "o/r"); errs <- err }()
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err == nil {
			t.Fatal("both callers must see the lookup failure")
		}
	}
}

func TestAdapterTokenHeadersAndMalformedBodies(t *testing.T) {
	var authHdr string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr = r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/compare") || strings.Contains(r.URL.Path, "/compare/") {
			_, _ = w.Write([]byte(`{"files":[]}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	ec := EventContext{Repository: Repository{FullName: "o/r"}, BaseSHA: "b", HeadSHA: "h"}

	// GitHub compare carries the bearer token.
	g := &GitHub{Token: "gh-tok", BaseURL: ts.URL}
	if res, err := g.ChangedFiles(context.Background(), ec); err != nil || !res.Complete {
		t.Fatalf("github ChangedFiles = %+v (err %v)", res, err)
	}
	if authHdr != "Bearer gh-tok" {
		t.Fatalf("github compare auth = %q", authHdr)
	}

	// GitHub PublishCheck propagates an App token error.
	appErr := &GitHub{BaseURL: "http://example.invalid", App: NewApp(1, []byte("not pem"))}
	if err := appErr.PublishCheck(context.Background(), "o/r", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("publish with a broken App must fail")
	}

	// Forgejo compare and status carry the token scheme.
	var fAuth string
	fsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fAuth = r.Header.Get("Authorization")
		if strings.Contains(r.URL.Path, "/compare/") {
			_, _ = w.Write([]byte(`{"files":[]}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer fsrv.Close()
	f := &Forgejo{Token: "fj-tok", BaseURL: fsrv.URL}
	if res, err := f.ChangedFiles(context.Background(), ec); err != nil || !res.Complete {
		t.Fatalf("forgejo ChangedFiles = %+v (err %v)", res, err)
	}
	if fAuth != "token fj-tok" {
		t.Fatalf("forgejo compare auth = %q", fAuth)
	}
	if err := f.PublishCheck(context.Background(), "o/r", "sha", "n", "queued", "", "", "", nil); err != nil {
		t.Fatalf("forgejo PublishCheck: %v", err)
	}
	if fAuth != "token fj-tok" {
		t.Fatalf("forgejo status auth = %q", fAuth)
	}

	// GitLab status carries PRIVATE-TOKEN.
	var glAuth string
	gsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		glAuth = r.Header.Get("PRIVATE-TOKEN")
		w.WriteHeader(http.StatusCreated)
	}))
	defer gsrv.Close()
	gl := &GitLab{Token: "gl-tok", BaseURL: gsrv.URL}
	if err := gl.PublishCheck(context.Background(), "g/p", "sha", "n", "queued", "", "", "", nil); err != nil {
		t.Fatalf("gitlab PublishCheck: %v", err)
	}
	if glAuth != "gl-tok" {
		t.Fatalf("gitlab status token = %q", glAuth)
	}

	// Malformed payloads inside a recognized shape fail the decode.
	if _, err := (&Forgejo{}).ParseEvent([]byte(`{"ref":"x","repository":123}`)); err == nil {
		t.Fatal("forgejo push with a bad repository must fail")
	}
	if _, err := (&Forgejo{}).ParseEvent([]byte(`{"pull_request":{"x":1},"number":"bad"}`)); err == nil {
		t.Fatal("forgejo PR with a bad number must fail")
	}
	// A PR without a head repository falls back to the base repository.
	ec2, err := (&Forgejo{}).ParseEvent([]byte(`{"action":"opened","pull_request":{"head":{"ref":"f","sha":"h"},"base":{"ref":"main","sha":"b"}},"repository":{"full_name":"o/r"}}`))
	if err != nil || ec2.HeadRepository.FullName != "o/r" || !ec2.Trusted {
		t.Fatalf("forgejo PR without head repo = %+v (err %v)", ec2, err)
	}
	if _, err := (&GitHub{}).ParseEvent([]byte(`{"ref":"x","repository":123}`)); err == nil {
		t.Fatal("github push with a bad repository must fail")
	}
	if _, err := (&GitHub{}).ParseEvent([]byte(`{"pull_request":{"x":1},"number":"bad"}`)); err == nil {
		t.Fatal("github PR with a bad number must fail")
	}
	if _, err := (&GitLab{}).ParseEvent([]byte(`{"object_kind":"push","ref":123}`)); err == nil {
		t.Fatal("gitlab push with a bad ref must fail")
	}
}

func TestGitLabFetchFileBodyReadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}))
	defer ts.Close()
	if _, err := (&GitLab{BaseURL: ts.URL}).FetchFile(context.Background(), "g/p", "f", "main"); err == nil {
		t.Fatal("a truncated body must fail")
	}
}

func TestAppInstallationTokenStatusError(t *testing.T) {
	_, pemBytes := testAppKey(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			http.Error(w, "rate limited", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int64{"id": 7})
	}))
	defer ts.Close()
	app := NewApp(1, pemBytes)
	app.BaseURL = ts.URL
	if _, _, err := app.InstallationToken(context.Background(), 7); err == nil || !strings.Contains(err.Error(), "token API 403") {
		t.Fatalf("status error = %v", err)
	}
	if _, err := app.TokenFor(context.Background(), "o/r"); err == nil {
		t.Fatal("TokenFor must propagate the mint failure")
	}
}

package forge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestNoRedirectClientNilBase(t *testing.T) {
	cl := NoRedirectClient(nil)
	if cl == nil || cl.CheckRedirect == nil {
		t.Fatal("NoRedirectClient(nil) must build a client with a redirect guard")
	}
	if err := cl.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	base := &http.Client{Timeout: 5}
	copied := NoRedirectClient(base)
	if copied == base {
		t.Fatal("the caller's client must not be mutated")
	}
	if base.CheckRedirect != nil || copied.Timeout != 5 {
		t.Fatalf("copy semantics broken: %+v vs %+v", base, copied)
	}
}

func TestMatchesTriggerRemainingCovers(t *testing.T) {
	tagByRef := EventContext{Event: "push", Ref: "refs/tags/v2.0.0"}
	tagMatch := map[string]pipeline.Trigger{"push": {Tags: []string{"v1.*"}}}

	if ok, _ := MatchesTrigger(tagMatch, tagByRef); ok {
		t.Fatal("tag ref without ec.Tag must still be filtered by tags")
	}
	if ok, _ := MatchesTrigger(map[string]pipeline.Trigger{"push": {Tags: []string{"  "}}}, tagByRef); ok {
		t.Fatal("blank tag pattern must not match")
	}
	// A tags-only trigger is tag-scoped: it must not admit a branch push.
	if ok, key := MatchesTrigger(tagMatch, EventContext{Event: "push", Ref: "refs/heads/main"}); ok || key != "" {
		t.Fatalf("tags-only trigger on a branch = %v,%q, want no match", ok, key)
	}
	if ok, key := MatchesTrigger(map[string]pipeline.Trigger{"push": {Tags: []string{"v2.*"}}}, EventContext{Event: "push", Tag: "v2.1.0"}); !ok || key != "push" {
		t.Fatal("tag glob must match the tag name")
	}
	if _, _ = MatchesTrigger(map[string]pipeline.Trigger{"push": {Tags: []string{"["}}}, tagByRef); false {
		t.Fatal("unreachable")
	}
	if ok, _ := MatchesTrigger(map[string]pipeline.Trigger{"push": {Tags: []string{"["}}}, tagByRef); ok {
		t.Fatal("an invalid glob must not match")
	}
}

func TestGitHubBaseURLAndClientOverrides(t *testing.T) {
	var gotPath, gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"content":"` + base64.StdEncoding.EncodeToString([]byte("hello")) + `","encoding":"base64"}`))
	}))
	defer ts.Close()

	g := &GitHub{Token: "tok", BaseURL: ts.URL + "/", Client: ts.Client()}
	content, err := g.FetchFile(context.Background(), "o/r", "/dir/file.yaml", "main")
	if err != nil {
		t.Fatalf("FetchFile: %v", err)
	}
	if content != "hello" {
		t.Fatalf("content = %q", content)
	}
	if gotPath != "/repos/o/r/contents/dir/file.yaml" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if g.apiBase() != ts.URL {
		t.Fatalf("apiBase = %q", g.apiBase())
	}
	if (&GitHub{}).apiBase() != defaultGitHubAPI {
		t.Fatalf("default apiBase = %q", (&GitHub{}).apiBase())
	}
}

func TestGitHubEnvTokenAndCloneCredential(t *testing.T) {
	t.Setenv("KIWI_GITHUB_TOKEN", "env-token")
	g := &GitHub{}
	tok, err := g.TokenFor(context.Background(), "")
	if err != nil || tok != "env-token" {
		t.Fatalf("TokenFor = %q (err %v)", tok, err)
	}
	if cred, ok := g.CloneCredentialFor("o/r"); !ok || cred != "env-token" {
		t.Fatalf("CloneCredentialFor = %q,%v", cred, ok)
	}

	g = &GitHub{Token: "pat"}
	if cred, ok := g.CloneCredentialFor("o/r"); !ok || cred != "pat" {
		t.Fatalf("explicit token clone credential = %q,%v", cred, ok)
	}

	t.Setenv("KIWI_GITHUB_TOKEN", "")
	if cred, ok := (&GitHub{}).CloneCredentialFor("o/r"); ok || cred != "" {
		t.Fatalf("no token clone credential = %q,%v", cred, ok)
	}
}

func TestGitHubFetchFileErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close()

	g := &GitHub{BaseURL: base}
	if _, err := g.FetchFile(context.Background(), "o/r", "f", "main"); err == nil {
		t.Fatal("transport error must fail")
	}

	g = &GitHub{BaseURL: "http://\x7f"}
	if _, err := g.FetchFile(context.Background(), "o/r", "f", "main"); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}

	g = &GitHub{BaseURL: "http://example.invalid", App: NewApp(1, []byte("not pem"))}
	if _, err := g.FetchFile(context.Background(), "o/r", "f", "main"); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("app key error = %v", err)
	}

	cases := map[string]struct {
		status  int
		body    string
		wantSub string
	}{
		"status":     {http.StatusNotFound, "missing", "GitHub API 404"},
		"decode":     {http.StatusOK, "{nope", ""},
		"encoding":   {http.StatusOK, `{"content":"aGk=","encoding":"utf-8"}`, "unsupported GitHub content encoding"},
		"bad base64": {http.StatusOK, `{"content":"!!!","encoding":"base64"}`, ""},
	}
	for name, tc := range cases {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		_, err := (&GitHub{BaseURL: ts.URL}).FetchFile(context.Background(), "o/r", "f", "main")
		ts.Close()
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: error = %v, want %q", name, err, tc.wantSub)
		}
	}
}

func TestGitHubParseEventEdges(t *testing.T) {
	g := &GitHub{}
	// A pull_request key present but null is a push event.
	ec, err := g.ParseEvent([]byte(`{"pull_request":null,"ref":"refs/heads/main","after":"abc","before":"def","repository":{"full_name":"o/r"}}`))
	if err != nil || ec.Event != "push" || ec.Ref != "refs/heads/main" {
		t.Fatalf("null pull_request = %+v (err %v)", ec, err)
	}
	// Deleted pushes clear the head SHA.
	ec, err = g.ParseEvent([]byte(`{"ref":"refs/heads/gone","deleted":true,"after":"abc","repository":{"full_name":"o/r"}}`))
	if err != nil || ec.HeadSHA != "" {
		t.Fatalf("deleted push = %+v (err %v)", ec, err)
	}
	// All-zero after SHA clears the head SHA.
	ec, err = g.ParseEvent([]byte(`{"ref":"refs/heads/x","after":"` + strings.Repeat("0", 40) + `","repository":{"full_name":"o/r"}}`))
	if err != nil || ec.HeadSHA != "" {
		t.Fatalf("zero-sha push = %+v (err %v)", ec, err)
	}
	// A tagged push records the tag.
	ec, err = g.ParseEvent([]byte(`{"ref":"refs/tags/v1","after":"abc","repository":{"full_name":"o/r"}}`))
	if err != nil || ec.Tag != "v1" {
		t.Fatalf("tag push = %+v (err %v)", ec, err)
	}
	// An empty ref yields no event.
	ec, err = g.ParseEvent([]byte(`{"repository":{"full_name":"o/r"}}`))
	if err != nil || ec.Event != "" || ec.Ref != "" {
		t.Fatalf("empty ref = %+v (err %v)", ec, err)
	}
	// A PR without an action yields no event.
	ec, err = g.ParseEvent([]byte(`{"pull_request":{"number":1}}`))
	if err != nil || ec.Event != "" {
		t.Fatalf("empty action = %+v (err %v)", ec, err)
	}
	// A PR without a head repository is treated as same-repo (trusted).
	ec, err = g.ParseEvent([]byte(`{"action":"opened","pull_request":{"head":{"ref":"feature","sha":"h"},"base":{"ref":"main","sha":"b"}},"repository":{"full_name":"o/r"}}`))
	if err != nil || !ec.Trusted || ec.HeadRepository.FullName != "o/r" {
		t.Fatalf("same-repo PR = %+v (err %v)", ec, err)
	}
	// A cross-repo PR is untrusted and carries the fork coordinates.
	ec, err = g.ParseEvent([]byte(`{"action":"opened","pull_request":{"head":{"ref":"feature","sha":"h","repo":{"full_name":"fork/r","clone_url":"https://x"}},"base":{"ref":"main","sha":"b"}},"repository":{"id":7,"full_name":"o/r"}}`))
	if err != nil || ec.Trusted || ec.HeadRepository.FullName != "fork/r" {
		t.Fatalf("fork PR = %+v (err %v)", ec, err)
	}
	if ec.Repository.ID != "7" || ec.Repository.Forge != "github" {
		t.Fatalf("repo = %+v", ec.Repository)
	}
	if _, err := g.ParseEvent([]byte("not json")); err == nil {
		t.Fatal("malformed body must fail")
	}
	if allZerosSHA("") {
		t.Fatal("empty sha must not be all-zeros")
	}
	if !allZerosSHA("0000") || allZerosSHA("0001") {
		t.Fatal("allZerosSHA logic broken")
	}
}

func TestGitHubPublishCheckEdges(t *testing.T) {
	g := &GitHub{}
	if err := g.PublishCheck(context.Background(), "", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("missing repo must fail")
	}
	if err := g.PublishCheck(context.Background(), "o/r", "", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("missing sha must fail")
	}

	var body map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()
	err := (&GitHub{BaseURL: ts.URL}).PublishCheck(context.Background(), "o/r", strings.Repeat("a", 40), "build/test",
		"completed", "success", "https://ci.example/run/1", "all good",
		[]CheckAnnotation{{Path: "a.go", Line: 3, Level: "failure", Message: "boom"}})
	if err != nil {
		t.Fatalf("PublishCheck: %v", err)
	}
	if body["conclusion"] != "success" || body["details_url"] != "https://ci.example/run/1" || body["completed_at"] == nil {
		t.Fatalf("body = %v", body)
	}
	if body["external_id"] != "kiwi-"+strings.Repeat("a", 12)+"-build-test" {
		t.Fatalf("external_id = %v", body["external_id"])
	}
	output, ok := body["output"].(map[string]any)
	if !ok || output["annotations"] == nil {
		t.Fatalf("output = %v", body["output"])
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if err := (&GitHub{BaseURL: closed.URL}).PublishCheck(context.Background(), "o/r", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("transport error must fail")
	}
	if err := (&GitHub{BaseURL: "http://\x7f"}).PublishCheck(context.Background(), "o/r", "sha", "n", "queued", "", "", "", nil); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}
}

func TestGitHubChangedFilesErrors(t *testing.T) {
	ec := EventContext{Repository: Repository{FullName: "o/r"}, BaseSHA: "b", HeadSHA: "h"}
	if res, err := (&GitHub{}).ChangedFiles(context.Background(), EventContext{}); err != nil || res.Complete || res.Files != nil {
		t.Fatalf("empty context = %+v (err %v)", res, err)
	}
	if res, err := (&GitHub{}).ChangedFiles(context.Background(), EventContext{Repository: Repository{FullName: "o/r"}}); err != nil || res.Complete {
		t.Fatalf("missing shas = %+v (err %v)", res, err)
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Close()
	if _, err := (&GitHub{BaseURL: closed.URL}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("transport error must fail")
	}
	if _, err := (&GitHub{BaseURL: "http://\x7f"}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("unbuildable request URL must fail")
	}

	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer status.Close()
	if _, err := (&GitHub{BaseURL: status.URL}).ChangedFiles(context.Background(), ec); err == nil || !strings.Contains(err.Error(), "compare API 500") {
		t.Fatalf("status error = %v", err)
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{nope"))
	}))
	defer badJSON.Close()
	if _, err := (&GitHub{BaseURL: badJSON.URL}).ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("decode error must fail")
	}

	appErr := &GitHub{BaseURL: "http://example.invalid", App: NewApp(1, []byte("not pem"))}
	if _, err := appErr.ChangedFiles(context.Background(), ec); err == nil {
		t.Fatal("token error must fail")
	}
}

func TestGitHubShortSHAAndSlug(t *testing.T) {
	if got := shortSHA("abc"); got != "abc" {
		t.Fatalf("shortSHA = %q", got)
	}
	if got := shortSHA(strings.Repeat("x", 20)); len(got) != 12 {
		t.Fatalf("shortSHA = %q", got)
	}
	if got := slug("build / test!"); got != "build---test" {
		t.Fatalf("slug = %q", got)
	}
	if got := slug("!!!"); got != "pipeline" {
		t.Fatalf("slug(all punctuation) = %q", got)
	}
}

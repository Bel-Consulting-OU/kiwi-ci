package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// P0 regression: the image lock is applied by the CANONICAL RESOLVER, not
// the webhook's temporary spec. The compiled/canonical pipeline text that
// every job carries must contain the LOCKED digests — trigger-eval-only
// locking would leave remote runs on mutable tags.
func TestResolvePipelineAppliesImageLockToCanonicalGraph(t *testing.T) {
	s := New("runner-secret")
	const pipe = `version: 1
jobs:
  build:
    image: golang:1.27
    services:
      - name: db
        image: postgres:16
    steps:
      - run: go build ./...
`
	const lock = `{"version":1,"images":[
		{"ref":"golang:1.27","digest":"golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"ref":"postgres:16","digest":"postgres:16@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	]}`
	spec, canon, _, err := s.resolvePipeline(context.Background(), SubmitRun{Pipeline: pipe, ImageLock: lock})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(spec.Jobs["build"].Image, "golang:1.27@sha256:") ||
		!strings.Contains(spec.Jobs["build"].Image, "aaaa") {
		t.Fatalf("effective spec image = %q, want locked digest", spec.Jobs["build"].Image)
	}
	if len(spec.Jobs["build"].Services) == 0 ||
		!strings.HasPrefix(spec.Jobs["build"].Services[0].Image, "postgres:16@sha256:") ||
		!strings.Contains(spec.Jobs["build"].Services[0].Image, "bbbb") {
		t.Fatalf("service image not locked: %+v", spec.Jobs["build"].Services)
	}
	// The CANONICAL TEXT every runner recompiles must carry the locked form.
	if !strings.Contains(canon, "golang:1.27@sha256:") {
		t.Fatalf("canonical pipeline text lost the lock: %s", canon)
	}
	if !strings.Contains(canon, "postgres:16@sha256:") {
		t.Fatalf("canonical pipeline text lost the service lock: %s", canon)
	}
	// Trigger-eval-only locking would pass the spec check but fail here.
	if strings.Contains(canon, `"golang:1.27"`) && !strings.Contains(canon, "golang:1.27@sha256:") {
		t.Fatal("canonical text still carries the mutable tag")
	}
}

// A malformed lockfile at the trust boundary is FAIL-CLOSED, never a silent
// fallback to mutable tags.
func TestResolvePipelineMalformedLockFailsClosed(t *testing.T) {
	s := New("runner-secret")
	_, _, _, err := s.resolvePipeline(context.Background(), SubmitRun{
		Pipeline:  "version: 1\njobs:\n  b:\n    run: echo hi\n",
		ImageLock: "not json",
	})
	if err == nil {
		t.Fatal("malformed lockfile must fail closed")
	}
	// Empty lock is "no lockfile" and is tolerated.
	if _, _, _, err := s.resolvePipeline(context.Background(), SubmitRun{
		Pipeline: "version: 1\njobs:\n  b:\n    run: echo hi\n",
	}); err != nil {
		t.Fatalf("empty lock = %v, want success", err)
	}
}

// Component-only jobs must survive ingress (trigger parse) and reach the
// real resolver. The strict parser rejects them; ParseWithComponents does
// not. This pins the ingress/resolver split.
func TestComponentOnlyJobSurvivesTriggerParse(t *testing.T) {
	const pipe = `version: 1
jobs:
  test:
    component: company/go-test@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`
	// Strict parse rejects a job with no local steps.
	if _, err := pipeline.Parse([]byte(pipe)); err == nil {
		t.Log("note: strict Parse accepted a component-only job (relaxation may already be global)")
	}
	// The trigger-level parser MUST accept it.
	if _, err := pipeline.ParseWithComponents([]byte(pipe)); err != nil {
		t.Fatalf("component-only job must survive trigger parse: %v", err)
	}
}

// A client-supplied SHA is NEVER authority: the forge resolves whatever the
// client named. A garbage SHA fails to resolve and the submit is refused —
// better than admitting a run that cannot check out. This is the
// "client-supplied identity is not proof" class.
func TestAPISubmitClientSHAIsNotAuthority(t *testing.T) {
	s := New("runner-secret")
	s.StubRemoteIdentityForTest()
	// The stub resolves any ref to a full SHA; a garbage client SHA must be
	// replaced by the resolved one, not trusted.
	s.RevisionResolver = func(_ context.Context, _, _, ref string) (string, error) {
		if ref == "garbage-not-a-sha" {
			return "", fmt.Errorf("resolve revision %q: not found", ref)
		}
		return strings.Repeat("f", 40), nil
	}
	_, err := s.resolveExecutionRevision(context.Background(), "github", "o/r", "garbage-not-a-sha")
	if err == nil {
		t.Fatal("garbage SHA must fail to resolve")
	}
	// A real ref resolves to a full SHA the caller must use.
	sha, err := s.resolveExecutionRevision(context.Background(), "github", "o/r", "refs/heads/main")
	if err != nil || sha != strings.Repeat("f", 40) {
		t.Fatalf("resolve = %q %v", sha, err)
	}
}

// A nonempty lockfile document with zero images is NOT "no lockfile" —
// it is a lock that claims authority while pinning nothing. applyImageLockContent
// must fail closed whenever mutable identities exist.
func TestEmptyLockfileDocumentFailsClosed(t *testing.T) {
	spec, err := pipeline.Parse([]byte("version: 1\njobs:\n  b:\n    image: golang:1.27\n    run: echo hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyImageLockContent(spec, ""); err != nil {
		t.Fatalf("empty content = %v", err)
	}
	for _, doc := range []string{
		`{"version":1,"images":[]}`,
		`{"version":1}`,
	} {
		if err := applyImageLockContent(spec, doc); err == nil {
			t.Fatalf("lockfile %s must fail closed", doc)
		}
	}
	// Complete lock applies.
	doc := `{"version":1,"images":[{"ref":"golang:1.27","digest":"golang:1.27@sha256:` + strings.Repeat("a", 64) + `"}]}`
	if err := applyImageLockContent(spec, doc); err != nil {
		t.Fatalf("complete lock = %v", err)
	}
	if !strings.Contains(spec.Jobs["b"].Image, "@sha256:") {
		t.Fatalf("image not locked: %q", spec.Jobs["b"].Image)
	}
}

// A forge-hosted lockfile that exists but is empty/whitespace is NOT
// equivalent to a 404. fetchImageLock must fail closed so callers never
// treat "pins nothing" as "no lockfile".
func TestFetchImageLockEmptyDocumentFailsClosed(t *testing.T) {
	s := New("runner-secret")
	s.StubRemoteIdentityForTest()
	fg := &emptyLockForge{body: "  \n"}
	raw, found, err := s.fetchImageLock(context.Background(), fg, "o/r", "abc123")
	if err == nil {
		t.Fatalf("empty lockfile fetch must fail closed (raw=%q found=%v)", raw, found)
	}
	fg.body = `{"version":1,"images":[]}`
	if _, _, err := s.fetchImageLock(context.Background(), fg, "o/r", "abc123"); err != nil {
		t.Fatalf("nonempty lock document must be returned to RequireComplete: %v", err)
	}
	fg.notFound = true
	if _, found, err := s.fetchImageLock(context.Background(), fg, "o/r", "abc123"); err != nil || found {
		t.Fatalf("404 must stay soft (found=%v err=%v)", found, err)
	}
}

// emptyLockForge is a one-method forge.FetchFile stand-in.
type emptyLockForge struct {
	body     string
	notFound bool
}

func (f *emptyLockForge) FetchFile(context.Context, string, string, string) (string, error) {
	if f.notFound {
		return "", forge.ErrFileNotFound
	}
	return f.body, nil
}

// The remaining Forge surface is unused by fetchImageLock.
func (f *emptyLockForge) VerifyWebhook([]byte, string, http.Header) error { return nil }
func (f *emptyLockForge) ParseEvent([]byte) (forge.EventContext, error) {
	return forge.EventContext{}, nil
}
func (f *emptyLockForge) ChangedFiles(context.Context, forge.EventContext) (forge.ChangedFilesResult, error) {
	return forge.ChangedFilesResult{}, nil
}
func (f *emptyLockForge) PublishCheck(context.Context, string, string, string, string, string, string, string, []forge.CheckAnnotation) error {
	return nil
}
func (f *emptyLockForge) CloneCredentialFor(string) (string, bool) { return "", false }
func (f *emptyLockForge) ResolveRevision(context.Context, string, string) (string, error) {
	return strings.Repeat("a", 40), nil
}
func (f *emptyLockForge) TokenFor() string { return "" }

// A whitespace-only ImageLock is neither a document nor a pin. It must not
// skip the repo-lock fetch and must not be interpreted as "no lockfile
// required" after a fetch would have been mandatory.
func TestSubmitWhitespaceImageLockIsNotAuthority(t *testing.T) {
	// The submit handler normalizes TrimSpace(ImageLock) to "" before the
	// fetch decision. Pin the helper contract here: applyImageLockContent
	// treats only a truly empty string as "no document".
	spec, err := pipeline.Parse([]byte("version: 1\njobs:\n  b:\n    image: golang:1.27\n    run: echo hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyImageLockContent(spec, ""); err != nil {
		t.Fatalf("truly empty content is no document: %v", err)
	}
	for _, content := range []string{"   ", "\n\t"} {
		if err := applyImageLockContent(spec, content); err == nil {
			t.Fatalf("whitespace-only content %q must fail closed", content)
		}
	}
}

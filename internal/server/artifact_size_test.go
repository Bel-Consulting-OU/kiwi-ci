package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestArtifactContractSizeRejectedBeforeStaging proves a declared max_size is
// enforced at the reader: an oversized Content-Length is rejected with 413
// and the body is never read at all. The request body panics on any Read, so
// observing 413 proves the limit was applied before staging/hashing.
func TestArtifactContractSizeRejectedBeforeStaging(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const pipeline = `version: 1
jobs:
  j:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo hi
    artifacts:
      - name: app
        paths: [dist/**]
        max_size: 10
`
	runnerID, task := leaseArtifactJob(t, s, pipeline)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/app", panicReader{})
	req.ContentLength = 1 << 20 // 1 MiB vs the 10-byte contract
	req.Header.Set("Authorization", "Bearer token")
	for k, v := range leaseHeaders(task, runnerID) {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized Content-Length = %d, want 413: %s", w.Code, w.Body.String())
	}
}

// panicReader fails the test if the handler reads the body before applying
// the artifact size limit.
type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("artifact body was read despite the size limit")
}

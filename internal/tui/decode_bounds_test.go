package tui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeBodiesBounded is the H1-F regression: ReadPage and ListJobs must
// decode through a bounded reader, so a response body past the cap fails the
// decode instead of buffering without bound.
func TestDecodeBodiesBounded(t *testing.T) {
	oldPage, oldJobs := maxTUILogPageBytes, maxTUIListJobsBytes
	maxTUILogPageBytes, maxTUIListJobsBytes = 1024, 1024
	t.Cleanup(func() { maxTUILogPageBytes, maxTUIListJobsBytes = oldPage, oldJobs })

	// Valid JSON only after the cap: the leading padding alone exceeds it, so
	// the truncated stream cannot be decoded.
	big := "[" + strings.Repeat(" ", 4096) + "]"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	c := &Client{Server: srv.URL}
	if _, err := c.ReadPage(context.Background(), "run-1", 0, 10); err == nil {
		t.Fatal("ReadPage decoded an over-cap body")
	}
	if _, err := c.ListJobs(context.Background(), "run-1"); err == nil {
		t.Fatal("ListJobs decoded an over-cap body")
	}

	// A small body still decodes normally.
	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/jobs") {
			_, _ = w.Write([]byte(`[{"key":"build"}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"seq":1,"job_key":"build","line":"hi"}]`))
	}))
	defer small.Close()
	sc := &Client{Server: small.URL}
	if page, err := sc.ReadPage(context.Background(), "run-1", 0, 10); err != nil || len(page) != 1 {
		t.Fatalf("small ReadPage = %v, %v", page, err)
	}
	if keys, err := sc.ListJobs(context.Background(), "run-1"); err != nil || len(keys) != 1 || keys[0] != "build" {
		t.Fatalf("small ListJobs = %v, %v", keys, err)
	}
}

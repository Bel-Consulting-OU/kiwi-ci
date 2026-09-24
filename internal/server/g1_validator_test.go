package server

// G1-C endpoint regression: a /tests payload carrying a NUL (or other XML
// control byte) in an identity field is refused with 400 by the authoritative
// validator BEFORE any store call, so it can never reach SQL (where NUL fails
// 22P05) or be accepted by memory mode while the XML parser rejects it.

import (
	"net/http"
	"strings"
	"testing"
)

func TestEndpointRejectsControlByteIdentityBeforeStore(t *testing.T) {
	badCase := []map[string]any{{"name": "a\u0000b", "passed": true}}
	body := e5RawUploadBody("job-a", map[string]any{"tests": 1, "cases": badCase})

	t.Run("memory", func(t *testing.T) {
		s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
		w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "control byte") {
			t.Fatalf("memory upload = %d %q, want 400 with a control-byte reason", w.Code, w.Body.String())
		}
		s.mu.Lock()
		reports := len(s.reports)
		s.mu.Unlock()
		if reports != 0 {
			t.Fatalf("refused NUL report was stored: %d", reports)
		}
	})

	t.Run("db", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "control byte") {
			t.Fatalf("db upload = %d %q, want 400 with a control-byte reason", w.Code, w.Body.String())
		}
		f.mu.Lock()
		reports := len(f.reports)
		f.mu.Unlock()
		if reports != 0 {
			t.Fatalf("refused NUL report reached the store: %d", reports)
		}
	})
}

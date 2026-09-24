package runner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// TestLogBatchPostMasksEncodedSecrets is the H1-B regression: the log batch
// POST path must mask DERIVED/encoded secret forms, not only the raw value.
// With the pre-fix raw Mask call the base64 and hex forms of the lease token
// reached the control-plane log sink unchanged.
func TestLogBatchPostMasksEncodedSecrets(t *testing.T) {
	const secret = "lease-token"
	masker := &secrets.Masker{}
	masker.Add(secret)

	var mu sync.Mutex
	var bodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	fn := r.logBatchPost(basicTask(payloadPipeline), masker)
	line := "token-b64=" + base64.StdEncoding.EncodeToString([]byte(secret)) +
		" token-hex=" + hex.EncodeToString([]byte(secret))
	if err := fn(context.Background(), logBatch{Sequence: 1, ID: "batch-1", Lines: []logLine{{Job: "build", Step: "s", Line: line}}}); err != nil {
		t.Fatalf("logBatchPost: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("posted %d log batches, want 1", len(bodies))
	}
	// The request envelope legitimately carries the lease credential; only
	// the delivered log LINES must be masked.
	var posted struct {
		Lines []struct {
			Line string `json:"line"`
		} `json:"lines"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &posted); err != nil {
		t.Fatalf("decode log batch: %v (%s)", err, bodies[0])
	}
	if len(posted.Lines) != 1 {
		t.Fatalf("log batch carried %d lines, want 1: %s", len(posted.Lines), bodies[0])
	}
	gotLine := posted.Lines[0].Line
	for _, form := range []string{
		secret,
		base64.StdEncoding.EncodeToString([]byte(secret)),
		hex.EncodeToString([]byte(secret)),
	} {
		if strings.Contains(gotLine, form) {
			t.Fatalf("encoded secret form %q leaked to the log sink: %q", form, gotLine)
		}
	}
	if !strings.Contains(gotLine, "***") {
		t.Fatalf("log line was not redacted: %q", gotLine)
	}
}

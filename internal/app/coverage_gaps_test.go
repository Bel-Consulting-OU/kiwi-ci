package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDoIdempotentRetryMatrix pins the retry contract: transport errors and
// 429/5xx retry with the SAME idempotency key, 409 and other 4xx are final,
// and a canceled context aborts immediately.
func TestDoIdempotentRetryMatrix(t *testing.T) {
	ctx := context.Background()

	t.Run("transport then success reuses key", func(t *testing.T) {
		var keys []string
		first := true
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			if first {
				first = false
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, err := hj.Hijack()
					if err == nil {
						_ = conn.Close()
						return
					}
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"ok":true}`)
		}))
		defer srv.Close()
		c := &opsClient{base: srv.URL, client: srv.Client()}
		var out struct {
			OK bool `json:"ok"`
		}
		if err := c.doIdempotent(ctx, http.MethodPost, "/runs", map[string]string{"a": "b"}, &out); err != nil {
			t.Fatalf("transport retry: %v", err)
		}
		if !out.OK {
			t.Fatal("response not decoded")
		}
		if len(keys) != 2 || keys[0] != keys[1] || keys[0] == "" {
			t.Fatalf("idempotency keys = %v, want one stable key across the retry", keys)
		}
	})

	t.Run("server error then client error", func(t *testing.T) {
		attempts := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, "first boom")
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "second boom")
		}))
		defer srv.Close()
		c := &opsClient{base: srv.URL, client: srv.Client()}
		err := c.doIdempotent(ctx, http.MethodPost, "/runs", map[string]string{}, nil)
		if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "second boom") {
			t.Fatalf("err = %v, want the final 400", err)
		}
		if attempts != 2 {
			t.Fatalf("attempts = %d, want 2", attempts)
		}
	})

	t.Run("conflict is final", func(t *testing.T) {
		attempts := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, "IDEMPOTENCY_KEY_REUSED")
		}))
		defer srv.Close()
		c := &opsClient{base: srv.URL, client: srv.Client()}
		err := c.doIdempotent(ctx, http.MethodPost, "/runs", map[string]string{}, nil)
		if err == nil || !strings.Contains(err.Error(), "409") || attempts != 1 {
			t.Fatalf("409 err = %v after %d attempts, want one final refusal", err, attempts)
		}
	})

	t.Run("canceled context aborts", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		c := &opsClient{base: "http://127.0.0.1:1", client: http.DefaultClient}
		if err := c.doIdempotent(canceled, http.MethodPost, "/runs", map[string]string{}, nil); err == nil {
			t.Fatal("canceled context reported success")
		}
	})
}

// TestOutboxDeadLetterStoreOpenFailure covers the store-open refusal before
// any mutation is attempted.
func TestOutboxDeadLetterStoreOpenFailure(t *testing.T) {
	if _, err := openOutboxDeadLetterStore(context.Background(), "postgres://%zz"); err == nil {
		t.Fatal("unparsable database URL accepted")
	}
}

// TestOutboxDeadLetterMutationStrayPositional covers the second positional
// before any flag: the command must fail with a flag error, not pick one ID
// silently.
func TestOutboxDeadLetterMutationStrayPositional(t *testing.T) {
	err := outboxDeadLetterMutation(context.Background(), "requeue", []string{"id-one", "id-two", "--database-url", "postgres://%zz"})
	if err == nil {
		t.Fatal("stray positional accepted")
	}
}

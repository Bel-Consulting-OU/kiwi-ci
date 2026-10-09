package server

// Readiness surfacing for the migration 0048/0053 run/key identity index.

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// runKeyIndexFakeStore wraps dbFakeStore with the RunKeyIndexStore probe so
// the readiness/health surface can be exercised without PostgreSQL.
type runKeyIndexFakeStore struct {
	*dbFakeStore
	present bool
	err     error
}

func (f *runKeyIndexFakeStore) RunKeyIndexPresent(ctx context.Context) (bool, error) {
	return f.present, f.err
}

// TestReadinessSurfacesRunKeyIndex pins the operator signal: /readiness is
// 503 with a fixed body while the run/key identity index is missing (the
// state a dirty migration 0048 leaves), 200 once present, and 503 with the
// unproven state when the probe itself fails.
func TestReadinessSurfacesRunKeyIndex(t *testing.T) {
	s := New("admin-tok")
	f := &runKeyIndexFakeStore{dbFakeStore: newDBFakeStore(), present: false}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, s, http.MethodGet, "/readiness", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing index readiness = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "run-key-index-missing" {
		t.Fatalf("missing index X-Kiwi-State = %q, want run-key-index-missing", got)
	}
	if w.Body.String() != runKeyIndexMissingBody+"\n" {
		t.Fatalf("missing index body = %q, want the fixed body", w.Body.String())
	}

	f.present = true
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusOK {
		t.Fatalf("present index readiness = %d, want 200: %s", w.Code, w.Body.String())
	}

	f.err = errors.New("probe failed")
	w = doJSON(t, s, http.MethodGet, "/readiness", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unproven index readiness = %d, want 503", w.Code)
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "run-key-index-unproven" {
		t.Fatalf("unproven index X-Kiwi-State = %q, want run-key-index-unproven", got)
	}
	if w.Body.String() != runKeyIndexUnknownBody+"\n" {
		t.Fatalf("unproven index body = %q, want the fixed body", w.Body.String())
	}
}

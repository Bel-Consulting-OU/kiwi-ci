package server

// Coverage for the small pure branches that gate durability classification,
// the OIDC rotation fence selection and the strict /tests payload decoder.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestNotDurableNilStaysNil: a nil persist error must not be wrapped into a
// "not durable" failure (that would turn a healthy snapshot write into a
// 503).
func TestNotDurableNilStaysNil(t *testing.T) {
	if got := notDurable(nil); got != nil {
		t.Fatalf("notDurable(nil) = %v, want nil", got)
	}
	base := errors.New("disk full")
	wrapped := notDurable(base)
	var nd *stateNotDurableError
	if !errors.As(wrapped, &nd) {
		t.Fatalf("notDurable(err) = %T, want *stateNotDurableError", wrapped)
	}
	if !errors.Is(wrapped, base) {
		t.Fatal("wrapped cause is not reachable")
	}
	if s := wrapped.Error(); !strings.Contains(s, "state not durable") || !strings.Contains(s, "disk full") {
		t.Fatalf("message %q lacks the classified cause", s)
	}
}

// fencedDB wraps a Store and adds the rotation fence, modelling a PostgreSQL
// store used as the fallback fencer.
type fencedDB struct {
	storage.Store
	withFence func(kind string, fn func() error) error
}

func (f fencedDB) WithClusterKeyRotationFence(_ context.Context, kind string, fn func() error) error {
	if f.withFence != nil {
		return f.withFence(kind, fn)
	}
	return fn()
}

// TestClusterKeyRotationFencerSelection: the cluster store owns the ring so
// it is preferred; the DB store is the fallback; with neither the fence is
// nil (dev/in-memory mode) and callers must rotate unlocked.
func TestClusterKeyRotationFencerSelection(t *testing.T) {
	// Cluster store wins even when the DB could also fence.
	cluster := newFencedClusterStore()
	dbCalled := false
	s := New("shared-dev-tok")
	s.ClusterKeys = cluster
	s.DB = fencedDB{Store: newDBFakeStore(), withFence: func(string, func() error) error {
		dbCalled = true
		return nil
	}}
	fencer := s.clusterKeyRotationFencer()
	if fencer == nil {
		t.Fatal("no fencer selected")
	}
	if err := fencer.WithClusterKeyRotationFence(t.Context(), "oidc", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if dbCalled {
		t.Fatal("DB fencer used although the cluster store could fence")
	}

	// Cluster store without the fence: the DB fallback is used.
	s2 := New("shared-dev-tok")
	s2.ClusterKeys = &StaticClusterKeyStore{}
	s2.DB = fencedDB{Store: newDBFakeStore(), withFence: func(string, func() error) error {
		dbCalled = true
		return nil
	}}
	if err := s2.clusterKeyRotationFencer().WithClusterKeyRotationFence(t.Context(), "oidc", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !dbCalled {
		t.Fatal("DB fallback fencer was not used")
	}

	// Neither: nil, and the rotation still proceeds unlocked.
	s3 := New("shared-dev-tok")
	s3.ClusterKeys = &StaticClusterKeyStore{}
	if got := s3.clusterKeyRotationFencer(); got != nil {
		t.Fatalf("fencer with neither surface = %T, want nil", got)
	}
}

// TestDecodeTestReportPayloadBranches: the strict decoder passes an absent
// report through, rejects unknown fields and trailing data with a 400, and
// accepts a well-formed report.
func TestDecodeTestReportPayloadBranches(t *testing.T) {
	// Absent or JSON null: no report, but not an error (the handler treats
	// the report as optional).
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null")} {
		w := httptest.NewRecorder()
		rep, ok := decodeTestReportPayload(w, raw)
		if !ok || rep.ID != "" || w.Code != 200 {
			t.Fatalf("raw %q = (%+v, %v, code %d)", raw, rep, ok, w.Code)
		}
	}
	// Unknown field: rejected before any durable work.
	w := httptest.NewRecorder()
	if _, ok := decodeTestReportPayload(w, json.RawMessage(`{"id":"a","surprise":1}`)); ok {
		t.Fatal("unknown field accepted")
	}
	if w.Code != 400 || !strings.Contains(w.Body.String(), "bad json") {
		t.Fatalf("unknown field response = %d %q", w.Code, w.Body.String())
	}
	// Trailing data: rejected even though the first value decoded.
	w = httptest.NewRecorder()
	if _, ok := decodeTestReportPayload(w, json.RawMessage(`{"id":"a"}{"id":"b"}`)); ok {
		t.Fatal("trailing data accepted")
	}
	if w.Code != 400 || !strings.Contains(w.Body.String(), "trailing data") {
		t.Fatalf("trailing data response = %d %q", w.Code, w.Body.String())
	}
	// A well-formed report round-trips the fields the handler needs.
	w = httptest.NewRecorder()
	rep, ok := decodeTestReportPayload(w, json.RawMessage(`{"id":"rep-1","run_id":"run-1","job_key":"build","tests":2,"cases":[{"name":"t","passed":true}]}`))
	if !ok || rep.ID != "rep-1" || rep.JobKey != "build" || len(rep.Cases) != 1 || !rep.Cases[0].Passed {
		t.Fatalf("valid payload = (%+v, %v, code %d)", rep, ok, w.Code)
	}
	if rep.Tests != 2 {
		t.Fatalf("tests = %d, want 2", rep.Tests)
	}
}

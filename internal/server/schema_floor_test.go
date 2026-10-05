package server

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// floorStore overrides the fake store's schema floor (and read error) for
// gate tests.
type floorStore struct {
	*dbFakeStore
	floor int
	err   error
}

func (f *floorStore) SchemaCompatibilityFloor(context.Context) (int, error) {
	return f.floor, f.err
}

func testClientWithFloor(t *testing.T, floor int, ferr error) (*Server, *testClient) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(&floorStore{dbFakeStore: newDBFakeStore(), floor: floor, err: ferr}); err != nil {
		t.Fatal(err)
	}
	return s, &testClient{t: t, h: s.Handler()}
}

func submitBody() map[string]any {
	return map[string]any{"repo_url": "https://github.com/o/r.git", "repo_full_name": "o/r",
		"ref": "refs/heads/main", "pipeline": "version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n"}
}

// TestSchemaFloorMutationFence: every DB mutation surface refuses while the
// floor is incompatible — readiness-based LB removal is not a boundary.
func TestSchemaFloorMutationFence(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	s, c := testClientWithFloor(t, maxV+1, nil)
	_ = s
	auth := map[string]string{"Authorization": "Bearer token"}
	for name, req := range map[string]struct {
		method, path string
		body         any
	}{
		"submit":      {http.MethodPost, "/api/v1/runs", submitBody()},
		"webhook":     {http.MethodPost, "/hooks/github", map[string]any{}},
		"schedule":    {http.MethodPost, "/api/v1/schedules/x/trigger", map[string]any{}},
		"login":       {http.MethodPost, "/api/v1/login", map[string]any{}},
		"runner next": {http.MethodPost, "/api/v1/runners/ghost/next", map[string]any{}},
	} {
		w := c.do(req.method, req.path, req.body, auth)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s = %d, want 503 (schema fence): %s", name, w.Code, w.Body.String())
		}
		if w.Header().Get("X-Kiwi-State") != "schema-incompatible" {
			t.Fatalf("%s missing schema-incompatible state header", name)
		}
	}
	// Reads stay reachable so orchestration can observe the state.
	if w := c.do(http.MethodGet, "/api/v1/runs", nil, auth); w.Code == http.StatusServiceUnavailable {
		t.Fatalf("reads must not be fenced: %d", w.Code)
	}
}

// TestSchemaFloorReadFailureFailsClosed: an unreadable floor is NOT
// "compatible": readiness 503 and every mutation refused.
func TestSchemaFloorReadFailureFailsClosed(t *testing.T) {
	s, c := testClientWithFloor(t, 0, errors.New("permission denied for column compatible_from"))
	_ = s
	if w := c.do(http.MethodGet, "/readiness", nil, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness with an unreadable floor = %d, want 503", w.Code)
	}
	auth := map[string]string{"Authorization": "Bearer token"}
	if w := c.do(http.MethodPost, "/api/v1/runs", submitBody(), auth); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("submit with an unreadable floor = %d, want 503", w.Code)
	}
	if w := c.do(http.MethodPost, "/api/v1/runners/ghost/next", map[string]any{}, auth); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("next with an unreadable floor = %d, want 503", w.Code)
	}
}

// TestCompatibleFloorIsNeverCachedAcrossAnIncompatibleMigration: a replica
// that observed the pre-migration floor must refuse immediately after the
// floor advances — no positive cache window.
func TestCompatibleFloorIsNeverCachedAcrossAnIncompatibleMigration(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	fs := &floorStore{dbFakeStore: newDBFakeStore(), floor: maxV}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(fs); err != nil {
		t.Fatal(err)
	}
	c := &testClient{t: t, h: s.Handler()}
	auth := map[string]string{"Authorization": "Bearer token"}
	if w := c.do(http.MethodGet, "/readiness", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("pre-migration readiness = %d", w.Code)
	}
	// The newer replica commits its migration.
	fs.floor = maxV + 1
	// The very next mutation must be refused.
	if w := c.do(http.MethodPost, "/api/v1/runs", submitBody(), auth); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("submit after the floor advanced = %d, want 503 (positive cache window)", w.Code)
	}
	if w := c.do(http.MethodGet, "/readiness", nil, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after the floor advanced = %d, want 503", w.Code)
	}
}

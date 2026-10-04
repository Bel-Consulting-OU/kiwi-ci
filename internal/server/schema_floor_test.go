package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// floorStore overrides the fake store's schema floor for gate tests.
type floorStore struct {
	*dbFakeStore
	floor int
}

func (f *floorStore) SchemaCompatibilityFloor(context.Context) (int, error) {
	return f.floor, nil
}

// TestSchemaFloorGatesReadinessAndLeases: a database whose recorded
// compatibility floor demands a NEWER binary must turn readiness into 503 and
// refuse new leases, so an old replica cannot mutate shapes it does not know.
func TestSchemaFloorGatesReadinessAndLeases(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		floor     int
		wantReady int
	}{
		{"current", maxV, http.StatusOK},
		{"newer floor", maxV + 1, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewPersistent("token", "token", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SwitchToDB(&floorStore{dbFakeStore: newDBFakeStore(), floor: tc.floor}); err != nil {
				t.Fatal(err)
			}
			c := &testClient{t: t, h: s.Handler()}
			w := c.do(http.MethodGet, "/readiness", nil, nil)
			if w.Code != tc.wantReady {
				t.Fatalf("readiness = %d, want %d (%s)", w.Code, tc.wantReady, w.Body.String())
			}
			w = c.do(http.MethodPost, "/api/v1/runners/ghost/next", map[string]any{}, map[string]string{"Authorization": "Bearer token"})
			if tc.floor > maxV {
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("next under a newer floor = %d, want 503", w.Code)
				}
			} else if w.Code == http.StatusServiceUnavailable {
				t.Fatalf("next under a compatible floor = 503")
			}
		})
	}
}

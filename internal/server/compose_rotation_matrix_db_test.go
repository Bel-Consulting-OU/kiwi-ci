package server

// DB-mode half of the credential-rotation matrix: the same request matrix
// runs through the real middleware+router against a configured store, where
// the snapshot record comes from SnapshotStore and test-intelligence reads
// durable aggregates instead of the in-memory maps.

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestComposeRotationIdenticalAuthorizationMatrixDB parametrizes the DB-mode
// request matrix over both halves of a repository-scoped rotation pair: the
// store-backed snapshot listing/download and the durable test-intelligence
// path must answer identically for both credentials.
func TestComposeRotationIdenticalAuthorizationMatrixDB(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	rec := composeSnapshotTierUpload(t, s, hdrs)
	recID := rec.ID
	f.mu.Lock()
	f.runs["run-b"] = model.Run{ID: "run-b", Repo: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b", Status: model.StatusSuccess}
	f.mu.Unlock()

	for raw, p := range map[string]auth.Principal{
		"rot-a": {Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}}},
		"rot-b": {Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}}},
	} {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatal(err)
		}
	}

	cases := []composeMatrixCase{
		{"runs collection", http.MethodGet, "/api/v1/runs", "", http.StatusOK},
		{"runs collection page", http.MethodGet, "/api/v1/runs?limit=1", "", http.StatusOK},
		{"run visible", http.MethodGet, "/api/v1/runs/run-c", "", http.StatusOK},
		{"run invisible", http.MethodGet, "/api/v1/runs/run-b", "", http.StatusForbidden},
		{"snapshot listing visible", http.MethodGet, "/api/v1/runs/run-c/snapshots", "", http.StatusForbidden},
		{"snapshot listing invisible", http.MethodGet, "/api/v1/runs/run-b/snapshots", "", http.StatusForbidden},
		{"snapshot download visible", http.MethodGet, "/api/v1/runs/run-c/snapshots/" + recID, "", http.StatusForbidden},
		{"runner registration", http.MethodPost, "/api/v1/runners/register", `{"name":"r","protocol_min":3,"protocol_max":3}`, http.StatusUnauthorized},
		{"test-intelligence visible", http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "", http.StatusOK},
		{"test-intelligence invisible", http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-b", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		a := composeCapture(t, s, tc.method, tc.path, "rot-a", tc.body)
		b := composeCapture(t, s, tc.method, tc.path, "rot-b", tc.body)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: outcomes differ:\nrot-a: %d %q %v\nrot-b: %d %q %v",
				tc.name, a.Status, a.Body, a.Header, b.Status, b.Body, b.Header)
		}
		if a.Status != tc.want {
			t.Fatalf("%s = %d, want %d: %s", tc.name, a.Status, tc.want, a.Body)
		}
	}
	// Control: the runner token clears the runner-tier entry for the same
	// store configuration.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "runner-tok", `{"name":"r","protocol_min":3,"protocol_max":3}`); w.Code != http.StatusOK {
		t.Fatalf("runner-token registration in DB mode = %d: %s", w.Code, w.Body.String())
	}
}

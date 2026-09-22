package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// snapAdminAuthzToken installs one store principal under its own bearer.
func snapAdminAuthzToken(t *testing.T, s *Server, raw string, p auth.Principal) {
	t.Helper()
	if err := s.AuthStore.AddToken(raw, p); err != nil {
		t.Fatal(err)
	}
}

// snapAdminAuthzUpload uploads one real snapshot archive through the runner
// lease and returns the record ID.
func snapAdminAuthzUpload(t *testing.T, s *Server, hdrs map[string]string) string {
	t.Helper()
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.SnapshotRecord
	if err := jsonUnmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" {
		t.Fatal("snapshot upload returned no record id")
	}
	return rec.ID
}

// TestSnapshotDownloadIsAdminTierMemory pins the L4-A contract in memory
// mode: the snapshot surface is admin tier end to end. The record LISTING
// carries every workspace entry (name, mode, size, SHA-256) plus the manifest
// root and archive digests, so it demands the same admin action as the
// archive download — a global read role or a full repository grant is
// answered 403 for both — while an admin principal and the admin token both
// get the listing (manifest included) and the archive.
func TestSnapshotDownloadIsAdminTierMemory(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t) // run-c on github.com/o/repo-a
	recID := snapAdminAuthzUpload(t, s, hdrs)

	snapAdminAuthzToken(t, s, "snap-reader", auth.Principal{
		Subject: "global-reader",
		Roles:   []auth.Role{auth.RoleRead},
	})
	snapAdminAuthzToken(t, s, "snap-repo-reader", auth.Principal{
		Subject: "repo-reader",
		Repositories: map[string]auth.RepositoryPermission{
			"o/repo-a": {Read: true, ArtifactRead: true},
		},
	})
	snapAdminAuthzToken(t, s, "snap-admin", auth.Principal{
		Subject: "admin-user",
		Roles:   []auth.Role{auth.RoleAdmin},
	})

	for _, tok := range []string{"snap-reader", "snap-repo-reader"} {
		if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", tok, ""); w.Code != http.StatusForbidden {
			t.Fatalf("snapshot listing with %s = %d, want 403: %s", tok, w.Code, w.Body.String())
		}
	}
	for _, tok := range []string{"snap-reader", "snap-repo-reader"} {
		if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+recID, tok, ""); w.Code != http.StatusForbidden {
			t.Fatalf("snapshot download with %s = %d, want 403: %s", tok, w.Code, w.Body.String())
		}
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "snap-admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin-principal listing = %d, want 200: %s", w.Code, w.Body.String())
	}
	for _, want := range []string{recID, `"entries"`, `"out.txt"`, `"sha256"`, `"root_sha256"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("admin listing body missing %s: %s", want, w.Body.String())
		}
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+recID, "snap-admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin-principal download = %d, want 200: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Snapshot-SHA256") == "" || w.Body.Len() == 0 {
		t.Fatal("admin-principal download did not stream the archive")
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+recID, "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("admin-token download = %d, want 200", w.Code)
	}
}

// TestSnapshotDownloadIsAdminTierDB is the DB/CAS counterpart: the record
// comes from the SnapshotStore and the bytes from CAS, and the same tier
// split holds — listing and download are both 403 for readers and 200 for an
// admin principal.
func TestSnapshotDownloadIsAdminTierDB(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	recID := snapAdminAuthzUpload(t, s, hdrs)
	f.mu.Lock()
	recs := append([]model.SnapshotRecord(nil), f.snapshots...)
	f.mu.Unlock()
	found := false
	for _, rec := range recs {
		if rec.ID == recID {
			found = true
		}
	}
	if !found {
		t.Fatal("DB snapshot record not persisted")
	}

	snapAdminAuthzToken(t, s, "snap-reader", auth.Principal{
		Subject: "global-reader",
		Roles:   []auth.Role{auth.RoleRead},
	})
	snapAdminAuthzToken(t, s, "snap-repo-reader", auth.Principal{
		Subject: "repo-reader",
		Repositories: map[string]auth.RepositoryPermission{
			"github.com/o/repo-a": {Read: true, ArtifactRead: true},
		},
	})
	snapAdminAuthzToken(t, s, "snap-admin", auth.Principal{
		Subject: "admin-user",
		Roles:   []auth.Role{auth.RoleAdmin},
	})

	for _, tok := range []string{"snap-reader", "snap-repo-reader"} {
		if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", tok, ""); w.Code != http.StatusForbidden {
			t.Fatalf("DB snapshot listing with %s = %d, want 403: %s", tok, w.Code, w.Body.String())
		}
	}
	for _, tok := range []string{"snap-reader", "snap-repo-reader"} {
		if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+recID, tok, ""); w.Code != http.StatusForbidden {
			t.Fatalf("DB snapshot download with %s = %d, want 403: %s", tok, w.Code, w.Body.String())
		}
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "snap-admin", ""); w.Code != http.StatusOK {
		t.Fatalf("DB admin-principal listing = %d, want 200: %s", w.Code, w.Body.String())
	} else if !strings.Contains(w.Body.String(), `"entries"`) || !strings.Contains(w.Body.String(), `"out.txt"`) {
		t.Fatalf("DB admin listing body missing the manifest: %s", w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+recID, "snap-admin", ""); w.Code != http.StatusOK {
		t.Fatalf("DB admin-principal download = %d, want 200: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+recID, "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("DB admin-token download = %d, want 200", w.Code)
	}
}

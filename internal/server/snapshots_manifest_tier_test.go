package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// snapManifestUpload uploads one real archive through the lease and returns
// its stored record (including the workspace manifest).
func snapManifestUpload(t *testing.T, s *Server, hdrs map[string]string) model.SnapshotRecord {
	t.Helper()
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.SnapshotRecord
	if err := jsonUnmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Entries) == 0 || rec.Entries[0].Path != "out.txt" {
		t.Fatalf("upload response has no manifest: %+v", rec)
	}
	return rec
}

// snapManifestEveryRepoPermission is the widest possible repository-scoped
// grant: read plus every other permission the model has. It still must not
// open the snapshot surface (L4-A).
func snapManifestEveryRepoPermission() auth.Principal {
	return auth.Principal{
		Subject: "repo-superuser",
		Roles:   []auth.Role{auth.RoleRead, auth.RoleArtifactRead},
		Repositories: map[string]auth.RepositoryPermission{
			"o/repo-a": {
				Read: true, Run: true, TrustedRun: true, Approve: true,
				Cancel: true, Rerun: true, ArtifactRead: true,
			},
		},
	}
}

// TestSnapshotListingManifestIsAdminOnlyMemory is the L4-A response-body pin
// in memory mode: a repository grant that includes every permission cannot
// obtain the workspace inventory — the 403 body carries no file name, no
// entry array, no digest — while the admin listing returns the full manifest.
func TestSnapshotListingManifestIsAdminOnlyMemory(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	rec := snapManifestUpload(t, s, hdrs)

	snapAdminAuthzToken(t, s, "repo-superuser", snapManifestEveryRepoPermission())
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "repo-superuser", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("repo-grant listing = %d, want 403: %s", w.Code, w.Body.String())
	}
	assertNoManifestLeak(t, w.Body.String(), rec)

	w = doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin listing = %d, want 200: %s", w.Code, w.Body.String())
	}
	assertManifestVisible(t, w.Body.String(), rec)
}

// TestSnapshotListingManifestIsAdminOnlyDB is the DB/CAS counterpart: the
// SnapshotStore records carry the same manifest and are gated by the same
// admin action.
func TestSnapshotListingManifestIsAdminOnlyDB(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	rec := snapManifestUpload(t, s, hdrs)

	snapAdminAuthzToken(t, s, "repo-superuser", snapManifestEveryRepoPermission())
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "repo-superuser", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("repo-grant DB listing = %d, want 403: %s", w.Code, w.Body.String())
	}
	assertNoManifestLeak(t, w.Body.String(), rec)

	w = doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin DB listing = %d, want 200: %s", w.Code, w.Body.String())
	}
	assertManifestVisible(t, w.Body.String(), rec)
}

// TestSnapshotListingGlobalReadCannotSeeManifest pins the plain global-read
// case on both tiers' shared action: a RoleRead principal is refused the
// snapshot listing, which is ActionAdmin.
func TestSnapshotListingGlobalReadCannotSeeManifest(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	rec := snapManifestUpload(t, s, hdrs)
	snapAdminAuthzToken(t, s, "global-reader", auth.Principal{Subject: "global-reader", Roles: []auth.Role{auth.RoleRead}})
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "global-reader", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("global-read listing = %d, want 403", w.Code)
	}
	assertNoManifestLeak(t, w.Body.String(), rec)
}

// assertNoManifestLeak proves a response body exposes none of the workspace
// inventory: no entry path, no manifest/archive digest, no manifest shape.
func assertNoManifestLeak(t *testing.T, body string, rec model.SnapshotRecord) {
	t.Helper()
	secrets := []string{`"entries"`, `"root_sha256"`, `"sha256"`, `"path"`, rec.RootSHA256, rec.SHA256}
	for _, e := range rec.Entries {
		secrets = append(secrets, e.Path, e.SHA256)
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(body, secret) {
			t.Fatalf("response body leaked manifest material %q: %s", secret, body)
		}
	}
}

// assertManifestVisible proves the admin listing carries the full manifest of
// the addressed run.
func assertManifestVisible(t *testing.T, body string, rec model.SnapshotRecord) {
	t.Helper()
	wants := []string{rec.ID, rec.RootSHA256, rec.SHA256, `"root_sha256"`, `"sha256"`, `"entries"`}
	for _, e := range rec.Entries {
		wants = append(wants, e.Path, e.SHA256)
	}
	for _, want := range wants {
		if want == "" {
			continue
		}
		if !strings.Contains(body, want) {
			t.Fatalf("admin listing body missing %q: %s", want, body)
		}
	}
}

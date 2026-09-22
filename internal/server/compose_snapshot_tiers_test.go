package server

// Snapshot tiers x repository permission shapes, through the real
// middleware+router: the snapshot LISTING and the archive DOWNLOAD are admin
// tier for every repository-scoped grant shape — bare alias, canonical,
// explicit deny, canonically equivalent conflict, artifact-only and global
// read — while an admin-role principal (including one whose repository map is
// itself conflicting) receives the listing and the archive.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// composeSnapshotDeniedPrincipals returns every repository-permission shape
// a repository READ grant can take; all of them must be answered 403 on both
// snapshot routes. runRead records whether the credential can still read the
// addressed RUN, which proves the 403 is the snapshot tier and not a broken
// grant (it is false for deny/conflict/artifact-only shapes, which cannot
// read the run either).
type composeSnapshotShape struct {
	principal auth.Principal
	runRead   bool
}

func composeSnapshotDeniedPrincipals() map[string]composeSnapshotShape {
	all := auth.RepositoryPermission{
		Read: true, Run: true, TrustedRun: true, Approve: true,
		Cancel: true, Rerun: true, ArtifactRead: true,
	}
	return map[string]composeSnapshotShape{
		"global-read-role": {runRead: true, principal: auth.Principal{Subject: "global-read", Roles: []auth.Role{auth.RoleRead}}},
		"bare-alias-read": {runRead: true, principal: auth.Principal{
			Subject:      "bare-alias-read",
			Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}},
		}},
		"canonical-read": {runRead: true, principal: auth.Principal{
			Subject:      "canonical-read",
			Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}},
		}},
		"canonical-every-permission": {runRead: true, principal: auth.Principal{
			Subject:      "canonical-superuser",
			Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": all},
		}},
		"canonical-explicit-deny": {principal: auth.Principal{
			Subject:      "canonical-deny",
			Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {}},
		}},
		"bare-alias-explicit-deny": {principal: auth.Principal{
			Subject:      "bare-deny",
			Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {}},
		}},
		"conflict-read-vs-deny": {principal: auth.Principal{
			Subject: "conflict-read-deny",
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/o/repo-a":     {Read: true},
				"GitHub.com:443/o/repo-a": {},
			},
		}},
		"conflict-read-vs-artifact": {principal: auth.Principal{
			Subject: "conflict-read-artifact",
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/o/repo-a":  {Read: true},
				"github.com./o/repo-a": {ArtifactRead: true},
			},
		}},
		"artifact-read-only": {principal: auth.Principal{
			Subject:      "artifact-only",
			Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {ArtifactRead: true}},
		}},
		"global-read-plus-conflict": {principal: auth.Principal{
			Subject: "global-read-conflict",
			Roles:   []auth.Role{auth.RoleRead},
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/o/repo-a":     {Read: true},
				"GitHub.com:443/o/repo-a": {},
			},
		}},
	}
}

// composeSnapshotAdminPrincipals returns the admin-role shapes that must
// receive the snapshot surface, including the repository-conflicting map the
// admin role outranks.
func composeSnapshotAdminPrincipals() map[string]auth.Principal {
	return map[string]auth.Principal{
		"admin-role": {Subject: "admin-role", Roles: []auth.Role{auth.RoleAdmin}},
		"admin-role-with-conflict": {
			Subject: "admin-conflict",
			Roles:   []auth.Role{auth.RoleAdmin},
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/o/repo-a":     {Read: true},
				"GitHub.com:443/o/repo-a": {},
			},
		},
	}
}

// composeSnapshotTierUpload uploads one real archive through the runner lease
// and returns the stored record (manifest included).
func composeSnapshotTierUpload(t *testing.T, s *Server, hdrs map[string]string) model.SnapshotRecord {
	t.Helper()
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.SnapshotRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" || len(rec.Entries) == 0 {
		t.Fatalf("upload response has no manifest: %+v", rec)
	}
	return rec
}

// composeAssertNoManifestLeak proves a body exposes no workspace inventory.
func composeAssertNoManifestLeak(t *testing.T, body string, rec model.SnapshotRecord) {
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

// composeAssertManifestVisible proves a listing carries the full manifest.
func composeAssertManifestVisible(t *testing.T, body string, rec model.SnapshotRecord) {
	t.Helper()
	wants := []string{rec.ID}
	for _, e := range rec.Entries {
		wants = append(wants, e.Path)
	}
	for _, want := range wants {
		if want == "" {
			continue
		}
		if !strings.Contains(body, want) {
			t.Fatalf("listing body missing %q: %s", want, body)
		}
	}
}

// TestComposeSnapshotTiersRepositoryPermissionShapesMemory runs every
// repository-permission shape against the memory-mode snapshot routes.
func TestComposeSnapshotTiersRepositoryPermissionShapesMemory(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	rec := composeSnapshotTierUpload(t, s, hdrs)
	composeSnapshotTiersAssert(t, s, rec)
}

// TestComposeSnapshotTiersRepositoryPermissionShapesDB is the DB-mode
// counterpart: the record comes from SnapshotStore and the same shape matrix
// must resolve identically.
func TestComposeSnapshotTiersRepositoryPermissionShapesDB(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	rec := composeSnapshotTierUpload(t, s, hdrs)
	composeSnapshotTiersAssert(t, s, rec)
}

// composeSnapshotTiersAssert installs the shape matrix and drives both
// snapshot routes through the real handler for each credential.
func composeSnapshotTiersAssert(t *testing.T, s *Server, rec model.SnapshotRecord) {
	t.Helper()
	for name, shape := range composeSnapshotDeniedPrincipals() {
		p := shape.principal
		if err := s.AuthStore.AddToken(name, p); err != nil {
			t.Fatal(err)
		}
		// The per-run read route documents whether the credential is a real
		// repository reader: where it is, the 403 below is the snapshot tier,
		// not a broken grant.
		wantRunRead := http.StatusForbidden
		if shape.runRead {
			wantRunRead = http.StatusOK
		}
		if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c", name, ""); w.Code != wantRunRead {
			t.Fatalf("%s: run read = %d, want %d: %s", name, w.Code, wantRunRead, w.Body.String())
		}
		w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", name, "")
		if w.Code != http.StatusForbidden || w.Body.String() != "forbidden\n" {
			t.Fatalf("%s: snapshot listing = %d %q, want the opaque 403", name, w.Code, w.Body.String())
		}
		composeAssertNoManifestLeak(t, w.Body.String(), rec)
		w = doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, name, "")
		if w.Code != http.StatusForbidden || w.Body.String() != "forbidden\n" {
			t.Fatalf("%s: snapshot download = %d %q, want the opaque 403", name, w.Code, w.Body.String())
		}
		if w.Header().Get("X-Kiwi-Snapshot-SHA256") != "" {
			t.Fatalf("%s: refused download advertised the archive digest", name)
		}
	}

	for name, p := range composeSnapshotAdminPrincipals() {
		if err := s.AuthStore.AddToken(name, p); err != nil {
			t.Fatal(err)
		}
		w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", name, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: snapshot listing = %d, want 200: %s", name, w.Code, w.Body.String())
		}
		composeAssertManifestVisible(t, w.Body.String(), rec)
		w = doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, name, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: snapshot download = %d, want 200: %s", name, w.Code, w.Body.String())
		}
		if w.Header().Get("X-Kiwi-Snapshot-SHA256") != rec.SHA256 || w.Body.Len() == 0 {
			t.Fatalf("%s: download did not stream the archive (sha256 header %q)", name, w.Header().Get("X-Kiwi-Snapshot-SHA256"))
		}
	}

	// The admin token is the non-principal control on the same routes.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("admin-token listing = %d, want 200", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("admin-token download = %d, want 200", w.Code)
	}
}

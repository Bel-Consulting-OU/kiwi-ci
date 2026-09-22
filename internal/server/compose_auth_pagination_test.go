package server

// Composition of the credential layer with the keyset-paginated runs
// collection: a token FILE whose subject is ambiguous must fail the startup
// load closed and must never serve a paginated collection, while a legal
// rotation pair must page exactly per its shared repository grants with no
// cursor ever crossing into a repository the credential cannot read.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// composeTokenFile persists principals in the on-disk digest->principal
// format the control plane loads from auth.tokens_file.
func composeTokenFile(t *testing.T, dir string, m map[string]auth.Principal) string {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// composeCanonicalKey renders an ACL grant in the explicit r1: spelling the
// strict token-file Load schema requires (a legacy "host/owner/name" string is
// ambiguous and refused).
func composeCanonicalKey(host, fullName string) string {
	return auth.RepoIdentity{Host: host, FullName: fullName}.Serialized()
}

// TestComposeConflictingSubjectTokenFileFailsClosed composes the startup
// credential load with the paginated collection: two credentials for one
// subject with different effective principals (each allowed to read a
// DIFFERENT repository) make the token file load fail, and neither
// credential may then authenticate into any read route — the collection of
// both repositories is served only to credentials whose grants are
// unambiguous.
func TestComposeConflictingSubjectTokenFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	conflictPath := composeTokenFile(t, dir, map[string]auth.Principal{
		auth.TokenDigest("conflict-a"): {Subject: "svc-ambiguous", Repositories: map[string]auth.RepositoryPermission{composeCanonicalKey("github.com", "o/repo-a"): {Read: true}}},
		auth.TokenDigest("conflict-b"): {Subject: "svc-ambiguous", Repositories: map[string]auth.RepositoryPermission{composeCanonicalKey("github.com", "o/repo-b"): {Read: true}}},
	})
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthStore.AddToken("valid", auth.Principal{Subject: "valid", Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}}}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	runsPaginationSeed(t, s, []model.Run{
		{ID: "run-a", Status: model.StatusSuccess, CreatedAt: base.Add(time.Second), Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"},
		{ID: "run-b", Status: model.StatusSuccess, CreatedAt: base.Add(2 * time.Second), Repo: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b"},
	})

	// The startup load (the same call internal/app wiring makes) fails closed
	// and names the ambiguous subject.
	loadErr := s.AuthStore.Load(conflictPath)
	if loadErr == nil {
		t.Fatal("a token file with a conflicting subject loaded")
	}
	if !strings.Contains(loadErr.Error(), `subject "svc-ambiguous"`) {
		t.Fatalf("load error %v does not name the ambiguous subject", loadErr)
	}

	// No pagination or per-run endpoint serves anything under the ambiguous
	// principal: the credentials never enter the store.
	for _, tok := range []string{"conflict-a", "conflict-b"} {
		for _, path := range []string{"/api/v1/runs", "/api/v1/runs?limit=1", "/api/v1/runs/run-a", "/api/v1/runs/run-b"} {
			w := doJSON(t, s, http.MethodGet, path, tok, "")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s with %s = %d, want 401: %s", path, tok, w.Code, w.Body.String())
			}
		}
	}

	// The failed load left the store intact: the valid credential pages
	// exactly its own repository.
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs?limit=1", "valid", "")
	if w.Code != http.StatusOK {
		t.Fatalf("valid credential = %d: %s", w.Code, w.Body.String())
	}
	if ids := runIDs(t, w.Body.String()); strings.Join(ids, ",") != "run-a" {
		t.Fatalf("valid credential page = %v, want only run-a", ids)
	}
	if w.Header().Get("X-Kiwi-Next-Cursor") != "" {
		t.Fatal("valid credential page carried a cursor for the unreachable run-b")
	}
	// Sanity: the ambiguous repositories really exist.
	if ids := runIDs(t, doJSON(t, s, http.MethodGet, "/api/v1/runs", "admin-tok", "").Body.String()); strings.Join(ids, ",") != "run-b,run-a" {
		t.Fatalf("admin page = %v, want the whole collection", ids)
	}
}

// composeRotationPaginationServer loads a rotation pair (one subject, two
// tokens, identical effective principals granting read on repo-a only) and
// seeds an interleaved run collection: repo-a runs at i=0,3,6,9, repo-b runs
// everywhere else, one second apart so the keyset order is deterministic.
func composeRotationPaginationServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	path := composeTokenFile(t, dir, map[string]auth.Principal{
		auth.TokenDigest("rot-1"): {Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{composeCanonicalKey("github.com", "o/repo-a"): {Read: true}}},
		auth.TokenDigest("rot-2"): {Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{composeCanonicalKey("github.com", "o/repo-a"): {Read: true}}},
	})
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthStore.Load(path); err != nil {
		t.Fatalf("rotation pair failed to load: %v", err)
	}
	base := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	runs := make([]model.Run, 0, 10)
	for i := 0; i < 10; i++ {
		runs = append(runs, runsPaginationRun(i, base, i%3 == 0))
	}
	runsPaginationSeed(t, s, runs)
	return s
}

// composeRotationVisibleIDs lists the repo-a run ids newest-first.
func composeRotationVisibleIDs() []string {
	return []string{"run-0009", "run-0006", "run-0003", "run-0000"}
}

// TestComposeRotationPairPaginationSharedGrants walks the collection with
// both halves of the rotation pair: identical pages and cursors, only the
// granted repository visible, and every cursor decodes to the last VISIBLE
// run of its page (the auth layer is in the loop on every page read, so a
// cursor can never be derived from a run the credential cannot read).
func TestComposeRotationPairPaginationSharedGrants(t *testing.T) {
	s := composeRotationPaginationServer(t)

	pages1 := walkRunsPages(t, s, "rot-1", 2, 8)
	pages2 := walkRunsPages(t, s, "rot-2", 2, 8)
	if len(pages1) != 2 || len(pages2) != 2 {
		t.Fatalf("walks = %d / %d pages, want 2 each", len(pages1), len(pages2))
	}
	for i := range pages1 {
		if strings.Join(pages1[i].ids, ",") != strings.Join(pages2[i].ids, ",") || pages1[i].cursor != pages2[i].cursor {
			t.Fatalf("page %d: rot-1 %v/%q != rot-2 %v/%q", i, pages1[i].ids, pages1[i].cursor, pages2[i].ids, pages2[i].cursor)
		}
	}
	var seen []string
	for i, page := range pages1 {
		if len(page.ids) == 0 {
			t.Fatalf("page %d is empty", i)
		}
		if page.cursor == "" && i != len(pages1)-1 {
			t.Fatalf("page %d ended the walk early", i)
		}
		if page.limitCap != strconv.Itoa(storage.MaxRunsPageLimit) {
			t.Fatalf("page %d limit cap = %q", i, page.limitCap)
		}
		for _, id := range page.ids {
			if !strings.HasPrefix(id, "run-") {
				t.Fatalf("unexpected id %q", id)
			}
			n, err := strconv.Atoi(strings.TrimPrefix(id, "run-"))
			if err != nil {
				t.Fatal(err)
			}
			if n%3 != 0 {
				t.Fatalf("page %d leaked the ungranted repository run %s", i, id)
			}
			seen = append(seen, id)
		}
		if page.cursor != "" {
			decoded, ok := decodeRunsCursor(page.cursor)
			if !ok {
				t.Fatalf("page %d cursor does not decode", i)
			}
			last := page.ids[len(page.ids)-1]
			if decoded.id != last {
				t.Fatalf("page %d cursor id = %q, want the last visible run %q", i, decoded.id, last)
			}
			n, err := strconv.Atoi(strings.TrimPrefix(decoded.id, "run-"))
			if err != nil || n%3 != 0 {
				t.Fatalf("page %d cursor %q is not a granted-repository run", i, decoded.id)
			}
		}
	}
	if strings.Join(seen, ",") != strings.Join(composeRotationVisibleIDs(), ",") {
		t.Fatalf("rotation walk = %v, want exactly %v", seen, composeRotationVisibleIDs())
	}

	// Rotation in the middle of a walk: the second page is requested with the
	// OTHER token and the SAME cursor, which may not change the result.
	page1 := doJSON(t, s, http.MethodGet, "/api/v1/runs?limit=2", "rot-1", "")
	if page1.Code != http.StatusOK {
		t.Fatalf("first page = %d: %s", page1.Code, page1.Body.String())
	}
	if ids := runIDs(t, page1.Body.String()); strings.Join(ids, ",") != "run-0009,run-0006" {
		t.Fatalf("first page = %v", ids)
	}
	cursor := page1.Header().Get("X-Kiwi-Next-Cursor")
	if cursor == "" {
		t.Fatal("first page carried no next cursor")
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs?limit=2&cursor="+url.QueryEscape(cursor), "rot-2", "")
	if w.Code != http.StatusOK {
		t.Fatalf("rotated continuation = %d: %s", w.Code, w.Body.String())
	}
	if ids := runIDs(t, w.Body.String()); strings.Join(ids, ",") != "run-0003,run-0000" {
		t.Fatalf("rotated continuation = %v, want the remaining visible runs", ids)
	}
	if w.Header().Get("X-Kiwi-Next-Cursor") != "" {
		t.Fatal("rotated continuation carried a cursor past the last visible run")
	}

	// The per-run route agrees with the collection for both halves: the
	// granted run is readable, the ungranted one is refused, identically.
	for _, tok := range []string{"rot-1", "rot-2"} {
		if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-0009", tok, ""); w.Code != http.StatusOK {
			t.Fatalf("visible run with %s = %d", tok, w.Code)
		}
		if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-0008", tok, ""); w.Code != http.StatusForbidden {
			t.Fatalf("ungranted run with %s = %d, want 403", tok, w.Code)
		}
	}
}

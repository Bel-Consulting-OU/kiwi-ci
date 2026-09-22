package server

// Real-PostgreSQL half of the auth x pagination composition: every test creates
// its OWN throwaway database (fresh name, dropped on cleanup) on the server
// named by KIWI_TEST_POSTGRES_URL, then runs the same credential-file and
// keyset-pagination flows the memory-mode compose tests cover, against a live
// store. Gated like every other *_it_test.go here (skipped when the variable
// is unset, and in -short mode).

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// composeFreshPGDatabase creates a throwaway database on the PostgreSQL
// instance named by KIWI_TEST_POSTGRES_URL and points this test's DSN at it,
// so the per-test throwaway SCHEMA helper (and every store opened through it)
// lives in a database no other test — or another agent's process — shares.
// The database is dropped (terminating its backends first) on cleanup.
func composeFreshPGDatabase(t *testing.T) string {
	t.Helper()
	base := pgITServerDSN(t)
	ctx := context.Background()
	adminCfg, err := pgx.ParseConfig(base)
	if err != nil {
		t.Fatalf("parse KIWI_TEST_POSTGRES_URL: %v", err)
	}
	admin, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("connect to KIWI_TEST_POSTGRES_URL: %v", err)
	}
	dbName := "kiwi_compose_" + pgITServerRandomHex(t, 10)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database %s: %v", dbName, err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("close admin connection: %v", err)
	}
	freshCfg, err := pgx.ParseConfig(base)
	if err != nil {
		t.Fatalf("re-parse KIWI_TEST_POSTGRES_URL: %v", err)
	}
	freshCfg.Database = dbName
	t.Setenv("KIWI_TEST_POSTGRES_URL", freshCfg.ConnString())
	t.Cleanup(func() {
		cctx := context.Background()
		c, cerr := pgx.ConnectConfig(cctx, adminCfg)
		if cerr != nil {
			t.Logf("drop database %s: connect: %v", dbName, cerr)
			return
		}
		defer func() { _ = c.Close(cctx) }()
		if _, terr := c.Exec(cctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", dbName); terr != nil {
			t.Logf("terminate backends for %s: %v", dbName, terr)
		}
		if _, derr := c.Exec(cctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()); derr != nil {
			t.Logf("drop database %s: %v", dbName, derr)
		}
	})
	return freshCfg.ConnString()
}

// composePGVisibleRuns lists the repo-a run ids of the interleaved PG seed
// (i%3 == 0) newest-first.
func composePGVisibleRuns(total int) []string {
	out := []string{}
	for i := total - 1; i >= 0; i-- {
		if i%3 == 0 {
			out = append(out, pgITRunsPageID(i))
		}
	}
	return out
}

// TestComposeRotationPairPaginationSharedGrantsPG re-verifies the rotation
// pair's pagination contract against real Postgres: identical pages for both
// credentials, only the granted repository visible, every cursor decoded to
// the last visible run of its page.
func TestComposeRotationPairPaginationSharedGrantsPG(t *testing.T) {
	composeFreshPGDatabase(t)
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("admin-tok")
	s.DB = st
	path := composeTokenFile(t, t.TempDir(), map[string]auth.Principal{
		auth.TokenDigest("rot-1"): {Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{composeCanonicalKey("github.com", "o/repo-a"): {Read: true}}},
		auth.TokenDigest("rot-2"): {Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{composeCanonicalKey("github.com", "o/repo-a"): {Read: true}}},
	})
	if err := s.AuthStore.Load(path); err != nil {
		t.Fatalf("rotation pair failed to load: %v", err)
	}

	const total = 10
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < total; i++ {
		pgITRunsPageSeed(t, st, []model.Run{pgITRunsPageRun(i, base, i%3 == 0)})
	}

	pages1 := pgITRunsPageWalk(t, s, "rot-1", 2, 8)
	pages2 := pgITRunsPageWalk(t, s, "rot-2", 2, 8)
	if len(pages1) != 2 || len(pages2) != 2 {
		t.Fatalf("walks = %d / %d pages, want 2 each", len(pages1), len(pages2))
	}
	for i := range pages1 {
		if strings.Join(pages1[i].ids, ",") != strings.Join(pages2[i].ids, ",") || pages1[i].cursor != pages2[i].cursor {
			t.Fatalf("page %d: rot-1 %v/%q != rot-2 %v/%q", i, pages1[i].ids, pages1[i].cursor, pages2[i].ids, pages2[i].cursor)
		}
		decoded, ok := decodeRunsCursor(pages1[i].cursor)
		switch {
		case pages1[i].cursor == "" && i != len(pages1)-1:
			t.Fatalf("page %d ended the walk early", i)
		case pages1[i].cursor != "" && !ok:
			t.Fatalf("page %d cursor %q does not decode", i, pages1[i].cursor)
		case pages1[i].cursor != "" && decoded.id != pages1[i].ids[len(pages1[i].ids)-1]:
			t.Fatalf("page %d cursor id = %q, want the last visible run %q", i, decoded.id, pages1[i].ids[len(pages1[i].ids)-1])
		}
	}
	seen := []string{}
	for _, page := range pages1 {
		seen = append(seen, page.ids...)
	}
	if strings.Join(seen, ",") != strings.Join(composePGVisibleRuns(total), ",") {
		t.Fatalf("rotation walk = %v, want exactly %v", seen, composePGVisibleRuns(total))
	}
	for i, page := range pages1 {
		if page.capHdr != strconv.Itoa(storage.MaxRunsPageLimit) {
			t.Fatalf("page %d limit cap = %q", i, page.capHdr)
		}
	}

	// A cursor minted by one credential completes under the other: no page
	// boundary may depend on which half of the rotation asked.
	rotatedCursor := pages1[0].cursor
	w := pgITDo(t, s, http.MethodGet, "/api/v1/runs?limit=2&cursor="+rotatedCursor, "rot-2", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("rotated continuation = %d: %s", w.Code, w.Body.String())
	}
	if ids := runIDs(t, w.Body.String()); strings.Join(ids, ",") != strings.Join(composePGVisibleRuns(total)[2:], ",") {
		t.Fatalf("rotated continuation = %v", ids)
	}
}

// TestComposeConflictingSubjectTokenFileFailsClosedPG is the live-store half
// of the ambiguity composition: the conflicting token file fails the startup
// load, neither ambiguous credential reaches the paginated collection (401,
// not a filtered or empty page), and the valid credentials still page exactly
// their granted repositories.
func TestComposeConflictingSubjectTokenFileFailsClosedPG(t *testing.T) {
	composeFreshPGDatabase(t)
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("admin-tok")
	s.DB = st
	if err := s.AuthStore.AddToken("valid", auth.Principal{Subject: "valid", Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}}}); err != nil {
		t.Fatal(err)
	}
	conflictPath := composeTokenFile(t, t.TempDir(), map[string]auth.Principal{
		auth.TokenDigest("conflict-a"): {Subject: "svc-ambiguous", Repositories: map[string]auth.RepositoryPermission{composeCanonicalKey("github.com", "o/repo-a"): {Read: true}}},
		auth.TokenDigest("conflict-b"): {Subject: "svc-ambiguous", Repositories: map[string]auth.RepositoryPermission{composeCanonicalKey("github.com", "o/repo-b"): {Read: true}}},
	})

	base := time.Now().UTC().Truncate(time.Microsecond)
	pgITRunsPageSeed(t, st, []model.Run{
		{ID: pgITRunsPageID(0), Status: model.StatusSuccess, CreatedAt: base.Add(time.Second), Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"},
		{ID: pgITRunsPageID(1), Status: model.StatusSuccess, CreatedAt: base.Add(2 * time.Second), Repo: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b"},
	})

	if err := s.AuthStore.Load(conflictPath); err == nil {
		t.Fatal("a token file with a conflicting subject loaded against Postgres mode")
	} else if !strings.Contains(err.Error(), `subject "svc-ambiguous"`) {
		t.Fatalf("load error %v does not name the ambiguous subject", err)
	}
	for _, tok := range []string{"conflict-a", "conflict-b"} {
		w := pgITDo(t, s, http.MethodGet, "/api/v1/runs", tok, "", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("ambiguous credential %s = %d, want 401: %s", tok, w.Code, w.Body.String())
		}
	}

	pages := pgITRunsPageWalk(t, s, "valid", 10, 4)
	seen := []string{}
	for _, page := range pages {
		seen = append(seen, page.ids...)
	}
	if strings.Join(seen, ",") != pgITRunsPageID(0) {
		t.Fatalf("valid credential saw %v, want only its granted repository", seen)
	}
}

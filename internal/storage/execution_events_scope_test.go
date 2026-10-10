package storage

// Scope-correct execution event retention tests: the repository/run
// dimensions on the stream, the per-scope deletion frontier and the scope
// filter of the atomic read, across the memory and filesystem stores. The
// PostgreSQL equivalents live in the PG-gated integration files.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestExecutionEventScopeKey(t *testing.T) {
	for _, tc := range []struct {
		scope ExecutionEventScope
		want  string
	}{
		{ExecutionEventScope{Kind: ExecutionEventScopeGlobal}, "global"},
		{ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: "github.com/acme/repo-a"}, "repo:github.com/acme/repo-a"},
		{ExecutionEventScope{Kind: ExecutionEventScopeRun, RepoID: "github.com/acme/repo-a", RunID: "run-1"}, "run:github.com/acme/repo-a/run-1"},
	} {
		if got := tc.scope.ScopeKey(); got != tc.want {
			t.Errorf("ScopeKey(%+v) = %q, want %q", tc.scope, got, tc.want)
		}
	}
}

// TestMemStoreExecutionEventRepoDimension proves the memStore append derives
// the repository dimension from the run/job state exactly like the
// PostgreSQL trigger: by run, by job's own RepoID, and by the job's run.
func TestMemStoreExecutionEventRepoDimension(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	m.mu.Lock()
	m.runs["run-a"] = model.Run{ID: "run-a", RepoID: "github.com/acme/repo-a"}
	m.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a"}
	m.jobs["job-b"] = model.Job{ID: "job-b", RunID: "run-a", RepoID: "github.com/acme/repo-a"}
	m.mu.Unlock()

	for _, tc := range []struct {
		name string
		e    model.ExecutionEvent
		want string
	}{
		{"run lookup", model.ExecutionEvent{RunID: "run-a", Type: "run.queued"}, "github.com/acme/repo-a"},
		{"job lookup through its run", model.ExecutionEvent{JobID: "job-a", Type: "job.queued"}, "github.com/acme/repo-a"},
		{"job's own repo", model.ExecutionEvent{JobID: "job-b", Type: "job.queued"}, "github.com/acme/repo-a"},
		{"unknown owner stays empty", model.ExecutionEvent{RunID: "run-x", Type: "run.queued"}, ""},
		{"explicit repo is never overwritten", model.ExecutionEvent{RunID: "run-a", RepoID: "github.com/acme/other", Type: "run.queued"}, "github.com/acme/other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := m.AppendExecutionEvent(ctx, tc.e); err != nil {
				t.Fatal(err)
			}
			page, _, err := m.ListExecutionEvents(ctx, 0, 10, "")
			if err != nil {
				t.Fatal(err)
			}
			if got := page[len(page)-1].RepoID; got != tc.want {
				t.Fatalf("derived repo = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMemStoreScopedRetention proves the memStore scope filter and per-scope
// frontier: a repository read sees only its events, the frontier is MAX over
// its pruned runs (so a global prune that removed only other repositories
// never expires its cursor), the run frontier is its own row, and the global
// frontier stays the cursor watermark.
func TestMemStoreScopedRetention(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	for _, e := range []model.ExecutionEvent{
		{RunID: "run-b", RepoID: "github.com/acme/repo-b", Type: "job.queued", CreatedAt: old},
		{RunID: "run-b", RepoID: "github.com/acme/repo-b", Type: "job.running", CreatedAt: old},
		{RunID: "run-a", RepoID: "github.com/acme/repo-a", Type: "job.queued", CreatedAt: now},
		{RunID: "run-a", RepoID: "github.com/acme/repo-a", Type: "job.running", CreatedAt: now},
	} {
		if err := m.AppendExecutionEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	scopeA := ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: "github.com/acme/repo-a"}
	scopeB := ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: "github.com/acme/repo-b"}
	page, cursor, retained, latest, err := m.ReadExecutionEventsRetention(ctx, 0, 100, scopeA)
	if err != nil || len(page) != 2 || cursor != 4 || retained != 0 || latest != 4 {
		t.Fatalf("repo A read = %d cursor %d retained %d latest %d err %v", len(page), cursor, retained, latest, err)
	}
	for _, e := range page {
		if e.RepoID != "github.com/acme/repo-a" {
			t.Fatalf("repo A read leaked %+v", e)
		}
	}

	// The prefix prune removes only the old repo B rows: the global watermark
	// advances to 2 while repo A's frontier stays 0 (nothing visible lost).
	pruned, globalRetained, err := m.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 100)
	if err != nil || pruned != 2 || globalRetained != 2 {
		t.Fatalf("prune = %d/%d err %v, want 2/2", pruned, globalRetained, err)
	}
	if got, err := m.ScopedRetainedFrom(ctx, scopeA); err != nil || got != 0 {
		t.Fatalf("repo A frontier = %d err %v, want 0", got, err)
	}
	if got, err := m.ScopedRetainedFrom(ctx, scopeB); err != nil || got != 2 {
		t.Fatalf("repo B frontier = %d err %v, want 2", got, err)
	}
	if got, err := m.ScopedRetainedFrom(ctx, ExecutionEventScope{Kind: ExecutionEventScopeRun, RepoID: "github.com/acme/repo-b", RunID: "run-b"}); err != nil || got != 2 {
		t.Fatalf("run B frontier = %d err %v, want 2", got, err)
	}
	if got, err := m.ScopedRetainedFrom(ctx, ExecutionEventScope{Kind: ExecutionEventScopeGlobal}); err != nil || got != 2 {
		t.Fatalf("global frontier = %d err %v, want 2", got, err)
	}
	// A repo A cursor at 0 is NOT expired by the global watermark: resume_ok
	// and the two surviving repo A events page with no duplicates.
	page, cursor, retained, _, err = m.ReadExecutionEventsRetention(ctx, 0, 100, scopeA)
	if err != nil || len(page) != 2 || page[0].Seq != 3 || page[1].Seq != 4 || cursor != 4 || retained != 0 {
		t.Fatalf("repo A post-prune read = %+v cursor %d retained %d err %v", page, cursor, retained, err)
	}
	if ExecutionEventCursorExpired(0, retained) {
		t.Fatal("repo A cursor 0 expired by another repository's prune")
	}
	// Repo B's own cursor below its frontier is expired; at the frontier it
	// stays valid and the page is empty.
	if !ExecutionEventCursorExpired(1, 2) {
		t.Fatal("repo B cursor 1 not expired at frontier 2")
	}
	if _, _, retainedB, _, err := m.ReadExecutionEventsRetention(ctx, 2, 100, scopeB); err != nil || retainedB != 2 || ExecutionEventCursorExpired(2, retainedB) {
		t.Fatalf("repo B boundary read retained %d err %v", retainedB, err)
	}
}

// TestRepositoryScopedRetentionPersistsFrontier proves the fs journal's
// scoped read, filter and durable per-run frontier: a prune of only repo B's
// events leaves repo A's frontier at 0, the frontier file survives a restart
// (so the scoped expiry decision is durable), and the scope filter never
// leaks the other repository.
func TestRepositoryScopedRetentionPersistsFrontier(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo := New(dir)
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	for _, e := range []model.ExecutionEvent{
		{RunID: "run-b", RepoID: "github.com/acme/repo-b", Type: "job.queued", CreatedAt: old},
		{RunID: "run-b", RepoID: "github.com/acme/repo-b", Type: "job.running", CreatedAt: old},
		{RunID: "run-a", RepoID: "github.com/acme/repo-a", Type: "job.queued", CreatedAt: now},
		{RunID: "run-a", RepoID: "github.com/acme/repo-a", Type: "job.running", CreatedAt: now},
	} {
		if err := repo.AppendExecutionEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	scopeA := ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: "github.com/acme/repo-a"}
	scopeB := ExecutionEventScope{Kind: ExecutionEventScopeRepo, RepoID: "github.com/acme/repo-b"}
	page, cursor, retained, latest, err := repo.ReadExecutionEventsRetention(ctx, 0, 100, scopeA)
	if err != nil || len(page) != 2 || cursor != 4 || retained != 0 || latest != 4 {
		t.Fatalf("repo A read = %d cursor %d retained %d latest %d err %v", len(page), cursor, retained, latest, err)
	}

	pruned, globalRetained, err := repo.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 100)
	if err != nil || pruned != 2 || globalRetained != 2 {
		t.Fatalf("prune = %d/%d err %v, want 2/2", pruned, globalRetained, err)
	}
	if _, err := os.Stat(filepath.Join(dir, executionEventsPrunedFile)); err != nil {
		t.Fatalf("pruned frontier file: %v", err)
	}
	if got, err := repo.ScopedRetainedFrom(ctx, scopeA); err != nil || got != 0 {
		t.Fatalf("repo A frontier = %d err %v, want 0", got, err)
	}
	if got, err := repo.ScopedRetainedFrom(ctx, scopeB); err != nil || got != 2 {
		t.Fatalf("repo B frontier = %d err %v, want 2", got, err)
	}

	// Restart: the frontier is durable and the scoped read still filters.
	fresh := New(dir)
	if _, err := fresh.Load(); err != nil {
		t.Fatal(err)
	}
	if got, err := fresh.ScopedRetainedFrom(ctx, scopeA); err != nil || got != 0 {
		t.Fatalf("fresh repo A frontier = %d err %v, want 0", got, err)
	}
	if got, err := fresh.ScopedRetainedFrom(ctx, scopeB); err != nil || got != 2 {
		t.Fatalf("fresh repo B frontier = %d err %v, want 2", got, err)
	}
	page, cursor, retained, _, err = fresh.ReadExecutionEventsRetention(ctx, 0, 100, scopeA)
	if err != nil || len(page) != 2 || cursor != 4 || retained != 0 {
		t.Fatalf("fresh repo A read = %+v cursor %d retained %d err %v", page, cursor, retained, err)
	}
	for _, e := range page {
		if e.RepoID != "github.com/acme/repo-a" {
			t.Fatalf("fresh repo A read leaked %+v", e)
		}
	}
	// A zero-repo event belongs to no repository scope, not even a
	// lookalike.
	if err := fresh.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-x", Type: "job.queued"}); err != nil {
		t.Fatal(err)
	}
	page, _, _, _, err = fresh.ReadExecutionEventsRetention(ctx, 0, 100, scopeA)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range page {
		if e.RunID == "run-x" {
			t.Fatalf("event with no repository leaked into a repo scope: %+v", e)
		}
	}
}

// TestFaultyStoreForwardsScopedFrontier proves the wrapper forwards the
// scoped frontier read and fails closed when the inner store lacks the
// contract.
func TestFaultyStoreForwardsScopedFrontier(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	fault := &FaultyStore{Inner: inner}
	scope := ExecutionEventScope{Kind: ExecutionEventScopeGlobal}
	if got, err := fault.ScopedRetainedFrom(ctx, scope); err != nil || got != 0 {
		t.Fatalf("forwarded global frontier = %d err %v", got, err)
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).ScopedRetainedFrom(ctx, scope); err == nil {
		t.Fatal("missing inner scoped frontier contract must fail closed")
	}
}

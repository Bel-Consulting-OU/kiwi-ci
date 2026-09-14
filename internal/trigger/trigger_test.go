package trigger

import (
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func push() forge.EventContext {
	return forge.EventContext{
		Forge: "github",
		Event: "push",
		Ref:   "refs/heads/main",
		Repository: forge.Repository{
			FullName: "acme/app",
			CloneURL: "https://github.com/acme/app.git",
		},
		Trusted: true,
	}
}

func TestMatchesEmptyTriggers(t *testing.T) {
	ok, key := Matches(nil, push())
	if !ok || key != "" {
		t.Fatalf("empty on section must match everything: %v %q", ok, key)
	}
	ok, key = Matches(map[string]pipeline.Trigger{}, push())
	if !ok || key != "" {
		t.Fatalf("empty on section must match everything: %v %q", ok, key)
	}
}

func TestMatchesEventAndActionKeys(t *testing.T) {
	triggers := map[string]pipeline.Trigger{
		"push":                {},
		"pull_request":        {},
		"pull_request.opened": {},
		"pull_request.closed": {},
		"merge_request":       {},
	}
	ec := push()
	ec.Event = "pull_request"
	ec.Action = "opened"
	ec.Ref = "refs/heads/feature"
	ok, key := Matches(triggers, ec)
	if !ok || key != "pull_request.opened" {
		t.Fatalf("action-scoped key must win: %v %q", ok, key)
	}
	ec.Action = "closed"
	ok, key = Matches(triggers, ec)
	if !ok || key != "pull_request.closed" {
		t.Fatalf("closed action key must win: %v %q", ok, key)
	}
	ec.Action = "reopened"
	ok, key = Matches(triggers, ec)
	if !ok || key != "pull_request" {
		t.Fatalf("bare event key must match other actions: %v %q", ok, key)
	}
	// merge_request falls back to pull_request when no merge_request key.
	delete(triggers, "merge_request")
	ec.Event = "merge_request"
	ec.Action = ""
	ok, key = Matches(triggers, ec)
	if !ok || key != "pull_request" {
		t.Fatalf("merge_request fallback failed: %v %q", ok, key)
	}
	// No key at all: no match.
	ec.Event = "issue_comment"
	if ok, _ := Matches(triggers, ec); ok {
		t.Fatal("unlisted event matched")
	}
}

func TestMatchesDraft(t *testing.T) {
	triggers := map[string]pipeline.Trigger{"pull_request": {}}
	ec := push()
	ec.Event = "pull_request"
	ec.Draft = true
	if ok, _ := Matches(triggers, ec); ok {
		t.Fatal("draft PR matched")
	}
}

func TestMatchesRefFilters(t *testing.T) {
	triggers := map[string]pipeline.Trigger{
		"push": {Branches: []string{"main", "release/*"}},
	}
	ec := push()
	if ok, key := Matches(triggers, ec); !ok || key != "push" {
		t.Fatalf("main branch must match: %v %q", ok, key)
	}
	ec.Ref = "refs/heads/release/v2"
	if ok, _ := Matches(triggers, ec); !ok {
		t.Fatal("glob branch must match")
	}
	ec.Ref = "refs/heads/feature/x"
	if ok, _ := Matches(triggers, ec); ok {
		t.Fatal("unlisted branch matched")
	}
	// Tag refs only match triggers with no branch filters, or with tag
	// filters.
	ec.Ref = "refs/tags/v1.0.0"
	ec.Tag = "v1.0.0"
	if ok, _ := Matches(triggers, ec); ok {
		t.Fatal("tag matched a branch-filtered trigger")
	}
	tagTriggers := map[string]pipeline.Trigger{"push": {Tags: []string{"v*"}}}
	if ok, _ := Matches(tagTriggers, ec); !ok {
		t.Fatal("tag glob must match")
	}
	ec.Tag = "x"
	if ok, _ := Matches(tagTriggers, ec); ok {
		t.Fatal("unlisted tag matched")
	}
	// Ignore lists.
	ignore := map[string]pipeline.Trigger{"push": {BranchesIgnore: []string{"main"}}}
	if ok, _ := Matches(ignore, push()); ok {
		t.Fatal("ignored branch matched")
	}
}

func TestMatchesPaths(t *testing.T) {
	triggers := map[string]pipeline.Trigger{
		"push": {Paths: []string{"src/**"}},
	}
	ec := push()
	ec.ChangedFiles = []string{"src/main.go"}
	if ok, _ := Matches(triggers, ec); !ok {
		t.Fatal("matching path rejected")
	}
	ec.ChangedFiles = []string{"docs/readme.md"}
	if ok, _ := Matches(triggers, ec); ok {
		t.Fatal("non-matching path accepted")
	}
}

func TestMatchesMirrorsForge(t *testing.T) {
	// Lockstep check against the server's forge.MatchesTrigger: identical
	// inputs must produce identical outputs (see the package comment).
	triggers := map[string]pipeline.Trigger{
		"push":                {Branches: []string{"main"}, Paths: []string{"src/**"}},
		"pull_request.opened": {},
	}
	cases := []forge.EventContext{
		push(),
		func() forge.EventContext { ec := push(); ec.Ref = "refs/heads/feature"; return ec }(),
		func() forge.EventContext { ec := push(); ec.ChangedFiles = []string{"docs/x"}; return ec }(),
		func() forge.EventContext { ec := push(); ec.Event = "pull_request"; ec.Action = "opened"; return ec }(),
		func() forge.EventContext {
			ec := push()
			ec.Draft = true
			ec.Event = "pull_request"
			ec.Action = "opened"
			return ec
		}(),
	}
	for i, ec := range cases {
		gotOK, gotKey := Matches(triggers, ec)
		wantOK, wantKey := forge.MatchesTrigger(triggers, ec)
		if gotOK != wantOK || gotKey != wantKey {
			t.Errorf("case %d: Matches = (%v, %q), forge.MatchesTrigger = (%v, %q)", i, gotOK, gotKey, wantOK, wantKey)
		}
	}
}

func TestTriggerSetMatches(t *testing.T) {
	var ts TriggerSet = map[string]pipeline.Trigger{"push": {Branches: []string{"main"}}}
	if ok, _ := ts.Matches(push()); !ok {
		t.Fatal("TriggerSet.Matches failed")
	}
}

func TestScheduleKey(t *testing.T) {
	nominal := time.Date(2026, 9, 14, 9, 30, 0, 0, time.UTC)
	k1 := ScheduleKey("nightly", nominal)
	k2 := ScheduleKey("nightly", nominal)
	if k1 != k2 {
		t.Fatalf("ScheduleKey not stable: %q vs %q", k1, k2)
	}
	if k1 != "nightly@2026-09-14T09:30:00Z" {
		t.Fatalf("unexpected key %q", k1)
	}
	if ScheduleKey("nightly", nominal.Add(time.Minute)) == k1 {
		t.Fatal("different nominal times must produce different keys")
	}
	if ScheduleKey("weekly", nominal) == k1 {
		t.Fatal("different schedule IDs must produce different keys")
	}
	// Non-UTC nominal times normalize to UTC.
	if got := ScheduleKey("n", time.Date(2026, 9, 14, 11, 30, 0, 0, time.FixedZone("EET", 2*3600))); got != "n@2026-09-14T09:30:00Z" {
		t.Fatalf("non-UTC nominal time not normalized: %q", got)
	}
}

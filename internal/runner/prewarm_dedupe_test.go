package runner

import (
	"context"
	"encoding/json"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDedupePrewarmItemsStableOrder(t *testing.T) {
	items := []prewarmItem{
		{Ref: "keep@sha256:a", Kind: "docker"},
		{Ref: "b@sha256:b", Kind: "docker"},
		{Ref: "keep@sha256:a", Kind: "docker"},
		{Ref: "b@sha256:b", Kind: "tart"},
		{Ref: "keep@sha256:a", Kind: "docker"},
	}
	got := dedupePrewarmItems(items)
	want := []prewarmItem{
		{Ref: "keep@sha256:a", Kind: "docker"},
		{Ref: "b@sha256:b", Kind: "docker"},
		{Ref: "b@sha256:b", Kind: "tart"},
	}
	if len(got) != len(want) {
		t.Fatalf("dedupe = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupe[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if got := dedupePrewarmItems(nil); len(got) != 0 {
		t.Fatalf("dedupe(nil) = %v", got)
	}
	// Capping after dedupe spends the budget on distinct entries only.
	capped := capPrewarmItems(dedupePrewarmItems(items), 2)
	if len(capped) != 2 || capped[0] == capped[1] {
		t.Fatalf("capped = %v", capped)
	}
}

// TestPrewarmRunDeduplicatesKeptRefs is the regression test for the
// duplicated-budget defect: refs kept from the previous state are pulled
// again and were appended a second time, so a 10-entry budget filled up with
// duplicate entries and evicted new refs. After the fix the persisted state
// holds each distinct (ref, kind) exactly once.
func TestPrewarmRunDeduplicatesKeptRefs(t *testing.T) {
	testutil.UnixShell(t)
	bin := t.TempDir()
	docker := filepath.Join(bin, "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(t.TempDir(), "prewarm.json")
	refs := []string{"a@sha256:" + strings.Repeat("1", 64), "b@sha256:" + strings.Repeat("2", 64), "c@sha256:" + strings.Repeat("3", 64)}
	prev := prewarmState{Version: 1, Items: []prewarmItem{
		{Ref: refs[0], Kind: "docker"},
		{Ref: refs[1], Kind: "docker"},
	}}
	body, _ := json.Marshal(prev)
	if err := os.WriteFile(stateFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	p := &prewarmer{refs: refs, stateFile: stateFile, maxTracked: 3, dockerPath: docker,
		logf: func(string, ...any) {}}
	if err := p.run(context.Background()); err != nil {
		t.Fatalf("prewarm run: %v", err)
	}
	st := p.loadState()
	if len(st.Items) != 3 {
		t.Fatalf("state items = %+v, want the 3 distinct refs", st.Items)
	}
	seen := map[string]int{}
	for _, item := range st.Items {
		seen[item.Ref]++
	}
	for _, ref := range refs {
		if seen[ref] != 1 {
			t.Fatalf("ref %s tracked %d times: %+v", ref, seen[ref], st.Items)
		}
	}
	// The new ref survives the cap because duplicates no longer consume
	// budget slots.
	if seen[refs[2]] != 1 {
		t.Fatalf("new ref evicted by duplicate budget use: %+v", st.Items)
	}
}

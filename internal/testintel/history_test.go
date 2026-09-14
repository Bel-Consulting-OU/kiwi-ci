package testintel

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestHistoryRecordAndFlaky(t *testing.T) {
	h := NewHistory()
	now := time.Now()
	h.Record("org/repo", "unit", "pkg", "stable", 1.0, true, now)
	h.Record("org/repo", "unit", "pkg", "stable", 1.2, true, now)
	h.Record("org/repo", "unit", "pkg", "flaky", 0.5, true, now)
	h.Record("org/repo", "unit", "pkg", "flaky", 0.4, false, now)
	h.Record("org/repo", "unit", "pkg", "flaky", 0.6, true, now)
	h.Record("other/repo", "unit", "pkg", "flaky", 0.1, false, now)

	flaky := h.Flaky("org/repo")
	if !reflect.DeepEqual(flaky, []string{"pkg.flaky"}) {
		t.Fatalf("flaky: %v", flaky)
	}
	if got := h.Flaky("other/repo"); len(got) != 0 {
		t.Fatalf("flaky other repo: %v", got)
	}
	if got := h.Flaky("missing/repo"); len(got) != 0 {
		t.Fatalf("flaky missing repo: %v", got)
	}
}

func TestHistoryEWMA(t *testing.T) {
	h := NewHistory()
	now := time.Now()
	h.Record("r", "s", "", "t", 10, true, now)
	// EWMA = 0.3*20 + 0.7*10 = 13
	h.Record("r", "s", "", "t", 20, true, now)
	st := h.stats[testKey("r", "s", "", "t")]
	if st.EWMA != 13 {
		t.Fatalf("ewma: %v", st.EWMA)
	}
	if st.Runs != 2 || st.Passes != 2 || st.Fails != 0 {
		t.Fatalf("counters: %+v", st)
	}
	if st.LastFailure != nil {
		t.Fatalf("last failure should be nil: %+v", st.LastFailure)
	}
	h.Record("r", "s", "", "t", 5, false, now)
	if st.LastFailure == nil {
		t.Fatal("want last failure")
	}
	if st.FlakeProb == 0 {
		t.Fatalf("flake prob: %v", st.FlakeProb)
	}
}

func TestHistoryOutcomeWindowBounded(t *testing.T) {
	h := NewHistory()
	now := time.Now()
	for i := 0; i < outcomeWindow+10; i++ {
		h.Record("r", "s", "", "t", 1, true, now)
	}
	st := h.stats[testKey("r", "s", "", "t")]
	if len(st.Outcomes) != outcomeWindow {
		t.Fatalf("window: %d", len(st.Outcomes))
	}
}

func TestHistoryManifest(t *testing.T) {
	h := NewHistory()
	now := time.Now()
	h.Record("r", "a", "c", "x", 1, true, now)
	h.Record("r", "a", "", "y", 1, true, now)
	h.Record("r", "b", "", "z", 1, true, now)
	got := h.Manifest("r", "a")
	want := []string{"c.x", "y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest: %v", got)
	}
}

func TestHistoryShardDeterministicAndBalanced(t *testing.T) {
	h := NewHistory()
	now := time.Now()
	// Durations: a=30, b=20, c=10, d=5, e=1
	for name, dur := range map[string]float64{"a": 30, "b": 20, "c": 10, "d": 5, "e": 1} {
		h.Record("r", "s", "", name, dur, true, now)
		h.Record("r", "s", "", name, dur, true, now)
	}
	got := h.Shard("r", "s", 2)
	again := h.Shard("r", "s", 2)
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("sharding not deterministic: %v vs %v", got, again)
	}
	// Largest-first round robin: a->0, b->1, c->0, d->1, e->0
	want := [][]string{{"a", "c", "e"}, {"b", "d"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shards: %v, want %v", got, want)
	}
	// Single shard contains everything sorted by duration desc.
	all := h.Shard("r", "s", 1)
	if !reflect.DeepEqual(all, [][]string{{"a", "b", "c", "d", "e"}}) {
		t.Fatalf("single shard: %v", all)
	}
	// Non-positive shards collapse to one.
	zero := h.Shard("r", "s", 0)
	if !reflect.DeepEqual(zero, [][]string{{"a", "b", "c", "d", "e"}}) {
		t.Fatalf("zero shards: %v", zero)
	}
	// Unknown suite yields empty shards.
	empty := h.Shard("r", "nope", 3)
	for _, s := range empty {
		if len(s) != 0 {
			t.Fatalf("expected empty shard, got %v", empty)
		}
	}
}

func TestHistorySaveLoad(t *testing.T) {
	h := NewHistory()
	now := time.Now()
	h.Record("r", "s", "c", "t", 3.5, false, now)
	h.Record("r", "s", "c", "t", 4.0, true, now)
	path := filepath.Join(t.TempDir(), "history.json")
	if err := h.Save(path); err != nil {
		t.Fatal(err)
	}
	h2, err := LoadHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	st1 := h.stats[testKey("r", "s", "c", "t")]
	st2 := h2.stats[testKey("r", "s", "c", "t")]
	if st2 == nil || st1.Runs != st2.Runs || st1.EWMA != st2.EWMA || len(st1.Outcomes) != len(st2.Outcomes) {
		t.Fatalf("round trip mismatch: %+v vs %+v", st1, st2)
	}
	if !sort.StringsAreSorted(h2.Manifest("r", "s")) {
		t.Fatalf("manifest not sorted: %v", h2.Manifest("r", "s"))
	}
	if !reflect.DeepEqual(h.Flaky("r"), h2.Flaky("r")) {
		t.Fatalf("flaky mismatch after load")
	}
}

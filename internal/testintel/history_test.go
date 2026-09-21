package testintel

import (
	"math"
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
	// LPT: a->0 (30), b->1 (20), c->1 (30), d->0 (35), e->1 (31).
	want := [][]string{{"a", "d"}, {"b", "c", "e"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shards: %v, want %v", got, want)
	}
	// The duration split is near-optimal for this fixture: 35 vs 31, where
	// the provably imbalanced round-robin gave 41 vs 25.
	if lptMax := maxShardLoad(got, map[string]float64{"a": 30, "b": 20, "c": 10, "d": 5, "e": 1}); lptMax != 35 {
		t.Fatalf("max shard load = %v, want 35", lptMax)
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

// maxShardLoad returns the heaviest shard's accumulated duration for an
// assignment, the makespan LPT minimizes.
func maxShardLoad(assignment [][]string, durations map[string]float64) float64 {
	worst := 0.0
	for _, shard := range assignment {
		sum := 0.0
		for _, name := range shard {
			sum += durations[name]
		}
		if sum > worst {
			worst = sum
		}
	}
	return worst
}

// bruteForceShardOptimum returns the minimal possible maximum shard load over
// every assignment of durations to shards. It is the ground truth the LPT
// test compares against for its small fixture.
func bruteForceShardOptimum(durations []float64, shards int) float64 {
	best := math.Inf(1)
	var assign func(i int, loads []float64)
	assign = func(i int, loads []float64) {
		if i == len(durations) {
			worst := 0.0
			for _, l := range loads {
				if l > worst {
					worst = l
				}
			}
			if worst < best {
				best = worst
			}
			return
		}
		for s := 0; s < shards; s++ {
			loads[s] += durations[i]
			assign(i+1, loads)
			loads[s] -= durations[i]
		}
	}
	assign(0, make([]float64, shards))
	return best
}

// roundRobinShardMaxLoad reproduces the replaced scheduling policy (sort
// largest-first, assign i%shards) so the fixture proves the LPT change
// actually fixes an imbalanced workload.
func roundRobinShardMaxLoad(durations []float64, shards int) float64 {
	sorted := append([]float64(nil), durations...)
	sort.Sort(sort.Reverse(sort.Float64Slice(sorted)))
	loads := make([]float64, shards)
	for i, d := range sorted {
		loads[i%shards] += d
	}
	worst := 0.0
	for _, l := range loads {
		if l > worst {
			worst = l
		}
	}
	return worst
}

// TestHistoryShardLPTBalancedWhereRoundRobinIsNot is the crafted
// counterexample the LPT rewrite exists for: with durations 8,7,3,3,2,1 in
// three shards, largest-first round-robin produces 12/9/3 while LPT produces
// 8/8/8 — the brute-force optimum. The assignment must be no worse than the
// optimum, and the old policy must be provably worse, on the same fixture.
func TestHistoryShardLPTBalancedWhereRoundRobinIsNot(t *testing.T) {
	durations := map[string]float64{"a": 8, "b": 7, "c": 3, "d": 3, "e": 2, "f": 1}
	h := NewHistory()
	now := time.Unix(1700000000, 0).UTC()
	for name, dur := range durations {
		h.Record("r", "s", "", name, dur, true, now)
	}
	const shards = 3
	got := h.Shard("r", "s", shards)
	if want := [][]string{{"a"}, {"b", "f"}, {"c", "d", "e"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("LPT assignment = %v, want %v", got, want)
	}
	all := []float64{8, 7, 3, 3, 2, 1}
	optimum := bruteForceShardOptimum(all, shards)
	if lptMax, rrMax := maxShardLoad(got, durations), roundRobinShardMaxLoad(all, shards); lptMax > optimum {
		t.Fatalf("LPT max load %v exceeds the optimum %v", lptMax, optimum)
	} else if rrMax <= optimum {
		t.Fatalf("fixture does not demonstrate the imbalance: round-robin max %v <= optimum %v", rrMax, optimum)
	}
}

// TestHistoryShardDeterministicAcrossRecordOrders proves the assignment does
// not depend on map iteration or Record order: two histories built with the
// same tests in opposite insertion orders shard identically, and repeated
// calls stay identical.
func TestHistoryShardDeterministicAcrossRecordOrders(t *testing.T) {
	durations := map[string]float64{"a": 8, "b": 7, "c": 3, "d": 3, "e": 2, "f": 1}
	now := time.Unix(1700000000, 0).UTC()
	forward := []string{"a", "b", "c", "d", "e", "f"}
	h1 := NewHistory()
	h2 := NewHistory()
	for _, name := range forward {
		h1.Record("r", "s", "", name, durations[name], true, now)
	}
	for i := len(forward) - 1; i >= 0; i-- {
		name := forward[i]
		h2.Record("r", "s", "", name, durations[name], true, now)
	}
	first := h1.Shard("r", "s", 3)
	if second := h2.Shard("r", "s", 3); !reflect.DeepEqual(first, second) {
		t.Fatalf("record order changed the assignment: %v vs %v", first, second)
	}
	if again := h1.Shard("r", "s", 3); !reflect.DeepEqual(first, again) {
		t.Fatalf("repeated call changed the assignment: %v vs %v", first, again)
	}
}

// TestHistoryShardEmptyAndFewerTestsThanShards pins the degenerate partition
// shapes: an empty history materialises every shard as an empty slice, and a
// history with fewer tests than shards leaves the trailing shards empty while
// the tests still occupy the lowest-indexed shards.
func TestHistoryShardEmptyAndFewerTestsThanShards(t *testing.T) {
	h := NewHistory()
	empty := h.Shard("r", "s", 4)
	if len(empty) != 4 {
		t.Fatalf("empty history shards = %v", empty)
	}
	for i, shard := range empty {
		if shard == nil || len(shard) != 0 {
			t.Fatalf("empty shard %d = %v, want a non-nil empty slice", i, shard)
		}
	}
	now := time.Unix(1700000000, 0).UTC()
	h.Record("r", "s", "", "first", 9, true, now)
	h.Record("r", "s", "", "second", 4, true, now)
	got := h.Shard("r", "s", 5)
	if len(got) != 5 {
		t.Fatalf("shards = %v", got)
	}
	if !reflect.DeepEqual(got[0], []string{"first"}) || !reflect.DeepEqual(got[1], []string{"second"}) {
		t.Fatalf("lowest shards = %v, %v; want one test each", got[0], got[1])
	}
	for i := 2; i < 5; i++ {
		if got[i] == nil || len(got[i]) != 0 {
			t.Fatalf("shard %d = %v, want a non-nil empty slice", i, got[i])
		}
	}
}

// TestHistoryShardMissingEWMAUsesDocumentedDefault pins the scheduling
// duration of a stat without a usable EWMA: Runs==0 (never measured) and a
// NaN EWMA (corrupt journal) both schedule with defaultShardDuration, so
// unmeasured tests spread one per shard instead of piling into shard 0.
func TestHistoryShardMissingEWMAUsesDocumentedDefault(t *testing.T) {
	h := NewHistory()
	h.stats[testKey("r", "s", "", "alpha")] = &TestStat{}
	h.stats[testKey("r", "s", "", "gamma")] = &TestStat{Runs: 2, EWMA: math.NaN()}
	got := h.Shard("r", "s", 2)
	want := [][]string{{"alpha"}, {"gamma"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing-EWMA shards = %v, want %v", got, want)
	}
	if again := h.Shard("r", "s", 2); !reflect.DeepEqual(got, again) {
		t.Fatalf("missing-EWMA sharding not deterministic: %v vs %v", got, again)
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

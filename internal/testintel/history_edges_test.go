package testintel

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistoryShardTieBreakIsStable(t *testing.T) {
	h := NewHistory()
	when := time.Unix(1700000000, 0).UTC()
	for _, name := range []string{"zulu", "alpha", "mike"} {
		h.Record("repo", "suite", "", name, 10, true, when)
	}
	got := h.Shard("repo", "suite", 2)
	if len(got) != 2 {
		t.Fatalf("shards = %v", got)
	}
	// Equal durations: the sort falls back to the name, largest-first
	// round-robin puts alpha/zulu in shard 0 and mike in shard 1.
	if len(got[0]) != 2 || got[0][0] != "alpha" || got[0][1] != "zulu" {
		t.Fatalf("shard 0 = %v", got[0])
	}
	if len(got[1]) != 1 || got[1][0] != "mike" {
		t.Fatalf("shard 1 = %v", got[1])
	}
	// A non-positive shard count yields one shard with everything.
	one := h.Shard("repo", "suite", 0)
	if len(one) != 1 || len(one[0]) != 3 {
		t.Fatalf("shard 0 = %v", one)
	}
	// Empty shards are still materialised.
	empty := h.Shard("repo", "suite", 5)
	if len(empty) != 5 {
		t.Fatalf("empty shards = %v", empty)
	}
	for i := 3; i < 5; i++ {
		if empty[i] == nil || len(empty[i]) != 0 {
			t.Fatalf("shard %d = %v, want an empty slice", i, empty[i])
		}
	}
}

func TestHistorySaveMarshalError(t *testing.T) {
	h := NewHistory()
	h.Record("repo", "suite", "", "nan", math.NaN(), true, time.Unix(1, 0))
	path := filepath.Join(t.TempDir(), "history.json")
	if err := h.Save(path); err == nil {
		t.Fatal("a NaN EWMA must fail to marshal")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a failed Save must not write a partial file")
	}
}

func TestLoadHistoryEdges(t *testing.T) {
	if _, err := LoadHistory(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file must fail")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHistory(bad); err == nil {
		t.Fatal("malformed JSON must fail")
	}

	withNull := filepath.Join(dir, "null.json")
	if err := os.WriteFile(withNull, []byte(`{"repo|suite|cls|name":null,"repo|suite||other":{"runs":1,"passes":1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := LoadHistory(withNull)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if _, ok := h.stats["repo|suite|cls|name"]; ok {
		t.Fatal("nil stat entries must be dropped on load")
	}
	if len(h.stats) != 1 {
		t.Fatalf("stats = %v", h.stats)
	}
	if got := h.Manifest("repo", "suite"); len(got) != 1 || got[0] != "other" {
		t.Fatalf("manifest = %v", got)
	}
}

func TestHistoryKeyPartHelpers(t *testing.T) {
	if got := repoPart("no-separator"); got != "no-separator" {
		t.Fatalf("repoPart = %q", got)
	}
	if got := repoPart("repo|suite||name"); got != "repo" {
		t.Fatalf("repoPart = %q", got)
	}
	if got := suitePart("repo|only-one"); got != "" {
		t.Fatalf("suitePart = %q, want empty for a short key", got)
	}
	if got := suitePart("repo|suite||name"); got != "suite" {
		t.Fatalf("suitePart = %q", got)
	}
	if got := suitePart("no-separator"); got != "" {
		t.Fatalf("suitePart = %q", got)
	}
	if got := displayName("only|three|parts"); got != "only|three|parts" {
		t.Fatalf("displayName(short key) = %q", got)
	}
	if got := displayName("repo|suite||name"); got != "name" {
		t.Fatalf("displayName = %q", got)
	}
	if got := displayName("repo|suite|cls|name"); got != "cls.name" {
		t.Fatalf("displayName = %q", got)
	}
}

func TestHistoryFlakeWindowAndLastFailure(t *testing.T) {
	h := NewHistory()
	base := time.Unix(1700000000, 0)
	for i := 0; i < outcomeWindow+4; i++ {
		h.Record("repo", "suite", "cls", "t", 1, i%2 == 0, base.Add(time.Duration(i)*time.Second))
	}
	st := h.stats["repo|suite|cls|t"]
	if st == nil {
		t.Fatal("stat missing")
	}
	if len(st.Outcomes) != outcomeWindow {
		t.Fatalf("outcome window = %d, want %d", len(st.Outcomes), outcomeWindow)
	}
	if st.FlakeProb <= 0 || st.FlakeProb >= 1 {
		t.Fatalf("flake probability = %v", st.FlakeProb)
	}
	if st.LastFailure == nil || st.LastFailure.Location() != time.UTC {
		t.Fatalf("last failure = %v", st.LastFailure)
	}
	if st.Fails+st.Passes != st.Runs {
		t.Fatalf("counters %+v", st)
	}
	if got := h.Flaky("other-repo"); len(got) != 0 {
		t.Fatalf("flaky for another repo = %v", got)
	}
	if got := h.Flaky("repo"); len(got) != 1 || !strings.Contains(got[0], "t") {
		t.Fatalf("flaky = %v", got)
	}
}

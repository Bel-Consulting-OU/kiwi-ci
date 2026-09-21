package testintel

// Key-format, copy-on-write and window-flakiness tests: the versioned
// structured history key (round-trip for "|", unicode, empty and
// whitespace-only parts plus legacy decode), History.Clone deep-copy
// semantics, and the flaky drop-out after a clean 16-outcome window.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestHistoryKeyV2RoundTrip proves the structured key is unambiguous for
// every part, including the ones the legacy "repo|suite|class|name" join
// could not represent.
func TestHistoryKeyV2RoundTrip(t *testing.T) {
	cases := []struct {
		repo, suite, class, name string
	}{
		{"github.com/o/pipe|repo", "suite|part", "class|part", "name|part"},
		{"github.com/o/r", "suite", "", ""},
		{"", "", "", ""},
		{" ", "  ", " \t ", "\n"},
		{"github.com/уни/код", "тест", "класс", "имя🚀"},
		{"repo|", "|suite", "|", "|name"},
	}
	for _, tc := range cases {
		key := encodeHistoryKey(tc.repo, tc.suite, tc.class, tc.name)
		if !strings.HasPrefix(key, historyKeyV2Prefix) {
			t.Fatalf("key %q is not v2-prefixed", key)
		}
		got, ok := decodeHistoryKey(key)
		if !ok {
			t.Fatalf("decode(%q) not ok", key)
		}
		want := historyKeyParts{repo: tc.repo, suite: tc.suite, class: tc.class, name: tc.name}
		if got != want {
			t.Fatalf("round trip %q: got %+v want %+v", key, got, want)
		}
		// The exported encoder is the same shape (the SQL aggregate encoder
		// relies on it).
		if exported := EncodeHistoryKey(tc.repo, tc.suite, tc.class, tc.name); exported != key {
			t.Fatalf("EncodeHistoryKey = %q, want %q", exported, key)
		}
	}
}

// TestHistoryKeyV2ThroughHistory proves the structured key carries through
// the full History API: repo and suite matching isolate identities that
// contain "|", the manifest renders class.name, and flakiness is per test.
func TestHistoryKeyV2ThroughHistory(t *testing.T) {
	h := NewHistory()
	now := time.Unix(1700000000, 0).UTC()
	h.Record("github.com/o/pipe|repo", "suite|part", "cl|ass", "na|me", 1, false, now)
	h.Record("github.com/o/pipe|repo", "suite|part", "cl|ass", "na|me", 1, true, now)
	h.Record("github.com/o/pipe", "suite|part", "cl|ass", "na|me", 1, true, now)

	if got := h.Manifest("github.com/o/pipe|repo", "suite|part"); !reflect.DeepEqual(got, []string{"cl|ass.na|me"}) {
		t.Fatalf("manifest = %v", got)
	}
	if got := h.Manifest("github.com/o/pipe", "suite|part"); !reflect.DeepEqual(got, []string{"cl|ass.na|me"}) {
		t.Fatalf("shorter repo manifest leaked the longer repo: %v", got)
	}
	if got := h.Flaky("github.com/o/pipe|repo"); !reflect.DeepEqual(got, []string{"cl|ass.na|me"}) {
		t.Fatalf("flaky = %v", got)
	}
	if got := h.Flaky("github.com/o/pipe"); len(got) != 0 {
		t.Fatalf("shorter repo flaky leaked: %v", got)
	}
	if got := h.Manifest("github.com/o/pipe", "suite"); len(got) != 0 {
		t.Fatalf("shorter suite manifest leaked: %v", got)
	}
}

// TestLoadHistoryLegacyKeysReadCompat proves a history file written by the
// pre-v2 code (pipe keys) still loads and answers Manifest/Flaky, including
// the ambiguous legacy key whose name contains "|" (which renders raw but
// never crashes or leaks across repositories).
func TestLoadHistoryLegacyKeysReadCompat(t *testing.T) {
	stats := map[string]TestStat{
		"github.com/o/r|build|C|plain": {Runs: 2, Passes: 1, Fails: 1, FlakeProb: 0.5},
		"github.com/o/r|build||amb|iguous": {
			Runs: 2, Passes: 1, Fails: 1, FlakeProb: 0.5,
		},
	}
	raw, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy-history.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := LoadHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Manifest("github.com/o/r", "build"); !reflect.DeepEqual(got, []string{"C.plain", "github.com/o/r|build||amb|iguous"}) {
		t.Fatalf("legacy manifest = %v", got)
	}
	if got := h.Flaky("github.com/o/r"); len(got) != 2 {
		t.Fatalf("legacy flaky = %v, want both entry keys", got)
	}
	if got := h.Flaky("github.com/o"); len(got) != 0 {
		t.Fatalf("legacy flaky leaked to another repository: %v", got)
	}
	if got := h.Manifest("other/repo", "build"); len(got) != 0 {
		t.Fatalf("legacy manifest leaked: %v", got)
	}
}

// TestHistoryCloneDeepCopy pins the copy-on-write primitive: mutating the
// clone (Record) never changes the source, the mutable TestStat fields are
// not shared, and a nil receiver clones to an empty history.
func TestHistoryCloneDeepCopy(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	h := NewHistory()
	h.Record("repo", "suite", "cls", "t", 1, false, now)
	h.Record("repo", "suite", "cls", "t", 3, true, now)
	key := testKey("repo", "suite", "cls", "t")
	before := *h.stats[key]
	beforeOutcomes := append([]bool(nil), before.Outcomes...)

	clone := h.Clone()
	if clone == h {
		t.Fatal("Clone returned the receiver")
	}
	if clone.stats[key] == h.stats[key] {
		t.Fatal("Clone shares the TestStat pointer")
	}
	if &clone.stats[key].Outcomes[0] == &h.stats[key].Outcomes[0] {
		t.Fatal("Clone shares the Outcomes backing array")
	}
	if clone.stats[key].LastFailure == h.stats[key].LastFailure {
		t.Fatal("Clone shares the LastFailure pointer")
	}
	clone.Record("repo", "suite", "cls", "t", 9, false, now)
	clone.Record("repo", "suite", "cls", "new", 1, true, now)
	after := *h.stats[key]
	if after.Runs != before.Runs || after.Fails != before.Fails || after.EWMA != before.EWMA || !reflect.DeepEqual(after.Outcomes, beforeOutcomes) {
		t.Fatalf("clone mutation changed the source: before %+v after %+v", before, after)
	}
	if _, ok := h.stats[testKey("repo", "suite", "cls", "new")]; ok {
		t.Fatal("clone mutation added a test to the source")
	}
	if got := clone.stats[key].Fails; got != before.Fails+1 {
		t.Fatalf("clone fails = %d, want %d", got, before.Fails+1)
	}
	// The clone's LastFailure is an independent pointer with the same value.
	if clone.stats[key].LastFailure == nil || !clone.stats[key].LastFailure.Equal(*before.LastFailure) {
		t.Fatalf("clone last failure = %v, want %v", clone.stats[key].LastFailure, before.LastFailure)
	}
	// A nil receiver clones to an empty, usable history.
	var nilHistory *History
	empty := nilHistory.Clone()
	if empty == nil || len(empty.Manifest("repo", "suite")) != 0 {
		t.Fatal("nil Clone must produce an empty history")
	}
	empty.Record("repo", "suite", "", "t", 1, true, now)
}

// TestHistoryFlakyDropsOutAfterCleanWindow is the reviewer's regression: a
// test that failed long ago and then passed its last 16 observations drops out
// of the flaky set (the window-derived predicate), even though its lifetime
// counters still show the old failure; a fresh failure inside the window puts
// it back.
func TestHistoryFlakyDropsOutAfterCleanWindow(t *testing.T) {
	h := NewHistory()
	now := time.Unix(1700000000, 0).UTC()
	h.Record("repo", "suite", "cls", "t", 1, false, now)
	for i := 0; i < outcomeWindow; i++ {
		h.Record("repo", "suite", "cls", "t", 1, true, now.Add(time.Duration(i+1)*time.Second))
	}
	st := h.stats[testKey("repo", "suite", "cls", "t")]
	if st.Fails == 0 {
		t.Fatal("premise broken: the lifetime failure counter must still be positive")
	}
	if st.FlakeProb != 0 {
		t.Fatalf("clean window flake probability = %v, want 0", st.FlakeProb)
	}
	if got := h.Flaky("repo"); len(got) != 0 {
		t.Fatalf("flaky after a clean window = %v, want none", got)
	}
	// A new failure inside the window restores flakiness.
	h.Record("repo", "suite", "cls", "t", 1, false, now.Add(2*time.Minute))
	if st.FlakeProb <= 0 {
		t.Fatalf("flake probability after a fresh failure = %v", st.FlakeProb)
	}
	if got := h.Flaky("repo"); !reflect.DeepEqual(got, []string{"cls.t"}) {
		t.Fatalf("flaky after a fresh failure = %v, want [cls.t]", got)
	}
	// The window stays bounded at 16 observations throughout.
	if len(st.Outcomes) != outcomeWindow {
		t.Fatalf("outcome window = %d, want %d", len(st.Outcomes), outcomeWindow)
	}
}

// TestHistoryLegacySerializationRoundTripsAdditive proves the persisted shape
// stays additive: a v2-keyed history saves and loads byte-for-byte
// equivalently through the legacy JSON map, including FlakeProb, and the
// window-derived flaky decision survives the round trip.
func TestHistoryLegacySerializationRoundTripsAdditive(t *testing.T) {
	h := NewHistory()
	now := time.Unix(1700000000, 0).UTC()
	for i := 0; i < outcomeWindow+2; i++ {
		h.Record("repo|x", "suite", "cls", "t", float64(i), i%2 == 0, now.Add(time.Duration(i)*time.Second))
	}
	path := filepath.Join(t.TempDir(), "history.json")
	if err := h.Save(path); err != nil {
		t.Fatal(err)
	}
	h2, err := LoadHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	st1 := h.stats[testKey("repo|x", "suite", "cls", "t")]
	st2 := h2.stats[testKey("repo|x", "suite", "cls", "t")]
	if st2 == nil || st1.FlakeProb != st2.FlakeProb || st1.Runs != st2.Runs || !reflect.DeepEqual(st1.Outcomes, st2.Outcomes) {
		t.Fatalf("flaky stats did not round-trip: %+v vs %+v", st1, st2)
	}
	if got, want := h2.Flaky("repo|x"), h.Flaky("repo|x"); !reflect.DeepEqual(got, want) {
		t.Fatalf("flaky after load = %v, want %v", got, want)
	}
}

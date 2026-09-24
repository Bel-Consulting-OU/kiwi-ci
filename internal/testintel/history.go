package testintel

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// ewmaAlpha weights recent durations over history when updating the
	// exponential moving average used for sharding decisions.
	ewmaAlpha = 0.3
	// outcomeWindow is how many most-recent outcomes each TestStat keeps.
	// Flake probability and the Flaky list are derived from this window.
	outcomeWindow = 16
	// historyKeyV2Prefix marks the structured, unambiguous history key
	// encoding: "v2:" + base64.RawURLEncoding(json([4]string{repo, suite,
	// class, name})). Every part is length-delimited by the JSON array, so a
	// part containing "|" (or any other byte) round-trips exactly. Empty and
	// whitespace-only parts are values like any other.
	historyKeyV2Prefix = "v2:"
)

// History accumulates per-test statistics keyed by the canonical, versioned
// history key (see encodeHistoryKey). It is safe for concurrent use and can
// be serialized for server-side persistence.
type History struct {
	mu    sync.Mutex
	stats map[string]*TestStat
}

// TestStat is the EWMA-based history of one test's outcomes and durations.
type TestStat struct {
	Runs        int        `json:"runs"`
	Passes      int        `json:"passes"`
	Fails       int        `json:"fails"`
	EWMA        float64    `json:"ewma"`
	LastFailure *time.Time `json:"last_failure,omitempty"`
	Outcomes    []bool     `json:"outcomes,omitempty"`
	FlakeProb   float64    `json:"flake_prob,omitempty"`
}

func NewHistory() *History {
	return &History{stats: map[string]*TestStat{}}
}

// encodeHistoryKey renders the canonical history key of one test identity:
// "v2:" followed by the raw-URL base64 of the JSON array [repo, suite, class,
// name]. The structured form is unambiguous for EVERY part (a name, class,
// suite or repository containing "|", unicode, empty or whitespace-only
// strings all round-trip), unlike the legacy repo|suite|class|name join. It
// is the ONLY encoding new writes use; decodeHistoryKey still reads legacy
// keys (additive read-compat).
func encodeHistoryKey(repo, suite, class, name string) string {
	// json.Marshal cannot fail for [4]string.
	raw, _ := json.Marshal([4]string{repo, suite, class, name})
	return historyKeyV2Prefix + base64.RawURLEncoding.EncodeToString(raw)
}

// EncodeHistoryKey is encodeHistoryKey for callers outside this package (the
// SQL aggregate encoder), so the incremental store and the in-memory history
// serialize to the SAME key shape.
func EncodeHistoryKey(repo, suite, class, name string) string {
	return encodeHistoryKey(repo, suite, class, name)
}

// historyKeyParts is one decoded history key.
type historyKeyParts struct {
	repo  string
	suite string
	class string
	name  string
}

// decodeHistoryKey parses one history key. ok reports whether the key is a
// fully attributed identity: either a decodable v2 key with EXACTLY four
// elements or a legacy key with exactly four "|"-separated fields. Ambiguous
// legacy keys (a pre-v2 part containing "|", hence a different field count)
// return ok=false with the leading repository and suite fields still filled
// in — exactly the leniency the old repoPart/suitePart helpers had — while
// displayName renders them as their raw key (also the old behavior). A
// corrupt v2 key can never be attributed — including one whose JSON array
// does not have exactly four elements (a shorter array must not be
// zero-filled and a longer one must not be truncated into a bogus identity):
// it falls through to the legacy split, where it can only ever match its own
// literal text as a repository.
func decodeHistoryKey(key string) (historyKeyParts, bool) {
	if rest, found := strings.CutPrefix(key, historyKeyV2Prefix); found {
		if raw, err := base64.RawURLEncoding.DecodeString(rest); err == nil {
			var fields []string
			if err := json.Unmarshal(raw, &fields); err == nil && len(fields) == 4 {
				return historyKeyParts{repo: fields[0], suite: fields[1], class: fields[2], name: fields[3]}, true
			}
		}
	}
	fields := strings.Split(key, "|")
	if len(fields) == 4 {
		return historyKeyParts{repo: fields[0], suite: fields[1], class: fields[2], name: fields[3]}, true
	}
	// Ambiguous legacy key. Its leading repository and suite fields still
	// resolve exactly as the old repoPart/suitePart helpers resolved them;
	// class and name are not attributable.
	parts := historyKeyParts{}
	if len(fields) > 0 {
		parts.repo = fields[0]
	}
	if len(fields) >= 3 {
		// The legacy suite field lived between the first and second
		// separator: a shorter key has no suite field at all.
		parts.suite = fields[1]
	}
	return parts, false
}

// testKey is the canonical history key of one test identity.
func testKey(repo, suite, class, name string) string {
	return encodeHistoryKey(repo, suite, class, name)
}

// Clone returns a deep copy of the history: the stats map and every TestStat
// are new, including the mutable Outcomes slice and the LastFailure pointer.
// Concurrent writers (Record) of the receiver can never change the returned
// snapshot and mutating the clone can never change the receiver, which is the
// copy-on-write primitive the server relies on to publish a new generation
// without touching snapshots already handed to readers. A nil receiver clones
// to an empty history so callers need no nil guard.
func (h *History) Clone() *History {
	if h == nil {
		return NewHistory()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := &History{stats: make(map[string]*TestStat, len(h.stats))}
	for key, st := range h.stats {
		if st == nil {
			continue
		}
		cp := *st
		if st.LastFailure != nil {
			when := *st.LastFailure
			cp.LastFailure = &when
		}
		cp.Outcomes = append([]bool(nil), st.Outcomes...)
		out.stats[key] = &cp
	}
	return out
}

// Record folds one test outcome into the history: run/pass/fail counters,
// the duration EWMA, the bounded outcome window, the last failure time and
// the derived flake probability.
func (h *History) Record(repo, suite, class, name string, dur float64, ok bool, when time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := testKey(repo, suite, class, name)
	st := h.stats[key]
	if st == nil {
		st = &TestStat{}
		h.stats[key] = st
	}
	st.Runs++
	if ok {
		st.Passes++
	} else {
		st.Fails++
		when = when.UTC()
		st.LastFailure = &when
	}
	if st.Runs == 1 {
		st.EWMA = dur
	} else {
		st.EWMA = ewmaAlpha*dur + (1-ewmaAlpha)*st.EWMA
	}
	st.Outcomes = append(st.Outcomes, ok)
	if len(st.Outcomes) > outcomeWindow {
		st.Outcomes = st.Outcomes[len(st.Outcomes)-outcomeWindow:]
	}
	st.FlakeProb = flakeProbability(st.Outcomes)
}

// flakeProbability estimates how often a test deviates from its dominant
// outcome inside the window: the minority outcome share, clamped so a
// single-outcome window is not flaky.
func flakeProbability(outcomes []bool) float64 {
	if len(outcomes) < 2 {
		return 0
	}
	var pass, fail int
	for _, ok := range outcomes {
		if ok {
			pass++
		} else {
			fail++
		}
	}
	minority := pass
	if fail < pass {
		minority = fail
	}
	return float64(minority) / float64(len(outcomes))
}

// OutcomeWindow is how many most-recent outcomes each TestStat keeps. It is
// exported so callers that fold their own outcome history (the report-derived
// test-intelligence summary) apply the SAME window as History.Record.
const OutcomeWindow = outcomeWindow

// FlakeProbability is the window-flakiness predicate of flakeProbability,
// exported for callers that derive flakiness from their own bounded outcome
// windows. A positive result means the window holds both outcomes; a
// single-outcome or empty window is never flaky.
func FlakeProbability(outcomes []bool) float64 {
	return flakeProbability(outcomes)
}

// Flaky returns the sorted names of tests in repo that were flaky inside
// their 16-outcome window: the window-derived flake probability is positive
// (both outcomes present in the window), NOT the lifetime counters a test
// that failed long ago and then passed its whole window would otherwise keep.
// Names are rendered as "name" or "class.name" exactly as recorded. The
// rendered list is de-duplicated: the same class.name in two suites keeps two
// independent windows internally but is ONE display name, matching the SQL
// (DISTINCT on the rendered name) and in-memory (seen-set) flaky queries.
func (h *History) Flaky(repo string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []string{}
	seen := map[string]bool{}
	for key, st := range h.stats {
		if !repoMatches(key, repo) {
			continue
		}
		if st.FlakeProb > 0 {
			name := displayName(key)
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Manifest returns the sorted known test names for repo/suite. A
// checked-in test manifest must list these names before a pipeline can opt
// into history-driven sharding.
func (h *History) Manifest(repo, suite string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []string{}
	for key := range h.stats {
		if !repoMatches(key, repo) || !suiteMatches(key, suite) {
			continue
		}
		out = append(out, displayName(key))
	}
	sort.Strings(out)
	return out
}

// defaultShardDuration is the nominal duration LPT schedules for a test
// without a usable EWMA measurement: TestStat.Runs == 0 (a stat loaded from a
// journal that predates duration recording, or one that has never run) or a
// non-finite/negative EWMA (a corrupt journal: NaN, +Inf, -Inf or a negative
// duration). A nominal unit rather than 0 keeps unmeasured tests spread
// across shards; treating them all as zero-load would pile every one of them
// into the first shard.
const defaultShardDuration = 1.0

// Shard deterministically splits the known tests of repo/suite into the
// given number of shards with longest-processing-time (LPT) list scheduling:
// tests are sorted by descending scheduling duration (ties by display name),
// then each test is assigned to the shard with the smallest accumulated
// duration, ties going to the lowest shard index. LPT is what actually
// balances shard duration; the previous largest-first round-robin is provably
// imbalanced for skewed workloads (one 10s test plus five 1s tests across two
// shards: round-robin yields 12s vs 3s, LPT yields 10s vs 5s, which is
// optimal).
//
// The scheduling duration is TestStat.EWMA; a test without a usable EWMA
// schedules with the documented defaultShardDuration. Each shard's list keeps
// the global scheduling order (descending duration, ties by name), so a shard
// is a stable, deterministic subsequence of that order. The partition is
// exact: every known test appears in exactly one shard. Empty shards are
// materialised as empty (non-nil) slices. A non-positive shard count yields
// one shard with every test.
func (h *History) Shard(repo, suite string, shards int) [][]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	type entry struct {
		name string
		ewma float64
	}
	entries := []entry{}
	for key, st := range h.stats {
		if !repoMatches(key, repo) || !suiteMatches(key, suite) {
			continue
		}
		dur := st.EWMA
		// A corrupt journal can carry a non-finite or negative EWMA: treating
		// any of them as a real scheduling duration would either poison the
		// load arithmetic (Inf/NaN) or invert the LPT order. They all
		// schedule with the documented default, exactly like an unmeasured
		// test.
		if st.Runs == 0 || math.IsNaN(dur) || math.IsInf(dur, 0) || dur < 0 {
			dur = defaultShardDuration
		}
		entries = append(entries, entry{name: displayName(key), ewma: dur})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ewma != entries[j].ewma {
			return entries[i].ewma > entries[j].ewma
		}
		return entries[i].name < entries[j].name
	})
	if shards < 1 {
		shards = 1
	}
	out := make([][]string, shards)
	load := make([]float64, shards)
	for _, e := range entries {
		target := 0
		for i := 1; i < shards; i++ {
			if load[i] < load[target] {
				target = i
			}
		}
		out[target] = append(out[target], e.name)
		load[target] += e.ewma
	}
	for i := range out {
		if out[i] == nil {
			out[i] = []string{}
		}
	}
	return out
}

// Save serializes the history as JSON at path.
func (h *History) Save(path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, err := json.MarshalIndent(h.stats, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadHistory loads a History previously written by Save.
func LoadHistory(path string) (*History, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	stats := map[string]*TestStat{}
	if err := json.Unmarshal(b, &stats); err != nil {
		return nil, err
	}
	h := &History{stats: stats}
	for k, st := range h.stats {
		if st == nil {
			delete(h.stats, k)
		}
	}
	return h, nil
}

func repoMatches(key, repo string) bool {
	parts, _ := decodeHistoryKey(key)
	return parts.repo == repo
}

func suiteMatches(key, suite string) bool {
	parts, _ := decodeHistoryKey(key)
	return parts.suite == suite
}

// displayName renders a history key as "name" (empty class) or "class.name".
// A key that is not fully attributed (an ambiguous legacy key, or one that
// never was a history key) renders as itself, exactly as the pre-v2 helper
// did.
func displayName(key string) string {
	parts, ok := decodeHistoryKey(key)
	if !ok {
		return key
	}
	if parts.class == "" {
		return parts.name
	}
	return parts.class + "." + parts.name
}

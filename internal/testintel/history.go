package testintel

import (
	"encoding/json"
	"os"
	"sort"
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
)

// History accumulates per-test statistics keyed by repo|suite|class|name.
// It is safe for concurrent use and can be serialized for server-side
// persistence.
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

func testKey(repo, suite, class, name string) string {
	return repo + "|" + suite + "|" + class + "|" + name
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

// Flaky returns the sorted names of tests in repo that have both passed and
// failed inside their outcome window (class-qualified when a class exists
// in at least one observation... names are rendered as "name" or
// "class.name" exactly as recorded via a stable rendering helper).
func (h *History) Flaky(repo string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []string{}
	for key, st := range h.stats {
		if !repoMatches(key, repo) {
			continue
		}
		if st.Passes > 0 && st.Fails > 0 {
			out = append(out, displayName(key))
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

// Shard deterministically splits the known tests of repo/suite into the
// given number of shards, largest-duration-first round-robin so shards end
// up duration-balanced. Ties break on name for reproducibility. A
// non-positive shard count yields one shard with every test.
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
		entries = append(entries, entry{name: displayName(key), ewma: st.EWMA})
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
	for i, e := range entries {
		shard := i % shards
		out[shard] = append(out[shard], e.name)
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
	return repoPart(key) == repo
}

func repoPart(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i]
		}
	}
	return key
}

func suitePart(key string) string {
	first := -1
	second := -1
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			if first < 0 {
				first = i
			} else if second < 0 {
				second = i
				break
			}
		}
	}
	if second < 0 {
		return ""
	}
	return key[first+1 : second]
}

func suiteMatches(key, suite string) bool {
	return suitePart(key) == suite
}

// displayName renders a history key as "name" (empty class) or "class.name".
func displayName(key string) string {
	parts := splitKey(key)
	if len(parts) != 4 {
		return key
	}
	if parts[2] == "" {
		return parts[3]
	}
	return parts[2] + "." + parts[3]
}

func splitKey(key string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(key); i++ {
		if i == len(key) || key[i] == '|' {
			out = append(out, key[start:i])
			start = i + 1
		}
	}
	return out
}

package dogfood

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestSeedCaptureIsReplayable pins requirement "seed capture for chaos
// reproducibility": the seed record carries the run identity and rebuilds
// the same deterministic stream on replay.
func TestSeedCaptureIsReplayable(t *testing.T) {
	meta := RunMetadata{
		Commit:       "cafebabe",
		Executor:     "fake",
		Versions:     VersionInfo{Server: "1.0", Runner: "1.0", Protocol: "kiwi.execution.v2"},
		PolicyDigest: strings.Repeat("8", 64),
	}
	s := NewSeed(0xC0FFEE, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC), meta)
	if err := s.Validate(); err != nil {
		t.Fatalf("seed rejected: %v", err)
	}
	if !s.Valid() {
		t.Fatal("seed invalid after construction")
	}
	// Replay produces the identical decision stream.
	a := s.Source()
	b := NewSeed(s.Value, s.CapturedAt, meta).Source()
	for i := 0; i < 8; i++ {
		if x, y := a.Int63(), b.Int63(); x != y {
			t.Fatalf("replay diverged at %d: %d != %d", i, x, y)
		}
	}
	// An incomplete seed is refused before any scenario runs.
	partial := NewSeed(1, time.Now(), RunMetadata{Commit: "x"})
	if err := partial.Validate(); err == nil {
		t.Fatal("incomplete seed validated")
	}
}

// TestDogfoodResultJSONShape pins the dogfood-result.json contract: the
// stable field names a report parser relies on, and the seal fills the
// schema version and green bit.
func TestDogfoodResultJSONShape(t *testing.T) {
	d := DogfoodResult{
		Seed:       NewSeed(1, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), RunMetadata{Commit: "c", Versions: VersionInfo{Protocol: "kiwi.execution.v2"}}),
		Namespace:  Namespace{Prefix: "df-1"},
		Topology:   "local",
		StartedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC),
		Scenarios: []ScenarioResult{{
			ID: "DF-BOOT-001", Name: "boot", Arm: "positive", Topology: "local",
			Attempts: AttemptAccounting{AttemptCount: 1, FirstAttemptResult: "success", FinalResult: "success"},
			Green:    true,
		}},
	}
	raw, err := d.MarshalResult()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"schema_version", "seed", "namespace", "topology", "started_at", "finished_at", "scenarios", "green"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("dogfood-result.json missing %q: %s", key, raw)
		}
	}
	if parsed["schema_version"].(float64) != float64(DogfoodSchemaVersion) {
		t.Fatalf("schema_version = %v", parsed["schema_version"])
	}
	if parsed["green"] != true {
		t.Fatalf("green = %v", parsed["green"])
	}
	scenarios := parsed["scenarios"].([]any)
	sc := scenarios[0].(map[string]any)
	for _, key := range []string{"id", "attempts", "oracle", "green"} {
		if _, ok := sc[key]; !ok {
			t.Fatalf("scenario row missing %q", key)
		}
	}
	attempts := sc["attempts"].(map[string]any)
	for _, key := range []string{"attempt_count", "first_attempt_result", "final_result"} {
		if _, ok := attempts[key]; !ok {
			t.Fatalf("attempts row missing %q", key)
		}
	}
}

// TestTopologyShapes pin the two declared topologies: local bootstraps with
// a server and one runner; distributed needs its durable stores and two
// runners (the lease-reassignment shape).
func TestTopologyShapes(t *testing.T) {
	ns, err := NewNamespace(time.Now(), defaultEntropy())
	if err != nil {
		t.Fatalf("namespace: %v", err)
	}
	local := Local(ns)
	if err := local.Validate(); err != nil {
		t.Fatalf("local: %v", err)
	}
	if len(local.RunnerNames()) != 1 {
		t.Fatalf("local runners = %v", local.RunnerNames())
	}
	dist := Distributed(ns)
	if err := dist.Validate(); err != nil {
		t.Fatalf("distributed: %v", err)
	}
	if len(dist.RunnerNames()) != 2 {
		t.Fatalf("distributed runners = %v", dist.RunnerNames())
	}
	kinds := dist.Kinds()
	if kinds[ComponentPostgres] != 1 || kinds[ComponentObjectStore] != 1 {
		t.Fatalf("distributed kinds = %v", kinds)
	}
	// A topology with runners but no server is refused.
	bad := Topology{Name: "bad", Components: []Component{{Kind: ComponentRunner, Name: "r1"}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("runner-only topology validated")
	}
}

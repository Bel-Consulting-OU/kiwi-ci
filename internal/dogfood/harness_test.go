package dogfood

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// TestDogfoodResultBundleEmission pins the suite-level result bundle: with
// DOGFOOD_RESULT_DIR set (or a fallback scratch dir), EmitResult writes
// dogfood-result.json plus one scenario-results/<id>.json per arm, and every
// emitted file re-parses into its documented shape.
func TestDogfoodResultBundleEmission(t *testing.T) {
	d := DogfoodResult{
		Seed:       NewSeed(2, time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC), RunMetadata{Commit: "c", Versions: VersionInfo{Protocol: "kiwi.execution.v2"}}),
		Namespace:  Namespace{Prefix: "df-2"},
		Topology:   "distributed",
		StartedAt:  time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 2, 2, 0, 2, 0, 0, time.UTC),
		Scenarios: []ScenarioResult{{
			ID: "DF-BOOT-001", Name: "boot", Arm: "positive", Topology: "local",
			Attempts: AttemptAccounting{AttemptCount: 1, FirstAttemptResult: "success", FinalResult: "success"},
			Green:    true,
		}, {
			ID: "DF-LEASE-001", Name: "stale-runner", Arm: "negative", Topology: "distributed",
			Attempts: AttemptAccounting{AttemptCount: 1, FirstAttemptResult: "rejected", FinalResult: "rejected"},
			Green:    true,
		}},
	}

	t.Run("env dir", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv(ResultDirEnv, dir)
		got, err := d.EmitResult(t.TempDir()) // fallback must be ignored
		if err != nil {
			t.Fatalf("EmitResult: %v", err)
		}
		if got != dir {
			t.Fatalf("EmitResult dir = %q, want DOGFOOD_RESULT_DIR %q", got, dir)
		}
		assertResultBundle(t, dir, d)
	})

	t.Run("fallback dir", func(t *testing.T) {
		t.Setenv(ResultDirEnv, "")
		dir := t.TempDir()
		got, err := d.EmitResult(dir)
		if err != nil {
			t.Fatalf("EmitResult: %v", err)
		}
		if got != dir {
			t.Fatalf("EmitResult dir = %q, want fallback %q", got, dir)
		}
		assertResultBundle(t, dir, d)
	})

	t.Run("no dir refused", func(t *testing.T) {
		t.Setenv(ResultDirEnv, "  ")
		if _, err := d.EmitResult(""); err == nil {
			t.Fatal("EmitResult with no directory succeeded")
		}
	})
}

// assertResultBundle verifies dogfood-result.json and scenario-results/
// exist and parse back into the sealed document shapes.
func assertResultBundle(t *testing.T, dir string, want DogfoodResult) {
	t.Helper()
	top := filepath.Join(dir, "dogfood-result.json")
	raw, err := os.ReadFile(top)
	if err != nil {
		t.Fatalf("read %s: %v", top, err)
	}
	var parsed DogfoodResult
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse dogfood-result.json: %v\n%s", err, raw)
	}
	if parsed.SchemaVersion != DogfoodSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", parsed.SchemaVersion, DogfoodSchemaVersion)
	}
	if !parsed.Green {
		t.Fatalf("emitted bundle is not green: %s", raw)
	}
	if len(parsed.Scenarios) != len(want.Scenarios) {
		t.Fatalf("emitted scenarios = %d, want %d", len(parsed.Scenarios), len(want.Scenarios))
	}
	entries, err := os.ReadDir(filepath.Join(dir, "scenario-results"))
	if err != nil {
		t.Fatalf("read scenario-results: %v", err)
	}
	if len(entries) != len(want.Scenarios) {
		t.Fatalf("scenario-results files = %d, want %d", len(entries), len(want.Scenarios))
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Fatalf("scenario-results contains directory %s", e.Name())
		}
		body, err := os.ReadFile(filepath.Join(dir, "scenario-results", e.Name()))
		if err != nil {
			t.Fatalf("read scenario file: %v", err)
		}
		var s ScenarioResult
		if err := json.Unmarshal(body, &s); err != nil {
			t.Fatalf("parse %s: %v\n%s", e.Name(), err, body)
		}
		if s.ID == "" {
			t.Fatalf("scenario file %s has empty id", e.Name())
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("scenario file %s failed Validate: %v", e.Name(), err)
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

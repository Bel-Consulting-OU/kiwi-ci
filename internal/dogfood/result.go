package dogfood

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AttemptAccounting is the explicit record of every execution attempt a
// scenario made. There are NO hidden retries: a scenario either records the
// single attempt it made, or it records each retry with its cause and the
// outcome of the first attempt. A consumer must be able to see from the
// result alone whether anything ran more than once and why.
type AttemptAccounting struct {
	// AttemptCount is how many attempts were actually made (>= 1).
	AttemptCount int `json:"attempt_count"`
	// RetryCause names why a retry happened; empty when AttemptCount is 1.
	RetryCause string `json:"retry_cause,omitempty"`
	// FirstAttemptResult is the outcome of the first attempt.
	FirstAttemptResult string `json:"first_attempt_result"`
	// FinalResult is the outcome of the last attempt.
	FinalResult string `json:"final_result"`
}

// ScenarioResult is the dogfood-result.json shape of one scenario arm: its
// identity, the seed and namespace it ran under, the attempt accounting, the
// eight-oracle verdict, and the green bit. The JSON field names are the
// stable report contract; tools parse this file, so changes bump
// DogfoodSchemaVersion.
type ScenarioResult struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Arm       string            `json:"arm"`
	Topology  string            `json:"topology"`
	Seed      Seed              `json:"seed"`
	Namespace Namespace         `json:"namespace"`
	Attempts  AttemptAccounting `json:"attempts"`
	Oracle    OracleResult      `json:"oracle"`
	Green     bool              `json:"green"`
	// RetryUnderTest marks arms whose PURPOSE is to exercise retry behavior.
	// Everything else must be single-attempt: a flaky retry of a
	// non-retry-under-test scenario is non-green by construction.
	RetryUnderTest bool   `json:"retry_under_test,omitempty"`
	Notes          string `json:"notes,omitempty"`
}

// DogfoodResult is the aggregate dogfood-result.json document of one
// invocation. Green is true only when every scenario arm is green under
// Result.Validate's rules (including the no-hidden-retry rule).
type DogfoodResult struct {
	SchemaVersion int              `json:"schema_version"`
	Seed          Seed             `json:"seed"`
	Namespace     Namespace        `json:"namespace"`
	Topology      string           `json:"topology"`
	StartedAt     time.Time        `json:"started_at"`
	FinishedAt    time.Time        `json:"finished_at"`
	Scenarios     []ScenarioResult `json:"scenarios"`
	Green         bool             `json:"green"`
}

// DogfoodSchemaVersion is the version of the dogfood-result.json shape. It
// is bumped whenever a field changes meaning so parsers can refuse an
// unknown document instead of guessing.
const DogfoodSchemaVersion = 1

// ErrFlakyRetry is the non-green verdict of a scenario that retried without
// being under retry-test. The retry is still RECORDED (nothing is hidden);
// it simply cannot be graded green.
var ErrFlakyRetry = fmt.Errorf("dogfood: scenario retried without retry_under_test; flaky retry is non-green")

// Validate enforces the no-hidden-retry rule on one scenario arm. It is
// called before the aggregate result is sealed: a single-attempt arm must
// have consistent accounting, and a multi-attempt arm is allowed to be green
// only when the arm is explicitly under retry-test.
func (r ScenarioResult) Validate() error {
	if r.Attempts.AttemptCount < 1 {
		return fmt.Errorf("dogfood: scenario %s has attempt_count %d, want >= 1", r.ID, r.Attempts.AttemptCount)
	}
	if r.Attempts.AttemptCount == 1 {
		if r.Attempts.RetryCause != "" {
			return fmt.Errorf("dogfood: scenario %s records retry_cause %q with a single attempt", r.ID, r.Attempts.RetryCause)
		}
		if r.Attempts.FirstAttemptResult == "" || r.Attempts.FinalResult == "" {
			return fmt.Errorf("dogfood: scenario %s is missing attempt results", r.ID)
		}
		return nil
	}
	if r.Attempts.RetryCause == "" {
		return fmt.Errorf("dogfood: scenario %s has %d attempts but no retry_cause", r.ID, r.Attempts.AttemptCount)
	}
	if r.Attempts.FirstAttemptResult == "" || r.Attempts.FinalResult == "" {
		return fmt.Errorf("dogfood: scenario %s is missing attempt results", r.ID)
	}
	if !r.RetryUnderTest {
		return ErrFlakyRetry
	}
	return nil
}

// Seal applies Validate and derives the green bit. A flaky retry of a
// non-retry-under-test scenario can never finish green: the seal forces
// Green false and returns ErrFlakyRetry so the caller records the reason.
func (r ScenarioResult) Seal() (ScenarioResult, error) {
	err := r.Validate()
	if err != nil {
		r.Green = false
		return r, err
	}
	return r, nil
}

// Seal validates every scenario arm and derives the aggregate green bit.
// Any arm that fails validation (including the flaky-retry rule) reddens the
// whole invocation: a dogfood run is only as green as its worst arm.
func (d DogfoodResult) Seal() (DogfoodResult, error) {
	var firstErr error
	sealed := make([]ScenarioResult, len(d.Scenarios))
	green := true
	for i, s := range d.Scenarios {
		out, err := s.Seal()
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("scenario %s: %w", s.ID, err)
		}
		if err != nil {
			out.Green = false
			green = false
		}
		if !out.Green {
			green = false
		}
		sealed[i] = out
	}
	d.Scenarios = sealed
	d.Green = green
	d.SchemaVersion = DogfoodSchemaVersion
	return d, firstErr
}

// MarshalResult renders the dogfood-result.json document. It is the file the
// CI job publishes; the shape is the ScenarioResult/DogfoodResult JSON tags.
func (d DogfoodResult) MarshalResult() ([]byte, error) {
	sealed, _ := d.Seal()
	return json.MarshalIndent(sealed, "", "  ")
}

// ResultDirEnv names the environment variable that selects the result-bundle
// output directory for a dogfood run. When empty, callers fall back to their
// own scratch directory (tests use t.TempDir()).
const ResultDirEnv = "DOGFOOD_RESULT_DIR"

// ScenarioResultFileName returns the stable scenario-results/ file name for
// one arm. IDs and arms are scenario identifiers, but they can contain
// characters that are hostile to file systems, so anything outside the
// portable set is folded to '-' and a collision-safe ordinal is appended.
func ScenarioResultFileName(s ScenarioResult, ordinal int) string {
	sanitize := func(in string) string {
		var b strings.Builder
		for _, r := range in {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
				b.WriteRune(r)
			default:
				b.WriteByte('-')
			}
		}
		out := strings.Trim(b.String(), "-.")
		if out == "" {
			out = "scenario"
		}
		return out
	}
	name := sanitize(s.ID)
	if s.Arm != "" {
		name += "-" + sanitize(s.Arm)
	}
	if ordinal > 0 {
		name += fmt.Sprintf("-%d", ordinal)
	}
	return name + ".json"
}

// WriteResultBundle writes the execution-dogfood result bundle under dir:
// dogfood-result.json (the sealed MarshalResult document) and one
// scenario-results/<id>[-<arm>].json per scenario arm. The directory and the
// scenario-results/ subdirectory are created as needed. It returns the path
// of dogfood-result.json.
func (d DogfoodResult) WriteResultBundle(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("dogfood: result bundle directory is empty")
	}
	raw, err := d.MarshalResult()
	if err != nil {
		return "", err
	}
	sealed, _ := d.Seal()
	if err := os.MkdirAll(filepath.Join(dir, "scenario-results"), 0o755); err != nil {
		return "", err
	}
	top := filepath.Join(dir, "dogfood-result.json")
	if err := os.WriteFile(top, raw, 0o644); err != nil {
		return "", err
	}
	used := map[string]bool{}
	for i, s := range sealed.Scenarios {
		name := ScenarioResultFileName(s, 0)
		if used[name] {
			name = ScenarioResultFileName(s, i+1)
		}
		used[name] = true
		body, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, "scenario-results", name), body, 0o644); err != nil {
			return "", err
		}
	}
	return top, nil
}

// EmitResult writes the result bundle to the directory named by
// DOGFOOD_RESULT_DIR when that variable is set and non-empty; otherwise it
// writes to fallback (tests pass t.TempDir() so the bundle is always
// exercised even without the environment variable). It returns the directory
// actually written.
func (d DogfoodResult) EmitResult(fallback string) (string, error) {
	dir := strings.TrimSpace(os.Getenv(ResultDirEnv))
	if dir == "" {
		dir = fallback
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("dogfood: no result directory (%s unset and no fallback)", ResultDirEnv)
	}
	if _, err := d.WriteResultBundle(dir); err != nil {
		return "", err
	}
	return dir, nil
}

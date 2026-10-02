package executor

// Retry-policy precedence regressions: explicit zero disables retries, absent
// values inherit, and persisted/programmatic values are clamped.

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestEffectiveStepRetryPrecedence(t *testing.T) {
	defaults := pipeline.Defaults{Retry: pipeline.Retry{Max: 1}}
	job := pipeline.Job{Retry: pipeline.Retry{Max: 3}}

	// Absent step retry inherits the job policy.
	if got := effectiveStepRetry(pipeline.Step{}, job, defaults); got.Max != 3 {
		t.Fatalf("absent step retry = %+v, want job max 3", got)
	}
	// Absent job retry inherits the defaults.
	if got := effectiveStepRetry(pipeline.Step{}, pipeline.Job{}, defaults); got.Max != 1 {
		t.Fatalf("absent job retry = %+v, want default max 1", got)
	}
	// An explicit step retry (max: 0) wins and disables retries.
	step := pipeline.Step{Retry: pipeline.Retry{Max: 0, MaxSet: true}}
	if got := effectiveStepRetry(step, job, defaults); got.Max != 0 {
		t.Fatalf("explicit zero step retry = %+v, want 0", got)
	}
	// An explicit job retry (max: 0) beats the defaults.
	if got := effectiveStepRetry(pipeline.Step{}, pipeline.Job{Retry: pipeline.Retry{Max: 0, MaxSet: true}}, defaults); got.Max != 0 {
		t.Fatalf("explicit zero job retry = %+v, want 0", got)
	}
	// A programmatic non-zero step retry still applies.
	if got := effectiveStepRetry(pipeline.Step{Retry: pipeline.Retry{Max: 2}}, job, defaults); got.Max != 2 {
		t.Fatalf("programmatic step retry = %+v, want 2", got)
	}
}

func TestEffectiveStepRetryClampsPersistedValue(t *testing.T) {
	step := pipeline.Step{Retry: pipeline.Retry{Max: int(^uint(0) >> 1), MaxSet: true}}
	got := effectiveStepRetry(step, pipeline.Job{}, pipeline.Defaults{})
	if got.Max != pipeline.MaxStepRetries {
		t.Fatalf("clamped step retry = %d, want %d", got.Max, pipeline.MaxStepRetries)
	}
}

func TestEffectiveServiceRetriesZeroMeansOne(t *testing.T) {
	if got := effectiveServiceRetries(pipeline.Service{Retries: 0, RetriesSet: true}); got != 0 {
		t.Fatalf("explicit zero service retries = %d, want 0 (one attempt)", got)
	}
	if got := effectiveServiceRetries(pipeline.Service{}); got != 12 {
		t.Fatalf("absent service retries = %d, want the 12 default", got)
	}
	if got := effectiveServiceRetries(pipeline.Service{Retries: pipeline.MaxServiceRetries + 1}); got != pipeline.MaxServiceRetries {
		t.Fatalf("clamped service retries = %d, want %d", got, pipeline.MaxServiceRetries)
	}
}

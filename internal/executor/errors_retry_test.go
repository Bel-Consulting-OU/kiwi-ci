package executor

import (
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestRunErrorClassMapping(t *testing.T) {
	cases := []struct {
		kind string
		want FailureClass
	}{
		{"", CommandFailure},
		{ErrorFailure, CommandFailure},
		{ErrorInfra, InfrastructureFailure},
		{ErrorTimeout, TimeoutFailure},
		{ErrorLostRunner, LostRunnerFailure},
		{ErrorCancelled, CancelledFailure},
		{ErrorConfig, ConfigurationFailure},
		{ErrorPolicy, PolicyFailure},
		{ErrorCache, CacheFailure},
		{ErrorArtifact, ArtifactFailure},
		{"unexpected-kind", CommandFailure},
	}
	for _, c := range cases {
		re := &RunError{Kind: c.kind, Err: errors.New("boom")}
		if got := re.Class(); got != c.want {
			t.Errorf("Class() for kind %q = %q, want %q", c.kind, got, c.want)
		}
	}
}

func TestFailureClassRetryabilityTable(t *testing.T) {
	classes := map[FailureClass]bool{
		CommandFailure:        true,
		InfrastructureFailure: true,
		TimeoutFailure:        true,
		CacheFailure:          true,
		ArtifactFailure:       true,
		CancelledFailure:      false,
		ConfigurationFailure:  false,
		PolicyFailure:         false,
		LostRunnerFailure:     false,
	}
	for class, want := range classes {
		if got := retryableClass(class); got != want {
			t.Errorf("retryableClass(%q) = %v, want %v", class, got, want)
		}
	}
}

func TestRetryAllowsDefaultClassPolicy(t *testing.T) {
	cases := []struct {
		kind string
		want bool
	}{
		{ErrorFailure, true},
		{ErrorInfra, true},
		{ErrorTimeout, true},
		{ErrorCache, true},
		{ErrorArtifact, true},
		{ErrorCancelled, false},
		{ErrorConfig, false},
		{ErrorPolicy, false},
		{ErrorLostRunner, false},
	}
	for _, c := range cases {
		r := pipeline.Retry{Max: 3}
		err := &RunError{Kind: c.kind, Err: errors.New("boom")}
		if got := retryAllows(r, err); got != c.want {
			t.Errorf("retryAllows(max=3, %q) = %v, want %v", c.kind, got, c.want)
		}
	}
	if retryAllows(pipeline.Retry{Max: 3}, errors.New("plain error")) != true {
		t.Error("plain errors must be retryable command failures by default")
	}
	if retryAllows(pipeline.Retry{Max: 0}, &RunError{Kind: ErrorFailure, Err: errors.New("x")}) {
		t.Error("max=0 must never retry")
	}
}

func TestRetryAllowsExplicitOnList(t *testing.T) {
	r := pipeline.Retry{Max: 2, On: []string{"failure"}}
	if !retryAllows(r, &RunError{Kind: ErrorFailure, Err: errors.New("x")}) {
		t.Error("on: [failure] must retry command failures")
	}
	if retryAllows(r, &RunError{Kind: ErrorInfra, Err: errors.New("x")}) {
		t.Error("on: [failure] must not retry infra failures")
	}
	if retryAllows(r, &RunError{Kind: ErrorTimeout, Err: errors.New("x")}) {
		t.Error("on: [failure] must not retry timeouts")
	}
	any := pipeline.Retry{Max: 2, On: []string{"any"}}
	if !retryAllows(any, &RunError{Kind: ErrorConfig, Err: errors.New("x")}) {
		t.Error("on: [any] must retry configuration failures")
	}
	if retryAllows(any, &RunError{Kind: ErrorCancelled, Err: errors.New("x")}) {
		t.Error("cancellation must never retry, even with on: [any]")
	}
}

func TestBackoffForBounds(t *testing.T) {
	base, maxd := time.Second, 30*time.Second
	for attempt := 1; attempt <= 15; attempt++ {
		for _, seed := range []uint64{1, 2, 42, 0xdeadbeef} {
			d := backoffFor(attempt, base, maxd, seed)
			if d < time.Duration(0.8*float64(base)) {
				t.Errorf("attempt %d seed %d: backoff %v below 80%% of base", attempt, seed, d)
			}
			if d > maxd {
				t.Errorf("attempt %d seed %d: backoff %v exceeds max %v", attempt, seed, d, maxd)
			}
		}
	}
	if d := backoffFor(1, 0, 0, 0); d < 800*time.Millisecond || d > 1200*time.Millisecond {
		t.Errorf("zero base/max must default to ~1s with jitter, got %v", d)
	}
}

func TestBackoffForDeterminism(t *testing.T) {
	args := [][2]uint64{{1, 100}, {7, 99}, {3, 0x12345678}}
	for _, a := range args {
		v1 := backoffFor(3, time.Second, time.Minute, a[0])
		v2 := backoffFor(3, time.Second, time.Minute, a[0])
		if v1 != v2 {
			t.Fatalf("backoffFor not deterministic: %v vs %v", v1, v2)
		}
		v3 := backoffFor(3, time.Second, time.Minute, a[1])
		if v3 != backoffFor(3, time.Second, time.Minute, a[1]) {
			t.Fatalf("backoffFor not deterministic: %v", v3)
		}
	}
}

func TestBackoffForJitter(t *testing.T) {
	base := time.Second
	var below, above, seen int
	values := map[time.Duration]bool{}
	for seed := uint64(1); seed <= 200; seed++ {
		d := backoffFor(1, base, time.Minute, seed)
		if d < base {
			below++
		}
		if d > base {
			above++
		}
		if d != base {
			values[d] = true
		}
		seen++
	}
	if below == 0 || above == 0 {
		t.Fatalf("jitter must produce values both below (%d) and above (%d) the base delay", below, above)
	}
	if len(values) < 10 {
		t.Fatalf("jitter produced only %d distinct delays over %d seeds", len(values), seen)
	}
}

func TestBackoffForExponentialGrowthCapped(t *testing.T) {
	base, maxd := time.Second, 4*time.Second
	var prev time.Duration
	for attempt := 1; attempt <= 10; attempt++ {
		mid := backoffFor(attempt, base, maxd, 0)
		if mid < prev*8/10 {
			t.Errorf("attempt %d: backoff %v regressed from %v", attempt, mid, prev)
		}
		prev = mid
	}
	if prev > maxd {
		t.Fatalf("capped backoff %v exceeds max %v", prev, maxd)
	}
}

func TestXorshift01Range(t *testing.T) {
	for seed := uint64(0); seed < 1000; seed++ {
		v := xorshift01(seed)
		if v < 0 || v >= 1 {
			t.Fatalf("xorshift01(%d) = %v outside [0,1)", seed, v)
		}
	}
}

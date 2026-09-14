package executor

import (
	"errors"
	"fmt"
	"time"
)

const (
	ErrorFailure    = "failure"
	ErrorInfra      = "infra"
	ErrorTimeout    = "timeout"
	ErrorCancelled  = "cancelled"
	ErrorConfig     = "config"
	ErrorPolicy     = "policy"
	ErrorCache      = "cache"
	ErrorArtifact   = "artifact"
	ErrorLostRunner = "lost_runner"
)

// FailureClass is the coarse, retry-relevant category of a run failure. The
// class constants map onto the errorKind values a RunError carries, so
// Class() is the single translation point between a concrete Kind and the
// retry policy.
type FailureClass string

const (
	CommandFailure        FailureClass = ErrorFailure
	InfrastructureFailure FailureClass = ErrorInfra
	TimeoutFailure        FailureClass = ErrorTimeout
	LostRunnerFailure     FailureClass = ErrorLostRunner
	CancelledFailure      FailureClass = ErrorCancelled
	ConfigurationFailure  FailureClass = ErrorConfig
	PolicyFailure         FailureClass = ErrorPolicy
	CacheFailure          FailureClass = ErrorCache
	ArtifactFailure       FailureClass = ErrorArtifact
)

type RunError struct {
	Kind string
	Err  error
}

func (e *RunError) Error() string { return fmt.Sprintf("%s: %v", e.Kind, e.Err) }
func (e *RunError) Unwrap() error { return e.Err }

// Class maps the RunError's Kind onto a FailureClass. An empty or unknown
// Kind defaults to CommandFailure, matching errorKind's default.
func (e *RunError) Class() FailureClass {
	switch e.Kind {
	case "", ErrorFailure:
		return CommandFailure
	case ErrorInfra:
		return InfrastructureFailure
	case ErrorTimeout:
		return TimeoutFailure
	case ErrorLostRunner:
		return LostRunnerFailure
	case ErrorCancelled:
		return CancelledFailure
	case ErrorConfig:
		return ConfigurationFailure
	case ErrorPolicy:
		return PolicyFailure
	case ErrorCache:
		return CacheFailure
	case ErrorArtifact:
		return ArtifactFailure
	default:
		return CommandFailure
	}
}

func errorKind(err error) string {
	var re *RunError
	if errors.As(err, &re) {
		return re.Kind
	}
	return ErrorFailure
}

// failureClass classifies an arbitrary error for retry policy. Errors that
// are not RunErrors (or wrap one) are treated as command failures.
func failureClass(err error) FailureClass {
	var re *RunError
	if errors.As(err, &re) {
		return re.Class()
	}
	return CommandFailure
}

// retryableClass reports whether the default retry policy (no explicit
// retry.on list) retries a failure of the given class. Transient failures
// retry; user-authored policy, configuration, cancellation, and lost-runner
// failures never do.
func retryableClass(c FailureClass) bool {
	switch c {
	case CommandFailure, InfrastructureFailure, TimeoutFailure, CacheFailure, ArtifactFailure:
		return true
	default:
		return false
	}
}

// maxRetryBackoff caps the exponential retry delay growth so a high retry
// count cannot park a job for hours.
const maxRetryBackoff = time.Minute

// backoffFor computes the deterministic delay before retry attempt N
// (1-based): base * 2^(N-1), capped at max, with ±20% deterministic jitter
// derived from a small xorshift seeded from attempt+seed. Identical inputs
// always produce identical delays; distinct seeds decorrelate jobs that
// failed at the same instant.
func backoffFor(attempt int, base, maxd time.Duration, seed uint64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if base <= 0 {
		base = time.Second
	}
	if maxd < base {
		maxd = base
	}
	d := base
	for i := 1; i < attempt; i++ {
		if d >= maxd {
			break
		}
		if d > maxd/2 {
			d = maxd
			break
		}
		d *= 2
	}
	factor := 0.8 + 0.4*xorshift01(seed+uint64(attempt))
	d = time.Duration(float64(d) * factor)
	if d > maxd {
		d = maxd
	}
	if d < 1 {
		d = 1
	}
	return d
}

// xorshift01 returns a deterministic pseudo-random value in [0,1).
func xorshift01(seed uint64) float64 {
	s := seed ^ 0x9E3779B97F4A7C15
	s ^= s << 13
	s ^= s >> 7
	s ^= s << 17
	return float64(s%1000) / 1000
}

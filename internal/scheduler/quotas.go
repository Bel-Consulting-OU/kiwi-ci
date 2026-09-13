package scheduler

import (
	"fmt"
	"math"
)

// RepoQuota bounds cumulative resource consumption (e.g. minutes) for one
// repository. It is a planning helper: enforcement lands with the persistence
// phase, which will track Used against Limit transactionally.
type RepoQuota struct {
	Repo  string  `json:"repo"`
	Limit float64 `json:"limit"`
	Used  float64 `json:"used"`
}

// TeamQuota bounds cumulative resource consumption for one team.
type TeamQuota struct {
	Team  string  `json:"team"`
	Limit float64 `json:"limit"`
	Used  float64 `json:"used"`
}

// WithinQuota reports whether consuming delta more units keeps the entity
// within its quota. Inputs must be finite and non-negative; otherwise an
// error is returned instead of a bogus admission decision. Arithmetic
// saturates at math.MaxInt64 so a unit beyond the int64 range can never
// wrap into a negative total and flip the verdict.
func WithinQuota(limit, used, delta float64) (bool, error) {
	for _, v := range []float64{limit, used, delta} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return false, fmt.Errorf("scheduler: invalid quota value %v", v)
		}
	}
	total := used + delta
	if math.IsInf(total, 1) || total > math.MaxInt64 {
		total = math.MaxInt64
	}
	return total <= limit, nil
}

// SaturatingAdd returns a+b clamped to [0, math.MaxInt64] for int64 quota
// accounting: overflow saturates instead of wrapping.
func SaturatingAdd(a, b int64) int64 {
	if a < 0 {
		a = 0
	}
	if b < 0 {
		b = 0
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

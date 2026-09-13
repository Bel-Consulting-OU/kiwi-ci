package scheduler

import "github.com/Bel-Consulting-OU/kiwi-ci/internal/model"

// EnvironmentAtCapacity reports whether a candidate job's environment has
// reached its concurrency limit: it counts other running jobs targeting the
// same environment and returns true once the limit is met or exceeded.
// Empty environments and non-positive limits impose no restriction.
func EnvironmentAtCapacity(j model.Job, jobs map[string]model.Job) bool {
	if j.Environment == "" || j.EnvironmentConcurrency <= 0 {
		return false
	}
	active := 0
	for _, other := range jobs {
		if other.ID == j.ID || other.Environment != j.Environment || other.Status != model.StatusRunning {
			continue
		}
		active++
		if active >= j.EnvironmentConcurrency {
			return true
		}
	}
	return false
}

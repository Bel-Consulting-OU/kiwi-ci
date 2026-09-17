package scheduler

import (
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// EnvironmentAtCapacity reports whether a candidate job's environment has
// reached its concurrency limit: it counts other running jobs holding the
// SAME (canonical repository identity, environment) key and returns true
// once the limit is met or exceeded. Empty environments and non-positive
// limits impose no restriction.
//
// The repository component is the canonical RepoID (storage.RepoIDForJob,
// with the legacy URL + full-name fallback for rows persisted before RepoID
// existed), never the clone URL: repository A's production environment never
// blocks repository B's production environment, and the same repository
// submitted once via HTTPS and once via SSH resolves to ONE key. This is the
// SAME predicate the SQL store's environment reservation and
// ListJobsByEnvironment apply, so memory mode and Postgres mode decide
// identically (the parity table tests pin the agreement).
func EnvironmentAtCapacity(j model.Job, jobs map[string]model.Job) bool {
	if j.Environment == "" || j.EnvironmentConcurrency <= 0 {
		return false
	}
	repoID := storage.RepoIDForJob(j)
	active := 0
	for _, other := range jobs {
		if other.ID == j.ID || other.Environment != j.Environment || other.Status != model.StatusRunning {
			continue
		}
		if storage.RepoIDForJob(other) != repoID {
			continue
		}
		active++
		if active >= j.EnvironmentConcurrency {
			return true
		}
	}
	return false
}

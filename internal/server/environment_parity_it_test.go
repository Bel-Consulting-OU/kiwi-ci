package server

// Memory-vs-Postgres parity table for the environment concurrency decision.
//
// environmentAtCapacityScoped (memory mode) and environmentAtCapacityDB
// (Postgres mode) must return IDENTICAL decisions for identical job sets:
// the key is the CANONICAL repository identity of the checkout repository
// plus the environment name, so repo A's production never blocks repo B's
// production and HTTPS/SSH spellings of one repository share one pool.
// Legacy rows persisted before RepoID existed derive the same identity on
// both sides. Gated on KIWI_TEST_POSTGRES_URL (skipped when unset, and in
// -short mode).
//
// Each row owns a private schema (and therefore a private job set), so the
// two decision paths are compared on exactly the same inputs.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// parityEnvJob builds one job of the parity table with an explicit identity
// and its own run id.
func parityEnvJob(id, runID, repoID, repoURL, fullName, environment string, concurrency int, status model.Status) model.Job {
	return model.Job{
		ID: id, RunID: runID, Key: "deploy",
		RepoID: repoID, RepoURL: repoURL, RepoFullName: fullName,
		Environment: environment, EnvironmentConcurrency: concurrency,
		Status: status, CreatedAt: time.Now().UTC(),
	}
}

// TestEnvironmentCapacityMemoryPostgresParity runs one table of identical
// job sets through both decision paths and requires the same answer (and the
// table's expected answer) for every row.
func TestEnvironmentCapacityMemoryPostgresParity(t *testing.T) {
	ctx := context.Background()
	type parityCase struct {
		name      string
		running   []model.Job
		candidate model.Job
		want      bool
	}
	const (
		repoAid  = "github.com/parity/a"
		repoAurl = "https://github.com/parity/a.git"
		repoBid  = "github.com/parity/b"
		repoBurl = "https://github.com/parity/b.git"
		repoCid  = "github.com/parity/c"
		repoCurl = "https://github.com/parity/c.git"
	)
	cases := []parityCase{
		{
			name: "same repo and env at limit",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01", "11111111111111111111111111111101", repoAid, repoAurl, "parity/a", "prod", 1, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02", "11111111111111111111111111111102", repoAid, repoAurl, "parity/a", "prod", 1, model.StatusQueued),
			want:      true,
		},
		{
			name: "same repo and env below limit",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03", "11111111111111111111111111111103", repoAid, repoAurl, "parity/a", "prod", 2, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04", "11111111111111111111111111111104", repoAid, repoAurl, "parity/a", "prod", 2, model.StatusQueued),
			want:      false,
		},
		{
			name: "different repo same env",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa05", "11111111111111111111111111111105", repoBid, repoBurl, "parity/b", "prod", 1, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa06", "11111111111111111111111111111106", repoAid, repoAurl, "parity/a", "prod", 1, model.StatusQueued),
			want:      false,
		},
		{
			name: "different env",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa07", "11111111111111111111111111111107", repoAid, repoAurl, "parity/a", "staging", 1, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa08", "11111111111111111111111111111108", repoAid, repoAurl, "parity/a", "prod", 1, model.StatusQueued),
			want:      false,
		},
		{
			name: "running jobs of unrelated repos",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa09", "11111111111111111111111111111109", repoBid, repoBurl, "parity/b", "prod", 1, model.StatusRunning),
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa10", "11111111111111111111111111111010", repoCid, repoCurl, "parity/c", "prod", 1, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11", "11111111111111111111111111111011", repoAid, repoAurl, "parity/a", "prod", 1, model.StatusQueued),
			want:      false,
		},
		{
			name: "legacy running row without repo id",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12", "11111111111111111111111111111012", "", "git@github.com:parity/a.git", "parity/a", "prod", 1, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa13", "11111111111111111111111111111013", repoAid, repoAurl, "parity/a", "prod", 1, model.StatusQueued),
			want:      true,
		},
		{
			name: "legacy candidate without repo id",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa14", "11111111111111111111111111111014", repoAid, repoAurl, "parity/a", "prod", 1, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa15", "11111111111111111111111111111015", "", "https://github.com/parity/a", "parity/a", "prod", 1, model.StatusQueued),
			want:      true,
		},
		{
			name: "same name on another forge",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa16", "11111111111111111111111111111016", "gitlab.company.com/parity/a", "https://gitlab.company.com/parity/a.git", "parity/a", "prod", 1, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa17", "11111111111111111111111111111017", repoAid, repoAurl, "parity/a", "prod", 1, model.StatusQueued),
			want:      false,
		},
		{
			name: "no declared limit",
			running: []model.Job{
				parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa18", "11111111111111111111111111111018", repoAid, repoAurl, "parity/a", "prod", 0, model.StatusRunning),
			},
			candidate: parityEnvJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa19", "11111111111111111111111111111019", repoAid, repoAurl, "parity/a", "prod", 0, model.StatusQueued),
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := pgITServerSetup(t).open(t)

			// Memory side: the identical job set in the in-memory map.
			memJobs := map[string]model.Job{}
			for _, j := range tc.running {
				memJobs[j.ID] = j
			}
			memJobs[tc.candidate.ID] = tc.candidate

			// Postgres side: the identical job set persisted through the
			// atomic enqueue.
			for _, j := range append(append([]model.Job{}, tc.running...), tc.candidate) {
				run := model.Run{ID: j.RunID, Repo: j.RepoURL, RepoFullName: j.RepoFullName, RepoID: j.RepoID, Status: model.StatusRunning, CreatedAt: time.Now().UTC()}
				if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
					Run:  run,
					Jobs: map[string]model.Job{j.ID: j},
				}); err != nil {
					t.Fatalf("seed %s: %v", j.ID, err)
				}
			}
			// The listing must resolve the canonical identity for this case.
			if _, err := st.ListJobsByEnvironment(ctx, storage.RepoIDForJob(tc.candidate), tc.candidate.Environment); err != nil {
				t.Fatalf("ListJobsByEnvironment: %v", err)
			}

			s := &Server{DB: st}
			mem := environmentAtCapacityScoped(tc.candidate, memJobs)
			pg := s.environmentAtCapacityDB(ctx, tc.candidate)
			if mem != pg {
				t.Fatalf("memory-vs-postgres parity broken: memory=%v postgres=%v (want %v)", mem, pg, tc.want)
			}
			if mem != tc.want {
				t.Fatalf("environmentAtCapacity = %v, want %v", mem, tc.want)
			}
		})
	}
}

package storage

// Real-PostgreSQL integration tests for the RepoID-keyed scheduling identity:
// supersession and environment concurrency must fold every clone-URL spelling
// of one repository (HTTPS, ssh://, scp-like SSH) into one canonical key,
// including legacy rows that carry no stored RepoID, while same-named
// repositories on other forges never collide. Gated on
// KIWI_TEST_POSTGRES_URL (skipped when unset, and in -short mode).

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITLegacyRun builds a run payload as a control plane predating RepoID
// would have persisted it: no repo_id, only the clone URL spelling plus the
// full name.
func pgITLegacyRun(runID, repoURL, status string, group string, createdAt time.Time) model.Run {
	return model.Run{ID: runID, Repo: repoURL, RepoFullName: "kiwi-it/repo", Status: model.Status(status), ConcurrencyGroup: group, CreatedAt: createdAt}
}

// pgITLegacyJob builds a legacy job payload (no repo_id) for one run.
func pgITLegacyJob(runID, jobID, repoURL string, status model.Status) model.Job {
	return model.Job{ID: jobID, RunID: runID, Key: "build", RepoURL: repoURL, RepoFullName: "kiwi-it/repo", Status: status, CreatedAt: time.Now().UTC()}
}

// TestPostgresIntegrationSupersedeCanonicalRepoID proves the SQL supersede
// predicate keys on payload->>'repo_id' with the legacy URL derivation as
// fallback: a prior run persisted via HTTPS (legacy, no repo_id) is
// cancelled by an SSH-derived successor carrying the canonical RepoID under
// the same concurrency group, the reverse spelling pair behaves identically,
// and a same-group run of another forge with the same owner/name survives.
func TestPostgresIntegrationSupersedeCanonicalRepoID(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const httpsURL = pgITRepo
	const sshURL = "git@github.com:kiwi-it/repo.git"
	const otherForgeURL = "https://gitlab.company.com/kiwi-it/repo.git"
	const otherForgeID = "gitlab.company.com/kiwi-it/repo"

	type spellingPair struct {
		name       string
		priorURL   string
		successURL string
	}
	pairs := []spellingPair{
		{"prior-https/success-ssh", httpsURL, sshURL},
		{"prior-ssh/success-https", sshURL, httpsURL},
	}
	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			oldRun, oldJob := pgITNewID(t), pgITNewID(t)
			otherRun, otherJob := pgITNewID(t), pgITNewID(t)
			newRun, newJob := pgITNewID(t), pgITNewID(t)

			if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
				Run:  pgITLegacyRun(oldRun, pair.priorURL, "running", "deploy", time.Now().UTC()),
				Jobs: map[string]model.Job{oldJob: pgITLegacyJob(oldRun, oldJob, pair.priorURL, model.StatusQueued)},
			}); err != nil {
				t.Fatalf("seed legacy prior run: %v", err)
			}
			// Same concurrency group and same owner/name, different forge:
			// its canonical identity differs, so supersession must skip it.
			if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
				Run:  model.Run{ID: otherRun, Repo: otherForgeURL, RepoFullName: "kiwi-it/repo", RepoID: otherForgeID, Status: model.StatusRunning, ConcurrencyGroup: "deploy", CreatedAt: time.Now().UTC()},
				Jobs: map[string]model.Job{otherJob: {ID: otherJob, RunID: otherRun, Key: "build", RepoURL: otherForgeURL, RepoFullName: "kiwi-it/repo", RepoID: otherForgeID, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
			}); err != nil {
				t.Fatalf("seed other-forge run: %v", err)
			}
			// The successor carries the canonical identity even though its
			// clone URL is spelled the other way.
			if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
				Run:       model.Run{ID: newRun, Repo: pair.successURL, RepoFullName: "kiwi-it/repo", RepoID: pgITRepoID, Status: model.StatusQueued, ConcurrencyGroup: "deploy", CreatedAt: time.Now().UTC()},
				Jobs:      map[string]model.Job{newJob: {ID: newJob, RunID: newRun, Key: "build", RepoURL: pair.successURL, RepoFullName: "kiwi-it/repo", RepoID: pgITRepoID, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
				Supersede: &SupersedePolicy{RepoID: pgITRepoID, ConcurrencyGroup: "deploy"},
			}); err != nil {
				t.Fatalf("superseding enqueue: %v", err)
			}

			if old, err := st.GetJob(ctx, oldJob); err != nil || old.Status != model.StatusCancelled {
				t.Fatalf("prior job = %+v err=%v, want cancelled across spellings", old, err)
			}
			if prev, err := st.GetRun(ctx, oldRun); err != nil || prev.Status != model.StatusCancelled {
				t.Fatalf("prior run = %+v err=%v, want cancelled", prev, err)
			}
			if other, err := st.GetJob(ctx, otherJob); err != nil || other.Status != model.StatusQueued {
				t.Fatalf("other-forge job = %+v err=%v, want untouched", other, err)
			}
			if other, err := st.GetRun(ctx, otherRun); err != nil || other.Status != model.StatusRunning {
				t.Fatalf("other-forge run = %+v err=%v, want untouched", other, err)
			}
		})
	}
}

// TestPostgresIntegrationEnvironmentConcurrencyCanonicalRepoID proves the SQL
// environment reservation keys on the canonical repo id: two concurrent
// claims whose jobs spell the same repository as HTTPS and SSH can never both
// take a declared concurrency-1 slot (the legacy holder derives its identity
// in SQL), while two different repositories with the same environment name
// do not block each other.
func TestPostgresIntegrationEnvironmentConcurrencyCanonicalRepoID(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	// One repository, two spellings: legacy SSH holder + modern HTTPS job.
	runID := pgITNewID(t)
	legacyJob, modernJob := pgITNewID(t), pgITNewID(t)
	legacyRec := pgITLegacyJob(runID, legacyJob, "git@github.com:kiwi-it/repo.git", model.StatusQueued)
	legacyRec.Environment = "prod"
	legacyRec.EnvironmentConcurrency = 1
	jobs := map[string]model.Job{
		legacyJob: legacyRec,
		modernJob: {ID: modernJob, RunID: runID, Key: "deploy", RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", RepoID: pgITRepoID, Environment: "prod", EnvironmentConcurrency: 1, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, RepoID: pgITRepoID, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: jobs,
	}); err != nil {
		t.Fatal(err)
	}
	runnerA, runnerB := pgITNewID(t), pgITNewID(t)
	pgITSeedRunner(t, st, runnerA, 1, 0, 0)
	pgITSeedRunner(t, st, runnerB, 1, 0, 0)

	type claimResult struct {
		jobID string
		err   error
	}
	results := make(chan claimResult, 2)
	var wg sync.WaitGroup
	for i, jobID := range []string{legacyJob, modernJob} {
		runnerID := []string{runnerA, runnerB}[i]
		wg.Add(1)
		go func(jobID, runnerID string) {
			defer wg.Done()
			_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1, CanonRepoID: pgITRepoID, Environment: "prod", EnvironmentConcurrency: 1})
			results <- claimResult{jobID, err}
		}(jobID, runnerID)
	}
	wg.Wait()
	close(results)
	winners, rejected := 0, 0
	for r := range results {
		switch {
		case r.err == nil:
			winners++
		case errors.Is(r.err, ErrEnvConcurrency):
			rejected++
		case errors.Is(r.err, ErrLeaseConflict), errors.Is(r.err, ErrNoCapacity):
		default:
			t.Fatalf("spelling-pair env claim error = %v", r.err)
		}
	}
	if winners != 1 || rejected != 1 {
		t.Fatalf("spelling-pair env concurrency = %d winners/%d rejected, want 1/1", winners, rejected)
	}

	// Different repositories, same environment name: no shared slot. Each
	// claim uses its own canonical identity and both must win. The first
	// phase's winner releases its runner slot so the second phase starts
	// from a clean runner state.
	stored, err := st.ListJobsByRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range stored {
		if j.Status == model.StatusRunning {
			if err := st.ReleaseRunnerJob(ctx, j.LeaseRunnerID, j.ID, model.StatusFailure); err != nil {
				t.Fatalf("release %s: %v", j.ID, err)
			}
		}
	}

	otherRun := pgITNewID(t)
	githubJob, gitlabJob := pgITNewID(t), pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run: model.Run{ID: otherRun, Repo: pgITRepo, RepoID: pgITRepoID, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			githubJob: {ID: githubJob, RunID: otherRun, Key: "deploy", RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", RepoID: pgITRepoID, Environment: "staging", EnvironmentConcurrency: 1, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
			gitlabJob: {ID: gitlabJob, RunID: otherRun, Key: "deploy", RepoURL: "https://gitlab.company.com/kiwi-it/repo.git", RepoFullName: "kiwi-it/repo", RepoID: "gitlab.company.com/kiwi-it/repo", Environment: "staging", EnvironmentConcurrency: 1, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		},
	}); err != nil {
		t.Fatal(err)
	}
	githubRunner, gitlabRunner := pgITNewID(t), pgITNewID(t)
	pgITSeedRunner(t, st, githubRunner, 1, 0, 0)
	pgITSeedRunner(t, st, gitlabRunner, 1, 0, 0)
	otherResults := make(chan claimResult, 2)
	for _, tc := range []struct{ jobID, runnerID, repoID string }{
		{githubJob, githubRunner, pgITRepoID},
		{gitlabJob, gitlabRunner, "gitlab.company.com/kiwi-it/repo"},
	} {
		wg.Add(1)
		go func(tc struct{ jobID, runnerID, repoID string }) {
			defer wg.Done()
			_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: tc.jobID, RunnerID: tc.runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1, CanonRepoID: tc.repoID, Environment: "staging", EnvironmentConcurrency: 1})
			otherResults <- claimResult{tc.jobID, err}
		}(tc)
	}
	wg.Wait()
	close(otherResults)
	for r := range otherResults {
		if r.err != nil {
			t.Fatalf("same-name-other-forge env claim %s = %v, want success (no shared slot)", r.jobID, r.err)
		}
	}
}

// TestPostgresIntegrationListJobsByEnvironmentCanonicalRepoID proves the
// per-environment listing resolves legacy repo_id-less rows through the same
// URL derivation as the Go fallback: HTTPS, ssh:// and scp-like spellings of
// one repository are one set, and the same name on another forge is not.
func TestPostgresIntegrationListJobsByEnvironmentCanonicalRepoID(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	spellings := []string{
		pgITRepo,
		"https://github.com/kiwi-it/repo",
		"ssh://git@github.com/kiwi-it/repo.git",
		"git@github.com:kiwi-it/repo.git",
	}
	ids := make([]string, 0, len(spellings)+1)
	for _, sp := range spellings {
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		ids = append(ids, jobID)
		rec := pgITLegacyJob(runID, jobID, sp, model.StatusRunning)
		rec.Environment = "prod"
		if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
			Run:  pgITLegacyRun(runID, sp, "running", "", time.Now().UTC()),
			Jobs: map[string]model.Job{jobID: rec},
		}); err != nil {
			t.Fatalf("seed legacy row %s: %v", sp, err)
		}
	}
	otherRunID := pgITNewID(t)
	otherJob := pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: otherRunID, Repo: "https://gitlab.company.com/kiwi-it/repo.git", RepoFullName: "kiwi-it/repo", RepoID: "gitlab.company.com/kiwi-it/repo", Status: model.StatusRunning, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{otherJob: {ID: otherJob, RunID: otherRunID, Key: "deploy", RepoURL: "https://gitlab.company.com/kiwi-it/repo.git", RepoFullName: "kiwi-it/repo", RepoID: "gitlab.company.com/kiwi-it/repo", Environment: "prod", Status: model.StatusRunning, CreatedAt: time.Now().UTC()}},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.ListJobsByEnvironment(ctx, pgITRepoID, "prod")
	if err != nil {
		t.Fatal(err)
	}
	found := make([]string, 0, len(got))
	for _, j := range got {
		found = append(found, j.ID)
	}
	sort.Strings(found)
	sort.Strings(ids)
	if len(found) != len(ids) {
		t.Fatalf("canonical listing = %v, want %v", found, ids)
	}
	for i := range ids {
		if found[i] != ids[i] {
			t.Fatalf("canonical listing = %v, want %v", found, ids)
		}
	}
	other, err := st.ListJobsByEnvironment(ctx, "gitlab.company.com/kiwi-it/repo", "prod")
	if err != nil || len(other) != 1 || other[0].ID != otherJob {
		t.Fatalf("other-forge listing = %v err=%v, want only its own row", other, err)
	}
}

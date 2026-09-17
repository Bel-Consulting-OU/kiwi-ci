package storage

import (
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// canonicalSpellings are the clone-URL spellings of ONE repository
// (github.com/acme/api) that every identity-keyed decision must fold
// together: HTTPS with and without the .git suffix, ssh:// and scp-like SSH.
var canonicalSpellings = []struct {
	name string
	url  string
}{
	{"https", "https://github.com/acme/api.git"},
	{"https-no-git", "https://github.com/acme/api"},
	{"ssh-scheme", "ssh://git@github.com/acme/api.git"},
	{"ssh-scp", "git@github.com:acme/api.git"},
}

// TestMemStoreSupersedeCanonicalRepoIDSpellings: supersession keys on the
// CANONICAL RepoID, so a prior run submitted via one clone-URL spelling is
// cancelled by a successor submitted via another spelling of the same
// repository — in memory mode including legacy rows that carry no stored
// RepoID at all. Runs of OTHER repositories in the same concurrency group
// are never cancelled, even when they share the owner/name path on another
// forge.
func TestMemStoreSupersedeCanonicalRepoIDSpellings(t *testing.T) {
	const group = "deploy"
	const canonical = "github.com/acme/api"
	for _, prior := range canonicalSpellings {
		for _, next := range canonicalSpellings {
			t.Run("prior="+prior.name+"/next="+next.name, func(t *testing.T) {
				m := newMemStore()
				oldRunID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
				oldJobID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
				otherRunID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				otherJobID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc"
				newRunID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"
				newJobID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae"

				// Prior run: legacy row (no stored RepoID) spelled as the
				// first URL.
				if err := m.InsertCompiledRun(ctx(), InsertCompiledRunRequest{
					Run: model.Run{ID: oldRunID, Repo: prior.url, RepoFullName: "acme/api", ConcurrencyGroup: group, Status: model.StatusRunning, CreatedAt: time.Unix(1000, 0).UTC()},
					Jobs: map[string]model.Job{
						oldJobID: {ID: oldJobID, RunID: oldRunID, RepoURL: prior.url, RepoFullName: "acme/api", Status: model.StatusQueued, CreatedAt: time.Unix(1001, 0).UTC()},
					},
				}); err != nil {
					t.Fatalf("seed prior run: %v", err)
				}
				// Same concurrency group, same owner/name, DIFFERENT forge:
				// the canonical identity differs, so it must survive.
				if err := m.InsertCompiledRun(ctx(), InsertCompiledRunRequest{
					Run: model.Run{ID: otherRunID, Repo: "https://gitlab.company.com/acme/api.git", RepoFullName: "acme/api", RepoID: "gitlab.company.com/acme/api", ConcurrencyGroup: group, Status: model.StatusRunning, CreatedAt: time.Unix(1100, 0).UTC()},
					Jobs: map[string]model.Job{
						otherJobID: {ID: otherJobID, RunID: otherRunID, RepoURL: "https://gitlab.company.com/acme/api.git", RepoFullName: "acme/api", RepoID: "gitlab.company.com/acme/api", Status: model.StatusQueued, CreatedAt: time.Unix(1101, 0).UTC()},
					},
				}); err != nil {
					t.Fatalf("seed other-forge run: %v", err)
				}

				// Successor: second spelling with the canonical identity stored.
				if err := m.InsertCompiledRun(ctx(), InsertCompiledRunRequest{
					Run: model.Run{ID: newRunID, Repo: next.url, RepoFullName: "acme/api", RepoID: canonical, ConcurrencyGroup: group, Status: model.StatusQueued, CreatedAt: time.Unix(2000, 0).UTC()},
					Jobs: map[string]model.Job{
						newJobID: {ID: newJobID, RunID: newRunID, RepoURL: next.url, RepoFullName: "acme/api", RepoID: canonical, Status: model.StatusQueued, CreatedAt: time.Unix(2001, 0).UTC()},
					},
					Supersede: &SupersedePolicy{RepoID: canonical, ConcurrencyGroup: group},
				}); err != nil {
					t.Fatalf("superseding enqueue: %v", err)
				}

				if old, err := m.GetJob(ctx(), oldJobID); err != nil || old.Status != model.StatusCancelled || old.Error != "superseded by run "+newRunID {
					t.Fatalf("prior job = %+v err=%v, want cancelled by the spelling-pair successor", old, err)
				}
				if prev, err := m.GetRun(ctx(), oldRunID); err != nil || prev.Status != model.StatusCancelled {
					t.Fatalf("prior run = %+v err=%v, want cancelled", prev, err)
				}
				if other, err := m.GetJob(ctx(), otherJobID); err != nil || other.Status != model.StatusQueued {
					t.Fatalf("other-forge job = %+v err=%v, want untouched", other, err)
				}
				if other, err := m.GetRun(ctx(), otherRunID); err != nil || other.Status != model.StatusRunning {
					t.Fatalf("other-forge run = %+v err=%v, want untouched", other, err)
				}
			})
		}
	}
}

// TestMemStoreSupersedeIgnoresCloneURLPolicy: a policy keyed by a clone URL
// (the pre-RepoID contract) or an empty canonical id resolves nothing: the
// resolver compares canonical identities only.
func TestMemStoreSupersedeIgnoresCloneURLPolicy(t *testing.T) {
	m := newMemStore()
	runID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
	jobID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
	if err := m.InsertCompiledRun(ctx(), InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: "https://github.com/acme/api.git", RepoFullName: "acme/api", ConcurrencyGroup: "deploy", Status: model.StatusRunning, CreatedAt: time.Unix(1000, 0).UTC()},
		Jobs: map[string]model.Job{jobID: {ID: jobID, RunID: runID, RepoURL: "https://github.com/acme/api.git", RepoFullName: "acme/api", Status: model.StatusQueued, CreatedAt: time.Unix(1001, 0).UTC()}},
	}); err != nil {
		t.Fatal(err)
	}
	if ids := m.supersededJobIDsLocked(&SupersedePolicy{RepoID: "https://github.com/acme/api.git", ConcurrencyGroup: "deploy"}, "new"); len(ids) != 0 {
		t.Fatalf("clone-URL policy matched %v, want none", ids)
	}
	if ids := m.supersededJobIDsLocked(&SupersedePolicy{RepoID: "", ConcurrencyGroup: "deploy"}, "new"); ids != nil {
		t.Fatalf("empty policy matched %v, want nil", ids)
	}
	if ids := m.supersededJobIDsLocked(&SupersedePolicy{RepoID: "github.com/acme/api", ConcurrencyGroup: "deploy"}, "new"); len(ids) != 1 || ids[0] != jobID {
		t.Fatalf("canonical policy matched %v, want [%s]", ids, jobID)
	}
}

// TestMemStoreEnvironmentConcurrencyCanonicalRepoID: the atomic environment
// reservation keys on the canonical repository identity. A legacy holder
// (no RepoID) spelled via SSH occupies the slot for a modern HTTPS candidate,
// while an identical environment name on another repository never blocks.
func TestMemStoreEnvironmentConcurrencyCanonicalRepoID(t *testing.T) {
	const canonical = "github.com/acme/api"
	m := newMemStore()
	runID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
	holderID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
	candidateID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"
	// Legacy holder: SSH spelling, no stored RepoID, environment prod.
	if err := m.InsertCompiledRun(ctx(), InsertCompiledRunRequest{
		Run: model.Run{ID: runID, Repo: "git@github.com:acme/api.git", RepoFullName: "acme/api", Status: model.StatusRunning, CreatedAt: time.Unix(1000, 0).UTC()},
		Jobs: map[string]model.Job{
			holderID:    {ID: holderID, RunID: runID, Key: "holder", RepoURL: "git@github.com:acme/api.git", RepoFullName: "acme/api", Environment: "prod", EnvironmentConcurrency: 1, Status: model.StatusQueued, CreatedAt: time.Unix(1001, 0).UTC()},
			candidateID: {ID: candidateID, RunID: runID, Key: "candidate", RepoURL: "https://github.com/acme/api.git", RepoFullName: "acme/api", RepoID: canonical, Environment: "prod", EnvironmentConcurrency: 1, Status: model.StatusQueued, CreatedAt: time.Unix(1002, 0).UTC()},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: "runner-1", Capacity: 4}); err != nil {
		t.Fatal(err)
	}
	claim := leaseClaimFor(holderID, "runner-1", 4)
	claim.CanonRepoID = canonical
	claim.Environment = "prod"
	claim.EnvironmentConcurrency = 1
	if _, err := m.AcquireLeaseAtomic(ctx(), claim); err != nil {
		t.Fatalf("lease legacy holder: %v", err)
	}
	// The HTTPS candidate derives the same canonical identity: full.
	full := leaseClaimFor(candidateID, "runner-1", 4)
	full.CanonRepoID = canonical
	full.Environment = "prod"
	full.EnvironmentConcurrency = 1
	if _, err := m.AcquireLeaseAtomic(ctx(), full); !errors.Is(err, ErrEnvConcurrency) {
		t.Fatalf("spelling-pair env claim = %v, want ErrEnvConcurrency", err)
	}
	// Another repository with the same environment name is not blocked.
	other := leaseClaimFor(candidateID, "runner-1", 4)
	other.CanonRepoID = "gitlab.company.com/acme/api"
	other.Environment = "prod"
	other.EnvironmentConcurrency = 1
	if _, err := m.AcquireLeaseAtomic(ctx(), other); err != nil {
		t.Fatalf("other-repo env claim = %v, want success", err)
	}
}

// TestMemStoreListJobsByEnvironmentCanonicalRepoID: the per-environment
// listing folds every clone-URL spelling of one repository into one set and
// never returns same-named repositories from another forge.
func TestMemStoreListJobsByEnvironmentCanonicalRepoID(t *testing.T) {
	m := newMemStore()
	runID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
	ids := []string{}
	for i, sp := range canonicalSpellings {
		id := string(rune('a'+i)) + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		ids = append(ids, id)
		if err := m.InsertJob(ctx(), model.Job{ID: id, RunID: runID, Key: sp.name, RepoURL: sp.url, RepoFullName: "acme/api", Environment: "prod", Status: model.StatusRunning, CreatedAt: time.Unix(int64(1000+i), 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.InsertJob(ctx(), model.Job{ID: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", RunID: runID, Key: "gitlab", RepoURL: "https://gitlab.company.com/acme/api.git", RepoFullName: "acme/api", RepoID: "gitlab.company.com/acme/api", Environment: "prod", Status: model.StatusRunning, CreatedAt: time.Unix(2000, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	got, err := m.ListJobsByEnvironment(ctx(), "github.com/acme/api", "prod")
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
	if other, err := m.ListJobsByEnvironment(ctx(), "gitlab.company.com/acme/api", "prod"); err != nil || len(other) != 1 {
		t.Fatalf("other-forge listing = %v err=%v, want exactly its own row", other, err)
	}
}

package storage

// Real-PostgreSQL integration tests for the unlink revocation rule of the
// runner-ID binding (K1-A): UnlinkRunnerProfile removes the binding AND
// clears the profile-derived registration-snapshot attributes of the marked
// runner row in ONE transaction, a dangling runner-ID binding DENIES the
// claim exactly like a dangling certificate binding, and a re-link restores
// the live overlay. The certificate path is untouched: a live cert binding
// keeps applying after an unrelated runner-ID unlink. Gated on
// KIWI_TEST_POSTGRES_URL exactly like the other *_it_test.go files in this
// package.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITUnlinkClaim is the one-claim helper these tests share.
func pgITUnlinkClaim(st *PostgresStore, jobID, runnerID, repoID string, labels []string) (model.Job, error) {
	return st.AcquireLeaseAtomic(context.Background(), LeaseClaim{
		JobID: jobID, RunnerID: runnerID, CanonRepoID: repoID, RequiredLabels: labels,
		Generation: 1, ExpiresAt: time.Now().Add(time.Minute), TokenHash: []byte("h"),
	})
}

// TestIntegrationRunnerProfileUnlinkRevocationPostgres: the unlink is a
// revocation (snapshot cleared with the binding), the next claim can no
// longer use the removed profile's labels, capacity or repository ACL, a
// dangling runner-ID binding denies, and a re-link restores the profile.
func TestIntegrationRunnerProfileUnlinkRevocationPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	profileID := "revoke-" + pgITNewID(t)

	if err := st.UpsertProfile(ctx, model.RunnerProfile{
		ID: profileID, Labels: []string{"bound"}, Region: "east",
		Repositories: []string{liveProfileRepoA}, Capabilities: []string{"container"},
		MaxCapacity: 2, MaxMemory: 8 << 30, CostPerHour: 1.5, PowerWatts: 50,
	}); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	// The registration snapshot a bound registration stores: the
	// profile-derived attributes plus the marker recording their provenance.
	// The snapshot's stale label proves the bound claim resolves the LIVE
	// profile, not the snapshot.
	if err := st.UpsertRunner(ctx, model.Runner{
		ID: runnerID, Name: runnerID, ProfileID: profileID,
		Labels: []string{"stale"}, Region: "east", AllowedRepositories: []string{liveProfileRepoA},
		Capabilities: []string{"container"}, Capacity: 2,
		ResourceCapacity: model.ResourceCapacity{Memory: 8 << 30},
		CostPerHour:      1.5, PowerWatts: 50,
	}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, runnerID, profileID); err != nil {
		t.Fatalf("link: %v", err)
	}

	// Bound: the live profile admits the "bound" label and its repository.
	run1, job1 := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, run1, job1, liveProfileRepoA, []string{"bound"})
	leased, err := pgITUnlinkClaim(st, job1, runnerID, liveProfileRepoA, []string{"bound"})
	if err != nil {
		t.Fatalf("bound claim = %v, want the live runner-ID profile", err)
	}
	if leased.CostRate != 1.5 {
		t.Fatalf("frozen cost rate = %v, want the live profile's 1.5", leased.CostRate)
	}

	// The profile's memory ceiling binds at claim time: a 9 GiB job cannot
	// fit max_memory 8 GiB even though a job slot remains. The claim carries
	// the job's resource request (the scheduler copies it from the job row),
	// so the capacity check sees the 9 GiB.
	runBig, jobBig := pgITNewID(t), pgITNewID(t)
	big := pgITJob(runBig, jobBig, pgITRepo)
	big.RepoID = liveProfileRepoA
	big.MemoryRequest = 9 << 30
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(runBig, model.StatusQueued),
		Jobs: map[string]model.Job{jobBig: big},
	}); err != nil {
		t.Fatalf("enqueue big job: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{
		JobID: jobBig, RunnerID: runnerID, CanonRepoID: liveProfileRepoA, MemoryRequest: 9 << 30,
		Generation: 1, ExpiresAt: time.Now().Add(time.Minute), TokenHash: []byte("h"),
	}); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("over-capacity claim = %v, want ErrResourceCapacity (profile max_memory)", err)
	}

	// Unlink: binding AND marked snapshot row are revoked together.
	if err := st.UnlinkRunnerProfile(ctx, runnerID); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if got.ProfileID != "" || got.Labels != nil || got.Region != "" || got.AllowedRepositories != nil ||
		got.Capabilities != nil || got.Capacity != 0 || got.ResourceCapacity != (model.ResourceCapacity{}) ||
		got.CostPerHour != 0 || got.PowerWatts != 0 {
		t.Fatalf("runner after unlink = %+v, want every profile-derived field cleared", got)
	}

	// The removed profile's grants are gone at the very next claim: a
	// label-free job cannot lease a revoked (capacity 0) runner, and the
	// removed ACL does not admit the then-cleared snapshot either.
	run2, job2 := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, run2, job2, liveProfileRepoA, nil)
	if _, err := pgITUnlinkClaim(st, job2, runnerID, liveProfileRepoA, nil); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("post-unlink claim = %v, want ErrNoCapacity", err)
	}

	// A dangling runner-ID binding (binding without a profile row) denies the
	// claim instead of falling back to the snapshot.
	if err := st.LinkRunnerProfile(ctx, runnerID, "ghost-"+pgITNewID(t)); err != nil {
		t.Fatalf("link dangling: %v", err)
	}
	run3, job3 := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, run3, job3, liveProfileRepoA, nil)
	if _, err := pgITUnlinkClaim(st, job3, runnerID, liveProfileRepoA, nil); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("dangling runner-ID claim = %v, want ErrNoCapacity (fail closed)", err)
	}

	// Re-link restores the live overlay without any re-registration.
	if err := st.LinkRunnerProfile(ctx, runnerID, profileID); err != nil {
		t.Fatalf("re-link: %v", err)
	}
	if _, err := pgITUnlinkClaim(st, job3, runnerID, liveProfileRepoA, nil); err != nil {
		t.Fatalf("re-linked claim = %v, want the re-bound live profile", err)
	}
}

// TestIntegrationRunnerProfileUnlinkKeepsCertBindingPostgres: the unlink
// revokes the runner-ID binding path only. A runner whose profile comes from
// a live certificate-serial binding keeps leasing through it after its marked
// snapshot row was cleared (the cert path is decided by cert_profile_links,
// never by the runner-ID binding or the snapshot).
func TestIntegrationRunnerProfileUnlinkKeepsCertBindingPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	serial := "cert-" + pgITNewID(t)
	certProfile := "cert-p-" + pgITNewID(t)

	if err := st.UpsertProfile(ctx, model.RunnerProfile{
		ID: certProfile, Labels: []string{"cert-bound"}, Repositories: []string{liveProfileRepoA}, MaxCapacity: 2,
	}); err != nil {
		t.Fatalf("upsert cert profile: %v", err)
	}
	if err := st.BindCertProfile(ctx, serial, certProfile); err != nil {
		t.Fatalf("bind cert profile: %v", err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{
		ID: runnerID, Name: runnerID, CertSerial: serial, ProfileID: certProfile,
		Labels: []string{"cert-bound"}, AllowedRepositories: []string{liveProfileRepoA}, Capacity: 2,
	}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}

	// Unlink the runner (there is no runner-ID binding for it): the marked
	// snapshot row is cleared, but the certificate binding is untouched.
	if err := st.UnlinkRunnerProfile(ctx, runnerID); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if p, ok, err := st.ProfileForSerial(ctx, serial); err != nil || !ok || p.ID != certProfile {
		t.Fatalf("cert binding after unlink = (%+v, %v, %v), want it untouched", p, ok, err)
	}
	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if got.ProfileID != "" || got.Labels != nil || got.Capacity != 0 {
		t.Fatalf("marked snapshot after unlink = %+v, want it cleared", got)
	}

	// The live certificate binding still governs the lease: the cert
	// profile's label admits the job.
	run, job := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, run, job, liveProfileRepoA, []string{"cert-bound"})
	if _, err := pgITUnlinkClaim(st, job, runnerID, liveProfileRepoA, []string{"cert-bound"}); err != nil {
		t.Fatalf("cert-bound claim after unlink = %v, want the live certificate profile", err)
	}
}

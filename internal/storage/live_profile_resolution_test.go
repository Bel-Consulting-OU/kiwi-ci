package storage

// Lease-time live profile resolution through the ONE shared precedence: the
// certificate-serial binding when the runner presents a registered serial,
// the runner-ID binding (runner_profile_links) otherwise, and the
// registration snapshot when neither applies. These tests pin that a
// per-runner bearer identity's profile EDITS take effect on the NEXT lease
// without re-registration, that the certificate binding wins, and the
// documented dangling-binding policy (a dangling binding fails closed for
// BOTH sources: the binding governs and its profile is gone), plus the
// unlink revocation (the store clears the profile-derived snapshot fields in
// the same operation as the binding removal).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const liveProfileRepoA = "github.com/o/allowed"
const liveProfileRepoB = "github.com/o/other"

func liveProfileJob(id, key string, labels []string, repoID string) model.Job {
	return model.Job{
		ID: id, RunID: "11111111111111111111111111111111", Key: key,
		Status: model.StatusQueued, RequiredLabels: labels, RepoID: repoID,
		CreatedAt: time.Unix(1000, 0).UTC(),
	}
}

func liveProfileInsert(t *testing.T, m *memStore, job model.Job) {
	t.Helper()
	if err := m.InsertJob(context.Background(), job); err != nil {
		t.Fatalf("insert job %s: %v", job.ID, err)
	}
}

func liveProfileClaim(m *memStore, jobID, runnerID string) (model.Job, error) {
	return m.AcquireLeaseAtomic(context.Background(), LeaseClaim{
		JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"),
		Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	})
}

// TestMemLeaseRunnerIDProfileLiveEdits: a bearer-bound runner (empty
// certificate serial) leases through its LIVE runner-ID profile, and a
// profile edit (capacity, labels, repository ACL) is honored by the NEXT
// lease without re-registration.
func TestMemLeaseRunnerIDProfileLiveEdits(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runner := model.Runner{ID: "cccccccccccccccccccccccccccccc01", Capacity: 9, Labels: []string{"snapshot-label"}, CostPerHour: 9}
	if err := m.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "live-p", Labels: []string{"bound"}, Repositories: []string{liveProfileRepoA}, MaxCapacity: 1, CostPerHour: 3.5}); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runner.ID, "live-p"); err != nil {
		t.Fatal(err)
	}

	first := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01", "first", []string{"bound"}, liveProfileRepoA)
	liveProfileInsert(t, m, first)
	j, err := liveProfileClaim(m, first.ID, runner.ID)
	if err != nil {
		t.Fatalf("first lease = %v, want the live runner-ID profile", err)
	}
	if j.CostRate != 3.5 {
		t.Fatalf("frozen cost rate = %v, want 3.5 from the live profile", j.CostRate)
	}

	// The live profile's capacity (1) beats the registration snapshot (9).
	second := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02", "second", []string{"bound"}, liveProfileRepoA)
	liveProfileInsert(t, m, second)
	if _, err := liveProfileClaim(m, second.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("second lease = %v, want ErrNoCapacity (live profile capacity 1)", err)
	}

	// Edit the profile: capacity 3, label and repository ACL replaced.
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "live-p", Labels: []string{"edited"}, Repositories: []string{liveProfileRepoB}, MaxCapacity: 3}); err != nil {
		t.Fatal(err)
	}
	// The removed label no longer matches (the runner is not full: 1 < 3).
	if _, err := liveProfileClaim(m, second.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("lease after label edit = %v, want ErrNoCapacity", err)
	}
	// The old ACL is gone too.
	repos := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03", "repos", []string{"edited"}, liveProfileRepoA)
	liveProfileInsert(t, m, repos)
	if _, err := liveProfileClaim(m, repos.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("lease after ACL edit = %v, want ErrNoCapacity", err)
	}
	// The edited profile admits the next lease.
	ok := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04", "ok", []string{"edited"}, liveProfileRepoB)
	liveProfileInsert(t, m, ok)
	if _, err := liveProfileClaim(m, ok.ID, runner.ID); err != nil {
		t.Fatalf("lease after edit = %v, want the edited live profile", err)
	}
}

// TestMemLeaseCertBindingBeatsRunnerIDBinding: an explicit
// certificate-serial binding wins over the runner-ID binding, and a
// certificate serial with NO cert binding falls through to the runner-ID
// binding.
func TestMemLeaseCertBindingBeatsRunnerIDBinding(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runner := model.Runner{ID: "cccccccccccccccccccccccccccccc02", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "serial-cert"}
	if err := m.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "cert-p", Labels: []string{"cert"}, MaxCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	if err := m.BindCertProfile(ctx, "serial-cert", "cert-p"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "id-p", Labels: []string{"id"}, MaxCapacity: 5}); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runner.ID, "id-p"); err != nil {
		t.Fatal(err)
	}

	// The cert-serial profile wins: the runner-ID label does not match.
	idJob := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11", "id", []string{"id"}, "")
	liveProfileInsert(t, m, idJob)
	if _, err := liveProfileClaim(m, idJob.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("runner-ID label = %v, want ErrNoCapacity (cert binding wins)", err)
	}
	certJob := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12", "cert", []string{"cert"}, "")
	liveProfileInsert(t, m, certJob)
	if _, err := liveProfileClaim(m, certJob.ID, runner.ID); err != nil {
		t.Fatalf("cert label lease = %v", err)
	}
}

// TestMemLeaseSerialWithoutCertBindingFallsThroughToRunnerID: the
// runner presents a serial, but no cert binding exists for it, so the
// runner-ID binding applies.
func TestMemLeaseSerialWithoutCertBindingFallsThroughToRunnerID(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runner := model.Runner{ID: "cccccccccccccccccccccccccccccc03", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "serial-unbound"}
	if err := m.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "id-p", Labels: []string{"id"}, MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runner.ID, "id-p"); err != nil {
		t.Fatal(err)
	}
	job := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa13", "id", []string{"id"}, "")
	liveProfileInsert(t, m, job)
	if _, err := liveProfileClaim(m, job.ID, runner.ID); err != nil {
		t.Fatalf("serial-without-cert-binding lease = %v, want the runner-ID binding", err)
	}
}

// TestMemLeaseDanglingCertBindingDeniesEvenWithRunnerIDBinding: a
// dangling certificate-serial binding wins the precedence and fails the
// claim closed; the live runner-ID binding is NOT a fallback.
func TestMemLeaseDanglingCertBindingDeniesEvenWithRunnerIDBinding(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runner := model.Runner{ID: "cccccccccccccccccccccccccccccc04", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "serial-dangling"}
	if err := m.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	m.certProfiles["serial-dangling"] = "99999999999999999999999999999999"
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "id-p", Labels: []string{"id"}, MaxCapacity: 5}); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runner.ID, "id-p"); err != nil {
		t.Fatal(err)
	}
	job := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa14", "id", []string{"id"}, "")
	liveProfileInsert(t, m, job)
	if _, err := liveProfileClaim(m, job.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("dangling cert binding = %v, want ErrNoCapacity", err)
	}
}

// TestMemLeaseUnbindFallsBackToSnapshot: unlinking removes the live
// overlay; for an UNMARKED runner row (self-reported dev-mode attributes,
// which an unlink must not touch) the next lease uses the registration
// snapshot again. A MARKED row is revoked instead; see
// TestMemLeaseUnlinkRevokesProfileSnapshot.
func TestMemLeaseUnbindFallsBackToSnapshot(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runner := model.Runner{ID: "cccccccccccccccccccccccccccccc05", Capacity: 4, Labels: []string{"snapshot"}}
	if err := m.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "live-p", Labels: []string{"bound"}, MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runner.ID, "live-p"); err != nil {
		t.Fatal(err)
	}
	first := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa15", "first", []string{"bound"}, "")
	liveProfileInsert(t, m, first)
	if _, err := liveProfileClaim(m, first.ID, runner.ID); err != nil {
		t.Fatalf("bound lease = %v", err)
	}
	if err := m.UnlinkRunnerProfile(ctx, runner.ID); err != nil {
		t.Fatal(err)
	}
	// The profile label is gone (snapshot labels apply again) ...
	bound := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa16", "bound", []string{"bound"}, "")
	liveProfileInsert(t, m, bound)
	if _, err := liveProfileClaim(m, bound.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("post-unbind bound label = %v, want ErrNoCapacity", err)
	}
	// ... and the snapshot capacity (4) admits the next job (1 active).
	snap := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa17", "snap", []string{"snapshot"}, "")
	liveProfileInsert(t, m, snap)
	if _, err := liveProfileClaim(m, snap.ID, runner.ID); err != nil {
		t.Fatalf("post-unbind snapshot lease = %v", err)
	}
}

// TestMemLeaseDanglingRunnerIDBindingDenies: a runner-ID binding whose
// profile row is gone DENIES the lease (parity with the dangling
// certificate-serial binding): the binding governs the runner, so a deleted
// profile must not silently fall back to the registration snapshot (which may
// itself hold attributes copied from that profile).
func TestMemLeaseDanglingRunnerIDBindingDenies(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runner := model.Runner{ID: "cccccccccccccccccccccccccccccc06", Capacity: 2, Labels: []string{"snapshot"}, CostPerHour: 7, ProfileID: "ghost-p"}
	if err := m.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runner.ID, "ghost-p"); err != nil {
		t.Fatal(err)
	}
	job := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa18", "snap", []string{"snapshot"}, "")
	liveProfileInsert(t, m, job)
	if _, err := liveProfileClaim(m, job.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("dangling runner-ID binding = %v, want ErrNoCapacity (fail closed)", err)
	}
}

// TestMemLeaseUnlinkRevokesProfileSnapshot: the store's UnlinkRunnerProfile
// is revocation, not merely row deletion — it clears the profile-derived
// registration attributes of the MARKED runner row in the same operation, so
// the very next claim can neither take the removed profile's labels, nor its
// capacity, nor its repository ACL through the snapshot fallback. A re-bind
// restores the profile (live overlay), and the mTLS/certificate path is
// unaffected.
func TestMemLeaseUnlinkRevokesProfileSnapshot(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runner := model.Runner{
		ID: "cccccccccccccccccccccccccccccc07",
		// The registration snapshot as a bound registration would store it:
		// every scheduling attribute below was copied from the profile, and
		// the marker records that provenance.
		ProfileID: "revoke-p", Capacity: 4, Labels: []string{"bound"},
		AllowedRepositories: []string{liveProfileRepoA},
		Capabilities:        []string{"container"},
		ResourceCapacity:    model.ResourceCapacity{Memory: 8 << 30},
		CostPerHour:         2.5, PowerWatts: 60,
	}
	if err := m.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{
		ID: "revoke-p", Labels: []string{"bound"}, Repositories: []string{liveProfileRepoA},
		Capabilities: []string{"container"}, MaxCapacity: 4, MaxMemory: 8 << 30, CostPerHour: 2.5, PowerWatts: 60,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runner.ID, "revoke-p"); err != nil {
		t.Fatal(err)
	}

	// Bound: the snapshot already admits the profile's grants.
	first := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa21", "first", []string{"bound"}, liveProfileRepoA)
	liveProfileInsert(t, m, first)
	if _, err := liveProfileClaim(m, first.ID, runner.ID); err != nil {
		t.Fatalf("bound lease = %v", err)
	}

	if err := m.UnlinkRunnerProfile(ctx, runner.ID); err != nil {
		t.Fatal(err)
	}
	// The revocation cleared the marked snapshot row in the store itself.
	got, err := m.GetRunner(ctx, runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != "" || got.Capacity != 0 || len(got.Labels) != 0 || len(got.AllowedRepositories) != 0 ||
		len(got.Capabilities) != 0 || got.ResourceCapacity != (model.ResourceCapacity{}) || got.CostPerHour != 0 || got.PowerWatts != 0 {
		t.Fatalf("snapshot after unlink = %+v, want the profile-derived fields cleared", got)
	}
	// No lease under the removed grants: the label no longer matches, and
	// even a label-free job cannot be admitted by the revoked capacity.
	bound := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa22", "bound", []string{"bound"}, "")
	liveProfileInsert(t, m, bound)
	if _, err := liveProfileClaim(m, bound.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("post-unlink bound label = %v, want ErrNoCapacity", err)
	}
	plain := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa23", "plain", nil, "")
	liveProfileInsert(t, m, plain)
	if _, err := liveProfileClaim(m, plain.ID, runner.ID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("post-unlink revoked capacity = %v, want ErrNoCapacity", err)
	}
	// The repository ACL is gone too: even if capacity were restored by a
	// re-registration, the removed profile's ACL cannot survive the unlink.
	if got.AllowedRepositories != nil {
		t.Fatalf("removed profile's repository ACL survived unlink: %v", got.AllowedRepositories)
	}

	// Re-bind restores the profile: the live overlay applies again.
	if err := m.LinkRunnerProfile(ctx, runner.ID, "revoke-p"); err != nil {
		t.Fatal(err)
	}
	rebound := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa24", "rebound", []string{"bound"}, liveProfileRepoA)
	liveProfileInsert(t, m, rebound)
	if _, err := liveProfileClaim(m, rebound.ID, runner.ID); err != nil {
		t.Fatalf("re-bound lease = %v, want the re-bound live profile", err)
	}
}

// TestMemLeaseUnlinkKeepsRunnerDeclaredSnapshot: an UNMARKED runner row
// carries the runner's own self-reported attributes (legacy dev mode), so an
// unlink must not touch it — the documented revocation rule clears
// profile-derived grants only.
func TestMemLeaseUnlinkKeepsRunnerDeclaredSnapshot(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runner := model.Runner{ID: "cccccccccccccccccccccccccccccc08", Capacity: 4, Labels: []string{"snapshot"}}
	if err := m.UpsertRunner(ctx, runner); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "live-p", Labels: []string{"bound"}, MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runner.ID, "live-p"); err != nil {
		t.Fatal(err)
	}
	if err := m.UnlinkRunnerProfile(ctx, runner.ID); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetRunner(ctx, runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != "" || got.Capacity != 4 || len(got.Labels) != 1 || got.Labels[0] != "snapshot" {
		t.Fatalf("unmarked snapshot after unlink = %+v, want the runner's own attributes", got)
	}
	snap := liveProfileJob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa25", "snap", []string{"snapshot"}, "")
	liveProfileInsert(t, m, snap)
	if _, err := liveProfileClaim(m, snap.ID, runner.ID); err != nil {
		t.Fatalf("post-unlink snapshot lease = %v, want the runner's own snapshot", err)
	}
}

// TestResolveLiveProfileBindingPrecedence pins the shared decision directly:
// certificate-serial binding first, then the runner-ID binding, then no
// binding (the registration snapshot), including the dangling policy.
func TestResolveLiveProfileBindingPrecedence(t *testing.T) {
	cert := model.RunnerProfile{ID: "cert", MaxCapacity: 1}
	linked := model.RunnerProfile{ID: "linked", MaxCapacity: 3}

	certState := func(p model.RunnerProfile, isLinked, found bool) ProfileBindingLookup {
		return func() (model.RunnerProfile, bool, bool, error) { return p, isLinked, found, nil }
	}
	runnerState := func(p model.RunnerProfile, isLinked, found bool) ProfileBindingLookup {
		return func() (model.RunnerProfile, bool, bool, error) { return p, isLinked, found, nil }
	}
	unreachable := func() (model.RunnerProfile, bool, bool, error) {
		t.Fatal("the lookup must not be consulted")
		return model.RunnerProfile{}, false, false, nil
	}

	// Cert binding wins when the runner presents a serial.
	res, err := ResolveLiveProfileBinding("serial", certState(cert, true, true), runnerState(linked, true, true))
	if err != nil || !res.Applies() || res.Profile.ID != "cert" || res.Source != ProfileBindingCertSerial {
		t.Fatalf("cert precedence = (%+v, %v)", res, err)
	}
	// A serial with no cert binding falls through to the runner-ID binding.
	res, err = ResolveLiveProfileBinding("serial", certState(model.RunnerProfile{}, false, false), runnerState(linked, true, true))
	if err != nil || !res.Applies() || res.Profile.ID != "linked" || res.Source != ProfileBindingRunnerID {
		t.Fatalf("runner-ID fallthrough = (%+v, %v)", res, err)
	}
	// An empty/blank serial never consults the cert lookup.
	res, err = ResolveLiveProfileBinding("  ", unreachable, runnerState(linked, true, true))
	if err != nil || !res.Applies() || res.Profile.ID != "linked" {
		t.Fatalf("blank serial = (%+v, %v)", res, err)
	}
	// No binding at all: the snapshot is used.
	res, err = ResolveLiveProfileBinding("", unreachable, runnerState(model.RunnerProfile{}, false, false))
	if err != nil || res.Linked || res.Found || res.Applies() || res.Source != ProfileBindingNone {
		t.Fatalf("no binding = (%+v, %v)", res, err)
	}
	// A dangling cert binding wins and denies; the runner-ID binding is NOT
	// a fallback.
	res, err = ResolveLiveProfileBinding("serial", certState(model.RunnerProfile{}, true, false), runnerState(linked, true, true))
	if err != nil || !res.DeniesLease() || res.Source != ProfileBindingCertSerial || res.Applies() {
		t.Fatalf("dangling cert = (%+v, %v)", res, err)
	}
	// A dangling runner-ID binding also resolves as linked+missing and
	// DENIES the lease: the binding governs, so the snapshot is not a
	// fallback (parity with the dangling certificate binding).
	res, err = ResolveLiveProfileBinding("", unreachable, runnerState(model.RunnerProfile{}, true, false))
	if err != nil || !res.DeniesLease() || res.Applies() || res.Source != ProfileBindingRunnerID {
		t.Fatalf("dangling runner-ID = (%+v, %v)", res, err)
	}
	// Lookup errors propagate.
	wantErr := errors.New("profile read down")
	if _, err := ResolveLiveProfileBinding("serial", func() (model.RunnerProfile, bool, bool, error) { return model.RunnerProfile{}, false, false, wantErr }, runnerState(linked, true, true)); !errors.Is(err, wantErr) {
		t.Fatalf("cert lookup error = %v", err)
	}
	if _, err := ResolveLiveProfileBinding("", unreachable, func() (model.RunnerProfile, bool, bool, error) { return model.RunnerProfile{}, false, false, wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("runner-ID lookup error = %v", err)
	}
}

// TestMemStoreResolveLiveRunnerProfileParity: the LiveProfileResolver surface
// the scheduler prefilter and the queue explainers consume answers exactly
// like the mem claim (same shared helper, same maps).
func TestMemStoreResolveLiveRunnerProfileParity(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "live-p", MaxCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "cert-p", MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := m.BindCertProfile(ctx, "serial-1", "cert-p"); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, "runner-1", "live-p"); err != nil {
		t.Fatal(err)
	}

	// Cert binding wins for a runner presenting a serial.
	res, err := m.ResolveLiveRunnerProfile(ctx, "runner-1", "serial-1")
	if err != nil || res.Profile.ID != "cert-p" || res.Source != ProfileBindingCertSerial {
		t.Fatalf("cert resolution = (%+v, %v)", res, err)
	}
	// No cert binding: the runner-ID binding applies.
	res, err = m.ResolveLiveRunnerProfile(ctx, "runner-1", "serial-unbound")
	if err != nil || res.Profile.ID != "live-p" || res.Source != ProfileBindingRunnerID {
		t.Fatalf("runner-ID resolution = (%+v, %v)", res, err)
	}
	// Dangling cert binding denies even with a live runner-ID binding.
	m.certProfiles["serial-dangling"] = "99999999999999999999999999999999"
	res, err = m.ResolveLiveRunnerProfile(ctx, "runner-1", "serial-dangling")
	if err != nil || !res.DeniesLease() {
		t.Fatalf("dangling cert resolution = (%+v, %v)", res, err)
	}
	// Dangling runner-ID binding: linked but missing, so the lease denies
	// (parity with the dangling certificate binding).
	m.runnerProfiles["runner-2"] = "99999999999999999999999999999999"
	res, err = m.ResolveLiveRunnerProfile(ctx, "runner-2", "")
	if err != nil || !res.DeniesLease() || res.Applies() || res.Source != ProfileBindingRunnerID {
		t.Fatalf("dangling runner-ID resolution = (%+v, %v)", res, err)
	}
	// Unbound runner: no binding.
	res, err = m.ResolveLiveRunnerProfile(ctx, "runner-3", "")
	if err != nil || res.Linked || res.Source != ProfileBindingNone {
		t.Fatalf("unbound resolution = (%+v, %v)", res, err)
	}
}

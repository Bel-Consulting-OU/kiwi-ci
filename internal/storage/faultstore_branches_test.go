package storage

import (
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestMemStoreUpdateDeploymentStatusNilFinishedKeepsValue(t *testing.T) {
	if err := (&memStore{}).AdjustQuotaCounter(ctx(), "", "", 0, 0); err != nil {
		t.Fatalf("empty quota adjust: %v", err)
	}
}

func TestMemStoreEnqueueValidationBranches(t *testing.T) {
	m := newMemStore()
	if err := m.InsertCompiledRun(ctx(), InsertCompiledRunRequest{Run: model.Run{ID: ""}}); err == nil {
		t.Fatal("empty run id must fail")
	}
	req := InsertCompiledRunRequest{Run: testRun, DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: "no-separators", StableChildID: memDigest}}
	if err := m.InsertCompiledRun(ctx(), req); err == nil {
		t.Fatal("malformed downstream link key must fail")
	}
	req = InsertCompiledRunRequest{Run: testRun, DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: testJob.ID + "\x00acme/child\x00main", StableChildID: "short"}}
	if err := m.InsertCompiledRun(ctx(), req); err == nil {
		t.Fatal("malformed stable child id must fail")
	}
	req = InsertCompiledRunRequest{Run: testRun, DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: testJob.ID + "\x00acme/missing\x00main", StableChildID: memDigest}}
	if err := m.InsertCompiledRun(ctx(), req); err == nil {
		t.Fatal("missing claim link must fail")
	}
	linkKey := testJob.ID + "\x00acme/child\x00main"
	if err := m.InsertDownstreamLink(ctx(), DownstreamLink{ParentJobID: testJob.ID, TargetRepo: "acme/child", TargetRef: "main"}); err != nil {
		t.Fatalf("insert link: %v", err)
	}
	// A link already launched for a DIFFERENT run fails closed.
	l := m.downstream[linkKey]
	l.ChildRunID = testRun.ID
	m.downstream[linkKey] = l
	req = InsertCompiledRunRequest{Run: testRun, DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: memDigest}}
	if err := m.InsertCompiledRun(ctx(), req); err == nil {
		t.Fatal("lost claim must fail")
	}
	// A link launched for the SAME run returns the duplicate sentinel so the
	// caller re-reads the existing child.
	l = m.downstream[linkKey]
	l.ChildRunID = testRun.ID
	m.downstream[linkKey] = l
	req = InsertCompiledRunRequest{Run: testRun, Jobs: map[string]model.Job{}, DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: memDigest}}
	if err := m.InsertCompiledRun(ctx(), req); !errors.Is(err, ErrDownstreamLaunched) {
		t.Fatalf("same-run claim = %v, want ErrDownstreamLaunched", err)
	}
}

func TestMemStoreEnqueueDuplicateAndContractBranches(t *testing.T) {
	m := newMemStore()
	if err := m.InsertRun(ctx(), testRun); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	err := m.InsertCompiledRun(ctx(), InsertCompiledRunRequest{
		Run:  testRun,
		Jobs: map[string]model.Job{},
	})
	if err == nil {
		t.Fatal("duplicate run must fail")
	}
	m2 := newMemStore()
	if err := m2.InsertJob(ctx(), testJob); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	err = m2.InsertCompiledRun(ctx(), InsertCompiledRunRequest{
		Run:  model.Run{ID: memRunID, Status: model.StatusQueued},
		Jobs: map[string]model.Job{testJob.ID: testJob},
	})
	if err == nil {
		t.Fatal("duplicate job must fail")
	}
	// A negative job count clamps to zero and a contract map lands with the
	// job rows.
	m3 := newMemStore()
	req := InsertCompiledRunRequest{
		Run:       testRun,
		Jobs:      map[string]model.Job{testJob.ID: testJob},
		Contracts: map[string]map[string]ArtifactContract{testJob.ID: testContracts},
		Quota:     &QuotaReservation{RepoKey: "github.com/o/r", JobCount: -5},
	}
	if err := m3.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatalf("enqueue with negative quota: %v", err)
	}
	contracts, ok, err := m3.GetJobContracts(ctx(), testJob.ID)
	if err != nil || !ok || contracts["bundle"].Name != "bundle" {
		t.Fatalf("enqueued contracts = %+v, %v, %v", contracts, ok, err)
	}
	running, queued, err := m3.QuotaCounts(ctx(), "github.com/o/r", "")
	if err != nil || running != 0 || queued != 0 {
		t.Fatalf("negative job count clamped to 0: %d, %d, %v", running, queued, err)
	}
}

func TestMemStoreEnqueueCancelAndFaultBranches(t *testing.T) {
	// A duplicate cancel ID is staged only once and a missing or terminal
	// job is skipped.
	m := newMemStore()
	terminal := testJob
	terminal.ID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	terminal.Key = "done"
	terminal.Status = model.StatusSuccess
	if err := m.InsertJob(ctx(), terminal); err != nil {
		t.Fatalf("seed terminal job: %v", err)
	}
	queued := testJob
	queued.ID = "ffffffffffffffffffffffffffffffff"
	queued.Key = "queued"
	if err := m.InsertJob(ctx(), queued); err != nil {
		t.Fatalf("seed queued job: %v", err)
	}
	req := InsertCompiledRunRequest{
		Run:            model.Run{ID: memRunID, Status: model.StatusQueued},
		Jobs:           map[string]model.Job{},
		CancelPrevious: []string{queued.ID, queued.ID, terminal.ID, "99999999999999999999999999999999"},
	}
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	got, _ := m.GetJob(ctx(), queued.ID)
	if got.Status != model.StatusCancelled {
		t.Fatalf("queued job not cancelled: %+v", got)
	}
	// The supersede resolver ignores an empty repo or group.
	if ids := m.supersededJobIDsLocked(&SupersedePolicy{Repo: "", ConcurrencyGroup: "g"}, memRunID); ids != nil {
		t.Fatalf("empty repo supersede = %v", ids)
	}
	if ids := m.supersededJobIDsLocked(&SupersedePolicy{Repo: "r", ConcurrencyGroup: ""}, memRunID); ids != nil {
		t.Fatalf("empty group supersede = %v", ids)
	}
	// A supersede policy with no matching runs yields nothing.
	if ids := m.supersededJobIDsLocked(&SupersedePolicy{Repo: "github.com/o/r", ConcurrencyGroup: "deploy"}, memRunID); len(ids) != 0 {
		t.Fatalf("unmatched supersede = %v", ids)
	}

	// The mid-enqueue fault hook defaults its message when no error was set.
	m2 := newMemStore()
	m2.enqueueFaultOps = 1
	m2.enqueueFaultErr = nil
	err := m2.InsertCompiledRun(ctx(), InsertCompiledRunRequest{Run: testRun, Jobs: map[string]model.Job{testJob.ID: testJob}})
	if err == nil || err.Error() != "storage: injected enqueue failure" {
		t.Fatalf("default enqueue fault = %v", err)
	}
	if m2.enqueueFaultOps != 0 || m2.enqueueFaultErr != nil {
		t.Fatal("one-shot enqueue fault hook was not cleared")
	}
}

func TestMemStoreRecomputeDependentsWaitsForPendingNeeds(t *testing.T) {
	m := newMemStore()
	cancelled := testJob
	cancelled.ID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	cancelled.Key = "cancelled"
	cancelled.Status = model.StatusRunning
	running := testJob
	running.ID = "ffffffffffffffffffffffffffffffff"
	running.Key = "running"
	running.Status = model.StatusRunning
	waiting := testJob
	waiting.ID = "12121212121212121212121212121212"
	waiting.Key = "waiting"
	waiting.Status = model.StatusQueued
	waiting.Needs = []string{cancelled.ID, running.ID}
	for _, j := range []model.Job{cancelled, running, waiting} {
		if err := m.InsertJob(ctx(), j); err != nil {
			t.Fatalf("seed job: %v", err)
		}
	}
	// The dependent still has a non-terminal need, so it is left untouched.
	m.recomputeDependentsLocked(map[string]bool{cancelled.ID: true}, time.Now().UTC())
	got, _ := m.GetJob(ctx(), waiting.ID)
	if got.Status != model.StatusQueued {
		t.Fatalf("dependent with pending need must not move: %+v", got)
	}
	// Once every need is terminal the outcome blocks the conditionless
	// dependent (cancelled dependency). The cancelled job's stored row is
	// the same transition the enqueue commits before recomputing.
	blocked := cancelled
	blocked.Status = model.StatusCancelled
	if err := m.UpdateJob(ctx(), blocked); err != nil {
		t.Fatalf("update cancelled: %v", err)
	}
	done := running
	done.Status = model.StatusSuccess
	if err := m.UpdateJob(ctx(), done); err != nil {
		t.Fatalf("update running: %v", err)
	}
	m.recomputeDependentsLocked(map[string]bool{cancelled.ID: true}, time.Now().UTC())
	got, _ = m.GetJob(ctx(), waiting.ID)
	if got.Status != model.StatusBlocked || got.DependencyStatus != model.StatusCancelled {
		t.Fatalf("dependent after outcome = %+v", got)
	}
}

func TestMemStoreResolveProfileLocked(t *testing.T) {
	m := newMemStore()
	r := testRunner
	r.CertSerial = "serial-unlinked"
	if _, linked, found := m.resolveProfileLocked(r); linked || found {
		t.Fatal("unlinked serial must report unlinked")
	}
	r.CertSerial = ""
	if _, linked, found := m.resolveProfileLocked(r); linked || found {
		t.Fatal("empty serial must report unlinked")
	}
	// A dangling link reports linked but not found (fail closed).
	m.certProfiles["serial-dangling"] = "99999999999999999999999999999999"
	r.CertSerial = "serial-dangling"
	if _, linked, found := m.resolveProfileLocked(r); !linked || found {
		t.Fatal("dangling link must report linked+missing")
	}
}

func TestMemStoreAcquireLeaseAtomicMissingRunnerAndDanglingProfile(t *testing.T) {
	m := newMemStore()
	if err := m.InsertJob(ctx(), testJob); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), LeaseClaim{JobID: testJob.ID, RunnerID: testRunner.ID}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("missing runner = %v, want ErrNoCapacity", err)
	}
	// A runner linked to a missing profile is denied the lease.
	linked := testRunner
	linked.CertSerial = "serial-dangling"
	m.certProfiles["serial-dangling"] = "99999999999999999999999999999999"
	if err := m.UpsertRunner(ctx(), linked); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), LeaseClaim{JobID: testJob.ID, RunnerID: testRunner.ID}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("dangling profile = %v, want ErrNoCapacity", err)
	}
}

func TestMemStoreReleaseRunnerSlotPromotesNextJob(t *testing.T) {
	m := newMemStore()
	other := testJob
	other.ID = "ffffffffffffffffffffffffffffffff"
	other.Key = "other"
	other.RunID = memRunID2
	other.Status = model.StatusRunning
	other.LeaseRunnerID = testRunner.ID
	running := testJob
	running.Status = model.StatusRunning
	running.LeaseRunnerID = testRunner.ID
	if err := m.UpsertRunner(ctx(), model.Runner{ID: testRunner.ID, Capacity: 3, ActiveJobs: []string{testJob.ID, other.ID}, CurrentJob: testJob.ID}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	for _, j := range []model.Job{running, other} {
		if err := m.InsertJob(ctx(), j); err != nil {
			t.Fatalf("seed job: %v", err)
		}
	}
	if err := m.InsertRun(ctx(), testRun); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if _, err := m.CancelRunJobs(ctx(), testRun.ID, "fault test"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	got, _ := m.GetRunner(ctx(), testRunner.ID)
	if got.CurrentJob != other.ID || len(got.ActiveJobs) != 1 {
		t.Fatalf("runner after cancel = %+v", got)
	}
	// A missing runner row is tolerated by the slot release helper.
	m.releaseRunnerSlotLocked("99999999999999999999999999999999", testJob.ID)
}

func TestMemStoreFragmentValidationBranches(t *testing.T) {
	m := newMemStore()
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), GeneratedFragmentRequest{ParentJobID: testJob.ID}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing parent = %v", err)
	}
	if err := m.InsertJob(ctx(), testJob); err != nil {
		t.Fatalf("seed parent: %v", err)
	}
	// A non-canonical job key fails closed.
	req := GeneratedFragmentRequest{
		ParentJobID: testJob.ID,
		Jobs:        map[string]model.Job{"not-an-id": {ID: "not-an-id"}},
	}
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), req, nil); err == nil {
		t.Fatal("invalid fragment job id must fail")
	}
	// A map key that disagrees with the job's own ID fails closed.
	req = GeneratedFragmentRequest{
		ParentJobID: testJob.ID,
		Jobs:        map[string]model.Job{memJobID: {ID: memJobID2}},
	}
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), req, nil); err == nil {
		t.Fatal("mismatched fragment job key must fail")
	}
	// Contracts must reference a job of the fragment.
	req = GeneratedFragmentRequest{
		ParentJobID: testJob.ID,
		Jobs:        map[string]model.Job{memJobID: {ID: memJobID}},
		Contracts:   map[string]map[string]ArtifactContract{memJobID2: testContracts},
	}
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), req, nil); err == nil {
		t.Fatal("unknown contract job must fail")
	}
	req = GeneratedFragmentRequest{
		ParentJobID: testJob.ID,
		Jobs:        map[string]model.Job{memJobID: {ID: memJobID}},
		Contracts:   map[string]map[string]ArtifactContract{"bad": {}},
	}
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), req, nil); err == nil {
		t.Fatal("invalid contract job id must fail")
	}
}

func TestMemStoreCacheManifestAndConsumeValidation(t *testing.T) {
	m := newMemStore()
	if _, ok, err := m.GetCacheManifest(ctx(), "repo", "td", "key"); err != nil || ok {
		t.Fatalf("missing manifest = %v, %v", ok, err)
	}
	rec := CacheManifestRecord{Repo: "github.com/o/r", TrustDomain: "td", LogicalKey: "l1", BlobSHA256: "sha"}
	if err := m.PutCacheManifest(ctx(), rec); err != nil {
		t.Fatalf("PutCacheManifest: %v", err)
	}
	got, ok, err := m.GetCacheManifest(ctx(), "github.com/o/r", "td", "l1")
	if err != nil || !ok || got.BlobSHA256 != "sha" || got.CreatedAt.IsZero() {
		t.Fatalf("GetCacheManifest = %+v, %v, %v", got, ok, err)
	}
	explicit := time.Unix(1000, 0).UTC()
	rec.CreatedAt = explicit
	if err := m.PutCacheManifest(ctx(), rec); err != nil {
		t.Fatalf("PutCacheManifest explicit: %v", err)
	}
	if got, _, _ = m.GetCacheManifest(ctx(), "github.com/o/r", "td", "l1"); !got.CreatedAt.Equal(explicit) {
		t.Fatalf("explicit CreatedAt lost: %v", got.CreatedAt)
	}

	// Consume validates its key before touching state.
	if err := m.ConsumePendingSidecar(ctx(), "bad", "bin", ArtifactSidecarKindSBOM, memDigest); err == nil {
		t.Fatal("invalid job id must fail")
	}
	if err := m.ConsumePendingSidecar(ctx(), memJobID, "bin", "pbom", memDigest); err == nil {
		t.Fatal("invalid kind must fail")
	}
	if err := m.ConsumePendingSidecar(ctx(), memJobID, "bin", ArtifactSidecarKindSBOM, "short"); err == nil {
		t.Fatal("invalid digest must fail")
	}
	if _, _, err := m.PendingSidecar(ctx(), "bad", "bin", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("PendingSidecar must validate its key")
	}
	if err := m.RememberPendingSidecar(ctx(), memJobID, "bin", "pbom", memDigest); err == nil {
		t.Fatal("RememberPendingSidecar must validate its kind")
	}
}

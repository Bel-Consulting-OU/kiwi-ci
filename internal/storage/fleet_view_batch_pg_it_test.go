package storage

// K4-A PostgreSQL parity: the batched fleet view must return EXACTLY the
// per-runner reads on a real database, across every binding shape
// (certificate-serial binding, runner-ID binding, fall-through, both dangling
// cases, unbound) and for the reservation ledger folded with GROUP BY
// runner_id versus the per-runner SUM. Gated on KIWI_TEST_POSTGRES_URL like
// every *_it_test.go here.

import (
	"context"
	"reflect"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestIntegrationFleetRunnerViewBatchParityPostgres pins
// FleetRunnerProfileBindings against ResolveLiveRunnerProfile for every
// binding shape, and RunnerReservationSums against RunnerReservedResources
// (the GROUP BY fold against the per-runner SUM).
func TestIntegrationFleetRunnerViewBatchParityPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	profCert, profLink := pgITNewID(t), pgITNewID(t)
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profCert, Labels: []string{"cert"}, Region: "eu", MaxCapacity: 3, MaxCPU: 1.5, MaxMemory: 1 << 30}); err != nil {
		t.Fatalf("upsert cert profile: %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profLink, Labels: []string{"link"}, Region: "us", MaxCapacity: 4, MaxMemory: 2 << 30}); err != nil {
		t.Fatalf("upsert link profile: %v", err)
	}
	if err := st.BindCertProfile(ctx, "it-batch-serial-cert", profCert); err != nil {
		t.Fatalf("bind cert profile: %v", err)
	}
	// Dangling bindings: the bound profile row does not exist.
	if err := st.BindCertProfile(ctx, "it-batch-serial-dangle", "it-batch-prof-gone"); err != nil {
		t.Fatalf("bind dangling cert profile: %v", err)
	}

	certRunner, linkRunner, fallthroughRunner := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	dangleCertRunner, dangleLinkRunner, plainRunner := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	if err := st.LinkRunnerProfile(ctx, linkRunner, profLink); err != nil {
		t.Fatalf("link runner: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, fallthroughRunner, profLink); err != nil {
		t.Fatalf("link fall-through runner: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, dangleCertRunner, profLink); err != nil {
		t.Fatalf("link dangling-cert runner: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, dangleLinkRunner, "it-batch-prof-gone"); err != nil {
		t.Fatalf("link dangling runner: %v", err)
	}

	runners := []model.Runner{
		{ID: certRunner, Name: "cert", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "it-batch-serial-cert"},
		{ID: linkRunner, Name: "link", Capacity: 9, Labels: []string{"snapshot"}},
		{ID: fallthroughRunner, Name: "fallthrough", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "it-batch-serial-unbound"},
		{ID: dangleCertRunner, Name: "dangle-cert", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "it-batch-serial-dangle"},
		{ID: dangleLinkRunner, Name: "dangle-link", Capacity: 9, Labels: []string{"snapshot"}},
		{ID: plainRunner, Name: "plain", Capacity: 7, Labels: []string{"plain"}, Region: "snap-region"},
	}
	for _, r := range runners {
		if err := st.UpsertRunner(ctx, r); err != nil {
			t.Fatalf("upsert runner %s: %v", r.Name, err)
		}
	}

	batch, err := st.FleetRunnerProfileBindings(ctx)
	if err != nil {
		t.Fatalf("FleetRunnerProfileBindings: %v", err)
	}
	if len(batch) != len(runners) {
		t.Fatalf("batched bindings = %d runners, want %d", len(batch), len(runners))
	}
	for _, r := range runners {
		binding, ok := batch[r.ID]
		if !ok {
			t.Fatalf("runner %s missing from the batched bindings", r.Name)
		}
		got := binding.Resolve(r.CertSerial)
		want, err := st.ResolveLiveRunnerProfile(ctx, r.ID, r.CertSerial)
		if err != nil {
			t.Fatalf("ResolveLiveRunnerProfile(%s): %v", r.Name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("runner %s: batched resolution = %+v, want per-runner %+v", r.Name, got, want)
		}
	}
	// Precedence pins.
	if res := batch[certRunner].Resolve("it-batch-serial-cert"); res.Source != ProfileBindingCertSerial || res.Profile.ID != profCert {
		t.Fatalf("cert-bound resolution = %+v, want the cert profile to win", res)
	}
	if res := batch[fallthroughRunner].Resolve("it-batch-serial-unbound"); res.Source != ProfileBindingRunnerID || res.Profile.ID != profLink {
		t.Fatalf("fall-through resolution = %+v, want the runner-ID profile to apply", res)
	}
	if res := batch[dangleCertRunner].Resolve("it-batch-serial-dangle"); !res.DeniesLease() {
		t.Fatalf("dangling cert resolution = %+v, want DeniesLease", res)
	}
	if res := batch[dangleLinkRunner].Resolve(""); !res.DeniesLease() {
		t.Fatalf("dangling runner-ID resolution = %+v, want DeniesLease", res)
	}
	if res := batch[plainRunner].Resolve(""); res.Source != ProfileBindingNone || res.Applies() {
		t.Fatalf("unbound resolution = %+v, want the registration snapshot", res)
	}

	// Reservation sums: two runners with live claims (the same profile, two
	// serials), one runner idle.
	resSerialA, resSerialB := "it-batch-res-serial-a", "it-batch-res-serial-b"
	profRes := pgITNewID(t)
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profRes, MaxCapacity: 8, MaxCPU: 4, MaxMemory: 8 << 30}); err != nil {
		t.Fatalf("upsert reservation profile: %v", err)
	}
	if err := st.BindCertProfile(ctx, resSerialA, profRes); err != nil {
		t.Fatalf("bind reservation serial a: %v", err)
	}
	if err := st.BindCertProfile(ctx, resSerialB, profRes); err != nil {
		t.Fatalf("bind reservation serial b: %v", err)
	}
	resRunnerA, resRunnerB := pgITNewID(t), pgITNewID(t)
	for id, serial := range map[string]string{resRunnerA: resSerialA, resRunnerB: resSerialB} {
		if err := st.UpsertRunner(ctx, model.Runner{ID: id, Name: id, Capacity: 8, CertSerial: serial}); err != nil {
			t.Fatalf("upsert reservation runner %s: %v", id, err)
		}
	}
	runID := pgITNewID(t)
	requestA := model.ResourceCapacity{CPU: 1, Memory: 1 << 30}
	requestB := model.ResourceCapacity{CPU: 0.5, Memory: 512 << 20}
	jobA, jobB := pgITNewID(t), pgITNewID(t)
	pgITResourceEnqueue(t, st, runID, jobA, pgITRepo, requestA)
	if err := st.InsertJob(ctx, pgITResourceJob(runID, jobB, pgITRepo, requestB)); err != nil {
		t.Fatalf("insert second reservation job: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(jobA, resRunnerA, requestA)); err != nil {
		t.Fatalf("lease job A: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(jobB, resRunnerB, requestB)); err != nil {
		t.Fatalf("lease job B: %v", err)
	}

	sums, err := st.RunnerReservationSums(ctx)
	if err != nil {
		t.Fatalf("RunnerReservationSums: %v", err)
	}
	for _, id := range []string{resRunnerA, resRunnerB, plainRunner} {
		want, err := st.RunnerReservedResources(ctx, id)
		if err != nil {
			t.Fatalf("RunnerReservedResources(%s): %v", id, err)
		}
		if got := sums[id]; got != want {
			t.Fatalf("runner %s: batched sum = %+v, want per-runner %+v", id, got, want)
		}
	}
	if sums[resRunnerA] != requestA {
		t.Fatalf("runner A batched sum = %+v, want %+v", sums[resRunnerA], requestA)
	}
	if sums[resRunnerB] != requestB {
		t.Fatalf("runner B batched sum = %+v, want %+v", sums[resRunnerB], requestB)
	}
	if sums[plainRunner] != (model.ResourceCapacity{}) {
		t.Fatalf("idle runner batched sum = %+v, want zero", sums[plainRunner])
	}
}

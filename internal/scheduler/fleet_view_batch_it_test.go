package scheduler

// K4-A PostgreSQL batch parity for the scheduler entry points: a real live
// database, the batched EffectiveRunnerBatch must equal EffectiveRunner for
// every runner across the binding precedence (cert binding, runner-ID
// binding, dangling sources, unbound snapshot) and ReservedResourcesBatch must
// equal the per-runner SUM after real leases. Gated on KIWI_TEST_POSTGRES_URL
// via the shared pgITSched* helpers.

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestIntegrationFleetViewBatchSchedulerPostgres(t *testing.T) {
	st := pgITSchedStore(t)
	sched := pgITSchedLeader(t, st)
	ctx := context.Background()

	profCert, profLink := pgITSchedID(t), pgITSchedID(t)
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profCert, Labels: []string{"cert"}, Region: "eu", MaxCapacity: 3, MaxCPU: 1.5}); err != nil {
		t.Fatalf("upsert cert profile: %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profLink, Labels: []string{"link"}, Region: "us", MaxCapacity: 4, MaxMemory: 2 << 30}); err != nil {
		t.Fatalf("upsert link profile: %v", err)
	}
	if err := st.BindCertProfile(ctx, "sched-batch-serial-dangle", "sched-batch-prof-gone"); err != nil {
		t.Fatalf("bind dangling cert profile: %v", err)
	}

	certRunner, linkRunner, fallthroughRunner := pgITSchedID(t), pgITSchedID(t), pgITSchedID(t)
	dangleCertRunner, dangleLinkRunner, plainRunner := pgITSchedID(t), pgITSchedID(t), pgITSchedID(t)
	if err := st.BindCertProfile(ctx, "sched-batch-serial-cert", profCert); err != nil {
		t.Fatalf("bind cert profile: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, linkRunner, profLink); err != nil {
		t.Fatalf("link runner: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, fallthroughRunner, profLink); err != nil {
		t.Fatalf("link fall-through runner: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, dangleCertRunner, profLink); err != nil {
		t.Fatalf("link dangling-cert runner: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, dangleLinkRunner, "sched-batch-prof-gone"); err != nil {
		t.Fatalf("link dangling runner: %v", err)
	}

	runners := []model.Runner{
		{ID: certRunner, Name: "cert", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "sched-batch-serial-cert"},
		{ID: linkRunner, Name: "link", Capacity: 9, Labels: []string{"snapshot"}},
		{ID: fallthroughRunner, Name: "fallthrough", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "sched-batch-serial-unbound"},
		{ID: dangleCertRunner, Name: "dangle-cert", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "sched-batch-serial-dangle"},
		{ID: dangleLinkRunner, Name: "dangle-link", Capacity: 9, Labels: []string{"snapshot"}},
		{ID: plainRunner, Name: "plain", Capacity: 7, Labels: []string{"plain"}, Region: "snap-region", CostPerHour: 1.25},
	}
	for _, r := range runners {
		if err := st.UpsertRunner(ctx, r); err != nil {
			t.Fatalf("upsert runner %s: %v", r.Name, err)
		}
	}

	batch, ok := sched.EffectiveRunnerBatch(ctx, runners)
	if !ok {
		t.Fatal("EffectiveRunnerBatch reported no batch contract")
	}
	if len(batch) != len(runners) {
		t.Fatalf("batched effective views = %d, want %d", len(batch), len(runners))
	}
	for _, r := range runners {
		got, present := batch[r.ID]
		if !present {
			t.Fatalf("runner %s missing from the batched effective views", r.Name)
		}
		want := sched.EffectiveRunner(ctx, r)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("runner %s: batched view = %+v, want per-runner %+v", r.Name, got, want)
		}
	}
	// Precedence pins.
	if v := batch[certRunner]; v.Capacity != 3 || !reflect.DeepEqual(v.Labels, []string{"cert"}) || v.Region != "eu" {
		t.Fatalf("cert-bound view = %+v, want the cert profile overlay", v)
	}
	if v := batch[linkRunner]; v.Capacity != 4 || !reflect.DeepEqual(v.Labels, []string{"link"}) || v.Region != "us" {
		t.Fatalf("runner-ID-bound view = %+v, want the runner-ID profile overlay", v)
	}
	if v := batch[fallthroughRunner]; v.Capacity != 4 || !reflect.DeepEqual(v.Labels, []string{"link"}) {
		t.Fatalf("fall-through view = %+v, want the runner-ID profile overlay", v)
	}
	if v := batch[dangleCertRunner]; v.Capacity != 0 {
		t.Fatalf("dangling cert view = %+v, want zero capacity", v)
	}
	if v := batch[dangleLinkRunner]; v.Capacity != 0 {
		t.Fatalf("dangling runner-ID view = %+v, want zero capacity", v)
	}
	if v := batch[plainRunner]; v.Capacity != 7 || !reflect.DeepEqual(v.Labels, []string{"plain"}) {
		t.Fatalf("unbound view = %+v, want the registration snapshot", v)
	}

	// Reservation sums after real leases: two runners with live claims.
	resProf := pgITSchedID(t)
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: resProf, MaxCapacity: 8, MaxCPU: 4, MaxMemory: 8 << 30}); err != nil {
		t.Fatalf("upsert reservation profile: %v", err)
	}
	resSerialA, resSerialB := "sched-batch-res-a", "sched-batch-res-b"
	if err := st.BindCertProfile(ctx, resSerialA, resProf); err != nil {
		t.Fatalf("bind reservation serial a: %v", err)
	}
	if err := st.BindCertProfile(ctx, resSerialB, resProf); err != nil {
		t.Fatalf("bind reservation serial b: %v", err)
	}
	resRunnerA, resRunnerB := pgITSchedID(t), pgITSchedID(t)
	for id, serial := range map[string]string{resRunnerA: resSerialA, resRunnerB: resSerialB} {
		if err := st.UpsertRunner(ctx, model.Runner{ID: id, Name: id, Capacity: 8, CertSerial: serial}); err != nil {
			t.Fatalf("upsert reservation runner %s: %v", id, err)
		}
	}
	now := time.Now().UTC()
	for i, id := range []string{resRunnerA, resRunnerB} {
		runID, jobID := pgITSchedID(t), pgITSchedID(t)
		job := pgITSchedJob(runID, jobID)
		job.CPURequest = 1
		job.MemoryRequest = int64(i+1) << 30
		if err := sched.Enqueue(ctx, model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: now}, map[string]model.Job{jobID: job}, nil, false); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if _, _, _, err := sched.Lease(ctx, id, now); err != nil {
			t.Fatalf("lease %s: %v", id, err)
		}
	}

	sums, ok := sched.ReservedResourcesBatch(ctx)
	if !ok {
		t.Fatal("ReservedResourcesBatch reported no batch contract")
	}
	for _, id := range []string{resRunnerA, resRunnerB, plainRunner} {
		want := sched.ReservedResources(ctx, id)
		if got := sums[id]; got != want {
			t.Fatalf("runner %s: batched sum = %+v, want per-runner %+v", id, got, want)
		}
	}
	if sums[resRunnerA] != (model.ResourceCapacity{CPU: 1, Memory: 1 << 30}) {
		t.Fatalf("runner A batched sum = %+v, want its live claim", sums[resRunnerA])
	}
	if sums[resRunnerB] != (model.ResourceCapacity{CPU: 1, Memory: 2 << 30}) {
		t.Fatalf("runner B batched sum = %+v, want its live claim", sums[resRunnerB])
	}
}

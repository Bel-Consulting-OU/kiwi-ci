package storage

// K4-A parity: the batched fleet view (FleetRunnerProfileBindings +
// RunnerReservationSums) must return EXACTLY the per-runner reads
// (ResolveLiveRunnerProfile + RunnerReservedResources) for every binding
// shape, including the precedence cases (cert binding wins, serial without a
// cert binding falls through to the runner-ID binding, no binding keeps the
// snapshot) and the dangling cases (a binding whose profile row is gone).
// These are the in-memory halves of the parity contract; the PostgreSQL
// halves live in the *_it_test.go file.

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestFleetRunnerViewBatchParityMem pins FleetRunnerProfileBindings against
// ResolveLiveRunnerProfile over every binding shape, resolved through the
// same shared precedence.
func TestFleetRunnerViewBatchParityMem(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()

	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "prof-cert", Labels: []string{"cert"}, Region: "eu", MaxCapacity: 3, MaxCPU: 1.5, CostPerHour: 2}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "prof-link", Labels: []string{"link"}, Region: "us", MaxCapacity: 4, MaxMemory: 1024}); err != nil {
		t.Fatal(err)
	}
	if err := m.BindCertProfile(ctx, "serial-cert", "prof-cert"); err != nil {
		t.Fatal(err)
	}
	if err := m.BindCertProfile(ctx, "serial-dangle", "prof-gone"); err != nil {
		t.Fatal(err)
	}

	runners := []model.Runner{
		// cert binding AND runner-ID binding: the cert binding must win.
		{ID: "cccccccccccccccccccccccccccccc01", Name: "cert", CertSerial: "serial-cert", Capacity: 9, Labels: []string{"snapshot"}},
		// serial with NO cert binding plus a runner-ID binding: falls through.
		{ID: "cccccccccccccccccccccccccccccc02", Name: "link", CertSerial: "serial-unbound", Capacity: 9, Labels: []string{"snapshot"}},
		// no serial, runner-ID binding only.
		{ID: "cccccccccccccccccccccccccccccc03", Name: "bearer", Capacity: 9, Labels: []string{"snapshot"}},
		// dangling cert binding: denies, even though a runner-ID binding exists.
		{ID: "cccccccccccccccccccccccccccccc04", Name: "dangle-cert", CertSerial: "serial-dangle", Capacity: 9, Labels: []string{"snapshot"}},
		// dangling runner-ID binding: denies, never the snapshot.
		{ID: "cccccccccccccccccccccccccccccc05", Name: "dangle-link", Capacity: 9, Labels: []string{"snapshot"}},
		// fully unbound: the registration snapshot applies.
		{ID: "cccccccccccccccccccccccccccccc06", Name: "plain", Capacity: 7, Labels: []string{"plain"}, Region: "snap-region"},
	}
	for _, r := range runners {
		if err := m.UpsertRunner(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.LinkRunnerProfile(ctx, runners[0].ID, "prof-link"); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runners[1].ID, "prof-link"); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runners[2].ID, "prof-link"); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runners[3].ID, "prof-link"); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, runners[4].ID, "prof-gone"); err != nil {
		t.Fatal(err)
	}

	batch, err := m.FleetRunnerProfileBindings(ctx)
	if err != nil {
		t.Fatalf("FleetRunnerProfileBindings: %v", err)
	}
	if len(batch) != len(runners) {
		t.Fatalf("batched bindings = %d runners, want %d", len(batch), len(runners))
	}
	for _, r := range runners {
		binding, ok := batch[r.ID]
		if !ok {
			t.Fatalf("runner %s missing from the batched bindings", r.ID)
		}
		got := binding.Resolve(r.CertSerial)
		want, err := m.ResolveLiveRunnerProfile(ctx, r.ID, r.CertSerial)
		if err != nil {
			t.Fatalf("ResolveLiveRunnerProfile(%s): %v", r.ID, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("runner %s: batched resolution = %+v, want per-runner %+v", r.Name, got, want)
		}
	}
	// The precedence pins, restated as observable outcomes.
	certRes := batch[runners[0].ID].Resolve(runners[0].CertSerial)
	if certRes.Source != ProfileBindingCertSerial || certRes.Profile.ID != "prof-cert" {
		t.Fatalf("cert-bound resolution = %+v, want the cert profile to win", certRes)
	}
	linkRes := batch[runners[1].ID].Resolve(runners[1].CertSerial)
	if linkRes.Source != ProfileBindingRunnerID || linkRes.Profile.ID != "prof-link" {
		t.Fatalf("unbound-serial resolution = %+v, want the runner-ID profile to apply", linkRes)
	}
	if res := batch[runners[3].ID].Resolve(runners[3].CertSerial); !res.DeniesLease() {
		t.Fatalf("dangling cert resolution = %+v, want DeniesLease", res)
	}
	if res := batch[runners[4].ID].Resolve(runners[4].CertSerial); !res.DeniesLease() {
		t.Fatalf("dangling runner-ID resolution = %+v, want DeniesLease", res)
	}
	if res := batch[runners[5].ID].Resolve(runners[5].CertSerial); res.Source != ProfileBindingNone || res.Applies() {
		t.Fatalf("unbound resolution = %+v, want the registration snapshot", res)
	}
}

// TestFleetRunnerReservationSumsParityMem pins RunnerReservationSums against
// the per-runner RunnerReservedResources over live claims (and after a
// release), so the batched fold can never diverge from the ledger the claim
// charges.
func TestFleetRunnerReservationSumsParityMem(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runnerA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a"
	runnerB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0b"
	for _, id := range []string{runnerA, runnerB} {
		if err := m.UpsertRunner(ctx, model.Runner{ID: id, Name: id, Capacity: 8, ResourceCapacity: model.ResourceCapacity{CPU: 4, Memory: 8 << 30}}); err != nil {
			t.Fatal(err)
		}
	}
	request := func(id string, cpu float64, memory int64) model.Job {
		return model.Job{ID: id, RunID: "11111111111111111111111111111111", Key: id, Status: model.StatusQueued, CPURequest: cpu, MemoryRequest: memory, CreatedAt: time.Unix(1000, 0).UTC()}
	}
	claim := func(j model.Job, runnerID string) error {
		_, err := m.AcquireLeaseAtomic(ctx, LeaseClaim{
			JobID: j.ID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
			ExpiresAt:  time.Now().Add(time.Minute),
			CPURequest: j.CPURequest, MemoryRequest: j.MemoryRequest,
		})
		return err
	}
	jobA1 := request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01", 1, 1<<30)
	jobA2 := request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02", 0.5, 512<<20)
	jobB1 := request("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01", 2, 2<<30)
	for _, j := range []model.Job{jobA1, jobA2, jobB1} {
		if err := m.InsertJob(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
	if err := claim(jobA1, runnerA); err != nil {
		t.Fatal(err)
	}
	if err := claim(jobA2, runnerA); err != nil {
		t.Fatal(err)
	}
	if err := claim(jobB1, runnerB); err != nil {
		t.Fatal(err)
	}

	assertSums := func(wantA model.ResourceCapacity) {
		t.Helper()
		sums, err := m.RunnerReservationSums(ctx)
		if err != nil {
			t.Fatalf("RunnerReservationSums: %v", err)
		}
		for _, id := range []string{runnerA, runnerB} {
			want, err := m.RunnerReservedResources(ctx, id)
			if err != nil {
				t.Fatalf("RunnerReservedResources(%s): %v", id, err)
			}
			if got := sums[id]; got != want {
				t.Fatalf("runner %s: batched sum = %+v, want per-runner %+v", id, got, want)
			}
		}
		if sums[runnerA] != wantA {
			t.Fatalf("runner A sum = %+v, want %+v", sums[runnerA], wantA)
		}
	}
	assertSums(model.ResourceCapacity{CPU: 1.5, Memory: 1<<30 + 512<<20})

	// Releasing one reservation moves BOTH reads identically.
	if err := m.ReleaseRunnerJob(ctx, runnerA, jobA1.ID, model.StatusSuccess); err != nil {
		t.Fatal(err)
	}
	sums, err := m.RunnerReservationSums(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sums[runnerA] != (model.ResourceCapacity{CPU: 0.5, Memory: 512 << 20}) {
		t.Fatalf("runner A sum after release = %+v, want only the surviving reservation", sums[runnerA])
	}
	assertSums(model.ResourceCapacity{CPU: 0.5, Memory: 512 << 20})

	// Concurrent churn (run with -race): while claims and releases
	// interleave on the shared store, every observation of the grouped fold
	// must equal a fresh re-derivation of the raw ledger. Both sides are read
	// inside ONE critical section (a public-pair comparison would span two
	// lock acquisitions and could legitimately observe different instants);
	// the public batch and per-runner reads are exercised alongside.
	stops := make(chan struct{})
	var wg sync.WaitGroup
	churnErr := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stops)
		for i := 0; i < 64; i++ {
			id := fmt.Sprintf("cccccccccccccccccccccccccccccc%02d", i)
			j := request(id, 0.1, 1<<20)
			if err := m.InsertJob(ctx, j); err != nil {
				churnErr <- err
				return
			}
			if err := claim(j, runnerA); err != nil {
				continue
			}
			if err := m.ReleaseRunnerJob(ctx, runnerA, id, model.StatusSuccess); err != nil {
				churnErr <- err
				return
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stops:
				return
			default:
			}
			if _, err := m.RunnerReservationSums(ctx); err != nil {
				churnErr <- err
				return
			}
			if _, err := m.RunnerReservedResources(ctx, runnerA); err != nil {
				churnErr <- err
				return
			}
			m.mu.Lock()
			got := m.reservationSumsLocked()
			want := map[string]model.ResourceCapacity{}
			for _, r := range m.reservations {
				want[r.RunnerID] = model.AddResourceCapacity(want[r.RunnerID], r.Capacity())
			}
			m.mu.Unlock()
			if !reflect.DeepEqual(got, want) {
				churnErr <- fmt.Errorf("batched sums under churn = %+v, want the raw ledger fold %+v", got, want)
				return
			}
		}
	}()
	wg.Wait()
	select {
	case err := <-churnErr:
		t.Fatal(err)
	default:
	}
}

// TestFleetRunnerViewBatchUnlinkedRunnerAbsent: the batched map covers exactly
// the store's runners; a runner ID the store never registered has no batched
// binding (the caller resolves it per-runner), and an unregistered runner has
// no reservation sum.
func TestFleetRunnerViewBatchUnlinkedRunnerAbsent(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	batch, err := m.FleetRunnerProfileBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := batch["dddddddddddddddddddddddddddddd01"]; ok {
		t.Fatal("unregistered runner must be absent from the batched bindings")
	}
	sums, err := m.RunnerReservationSums(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sums["dddddddddddddddddddddddddddddd01"]; ok {
		t.Fatal("unregistered runner must be absent from the batched reservation sums")
	}
}

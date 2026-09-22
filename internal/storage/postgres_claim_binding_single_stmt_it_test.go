package storage

// Real-PostgreSQL integration tests for the single-statement claim binding
// resolution (K6-D). Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go
// here.
//
// Defect: the claim always evaluated the runner-ID binding as a SECOND
// sequential lookup, so a lease attempt cost one to two extra round trips
// while it held the job and runner row locks — multiplied by every retry
// attempt. Both bindings must now be resolved in ONE statement with exactly
// the precedence and deny semantics of ResolveLiveProfileBinding, proven here
// by parity against the shared resolver over the whole binding matrix.

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// countingRowQuerier counts the statements a resolver issues through the
// package rowQuerier seam, so "ONE statement" is asserted rather than
// assumed.
type countingRowQuerier struct {
	pool  *pgxpool.Pool
	calls int
}

func (c *countingRowQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	c.calls++
	return c.pool.QueryRow(ctx, sql, args...)
}

// pgITBindingSpec describes one binding state of the parity matrix.
type pgITBindingSpec struct {
	name         string
	serial       string // serial presented to the resolver ("" = bearer identity)
	bindCert     bool   // create a cert_profile_links row for serial
	certLive     bool   // the cert-bound profile row exists (false = dangling)
	bindRunner   bool   // create a runner_profile_links row
	runnerLive   bool   // the runner-bound profile row exists (false = dangling)
	whitespaceID bool   // resolve with a whitespace-only runner ID
}

// TestIntegrationLiveProfileBindingSingleStatementParityPostgres compares the
// single-statement resolver (plus the shared precedence helper) against
// ResolveLiveProfileBinding with the per-source lookups for every binding
// state: no binding, cert-only, runner-only, both (cert wins), each dangling
// combination, and the whitespace-only serial/runner-id edges the per-source
// lookups skip.
func TestIntegrationLiveProfileBindingSingleStatementParityPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	specs := []pgITBindingSpec{
		{name: "no binding"},
		{name: "whitespace serial and runner id", serial: " \t ", whitespaceID: true},
		{name: "whitespace runner id with a stored whitespace binding", serial: "present", whitespaceID: true, bindRunner: true, runnerLive: true},
		{name: "cert only", serial: "present", bindCert: true, certLive: true},
		{name: "cert unbound serial", serial: "present"},
		{name: "runner only", bindRunner: true, runnerLive: true},
		{name: "runner only, unbound serial presented", serial: "present", bindRunner: true, runnerLive: true},
		{name: "both bound: cert wins", serial: "present", bindCert: true, certLive: true, bindRunner: true, runnerLive: true},
		{name: "both bound with blank serial: runner wins", serial: "  ", bindCert: true, certLive: true, bindRunner: true, runnerLive: true},
		{name: "dangling cert beats live runner binding", serial: "present", bindCert: true, bindRunner: true, runnerLive: true},
		{name: "dangling runner binding", bindRunner: true},
		{name: "both dangling: cert wins", serial: "present", bindCert: true, bindRunner: true},
	}
	for _, tc := range specs {
		t.Run(tc.name, func(t *testing.T) {
			runnerID := pgITNewID(t)
			if tc.whitespaceID {
				runnerID = " \t "
			}
			certProfileID := "cp-" + pgITRandomHex(t, 8)
			runnerProfileID := "rp-" + pgITRandomHex(t, 8)
			serial := tc.serial
			if tc.bindCert {
				serial = "cert-" + pgITRandomHex(t, 8)
				if err := st.BindCertProfile(ctx, serial, certProfileID); err != nil {
					t.Fatalf("bind cert profile: %v", err)
				}
				if tc.certLive {
					pgITUpsertBindingProfile(t, st, certProfileID, certProfileID)
				}
			}
			if tc.bindRunner {
				if err := st.LinkRunnerProfile(ctx, runnerID, runnerProfileID); err != nil {
					t.Fatalf("link runner profile: %v", err)
				}
				if tc.runnerLive {
					pgITUpsertBindingProfile(t, st, runnerProfileID, runnerProfileID)
				}
			}

			// The single-statement resolver: exactly one round trip.
			counter := &countingRowQuerier{pool: st.pool}
			binding, err := liveProfileBindingTx(ctx, counter, runnerID, serial)
			if err != nil {
				t.Fatalf("liveProfileBindingTx: %v", err)
			}
			if counter.calls != 1 {
				t.Fatalf("single-statement resolver issued %d statements, want 1", counter.calls)
			}
			got := binding.Resolve(serial)
			if err := ctx.Err(); err != nil {
				t.Fatal(err)
			}

			// The shared resolver over the per-source lookups: the reference
			// semantics (and, for a bound case, more than one statement).
			refCounter := &countingRowQuerier{pool: st.pool}
			want, err := ResolveLiveProfileBinding(serial,
				func() (model.RunnerProfile, bool, bool, error) { return profileForSerialQ(ctx, refCounter, serial) },
				func() (model.RunnerProfile, bool, bool, error) { return profileForRunnerIDQ(ctx, refCounter, runnerID) },
			)
			if err != nil {
				t.Fatalf("ResolveLiveProfileBinding: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("single-statement resolution = %+v, shared resolver = %+v", got, want)
			}
			if tc.bindCert || (tc.bindRunner && !tc.whitespaceID) {
				if refCounter.calls <= counter.calls {
					t.Fatalf("per-source resolver issued %d statements, single statement issued %d: no round trip was saved", refCounter.calls, counter.calls)
				}
			}
			// The deny semantics travel with the shared helper.
			if want.Linked && !want.Found && !got.DeniesLease() {
				t.Fatalf("dangling binding %+v does not deny the lease", got)
			}
		})
	}
}

// pgITUpsertBindingProfile creates the profile row a binding points at.
func pgITUpsertBindingProfile(t *testing.T, st *PostgresStore, profileID, label string) {
	t.Helper()
	if err := st.UpsertProfile(context.Background(), model.RunnerProfile{ID: profileID, Labels: []string{label}, MaxCapacity: 4}); err != nil {
		t.Fatalf("upsert binding profile %s: %v", profileID, err)
	}
}

// TestIntegrationClaimDeniesDanglingBindingsPostgres pins the claim-level
// consequence of the shared precedence: a dangling runner-ID binding (the
// binding row exists, its profile row is gone) fails the lease closed exactly
// like a dangling certificate-serial binding, and a runner with a live
// runner-ID binding leases through the binding rather than its registration
// snapshot.
func TestIntegrationClaimDeniesDanglingBindingsPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	// The registration snapshot would happily admit (capacity 5, matching
	// label); only the dangling binding may deny.
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 5, Labels: []string{"snapshot"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkRunnerProfile(ctx, runnerID, "dangling-"+pgITRandomHex(t, 8)); err != nil {
		t.Fatal(err)
	}
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, runID, jobID, pgITRepoID, nil)
	claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute), TokenHash: []byte("h")}
	if _, err := st.AcquireLeaseAtomic(ctx, claim); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("claim with a dangling runner-ID binding = %v, want ErrNoCapacity", err)
	}
	if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusQueued {
		t.Fatalf("denied claim changed the job: %+v err=%v", j, err)
	}

	// Re-bind the runner to a LIVE profile: the same claim now succeeds and
	// the live profile replaces the snapshot.
	profileID := "live-" + pgITRandomHex(t, 8)
	pgITUpsertBindingProfile(t, st, profileID, "live")
	if err := st.LinkRunnerProfile(ctx, runnerID, profileID); err != nil {
		t.Fatal(err)
	}
	leased, err := st.AcquireLeaseAtomic(ctx, claim)
	if err != nil {
		t.Fatalf("claim after re-binding: %v", err)
	}
	if leased.LeaseRunnerID != runnerID || leased.LeaseGeneration != 1 {
		t.Fatalf("leased job = %+v, want runner %s generation 1", leased, runnerID)
	}
}

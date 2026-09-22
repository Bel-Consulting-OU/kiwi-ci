package storage

// K4-A: the SET-BASED fleet view.
//
// The fleet-global queue-reason explainer must resolve the live profile
// binding of EVERY active runner on every lease-miss poll. Resolving them one
// runner at a time costs up to four sequential round trips each (cert link,
// cert profile, runner-ID link, runner-ID profile) plus one reservation SUM,
// so a poll's latency grew with the fleet size even though the decision only
// needs the aggregate. This file is the ONE batched read contract that
// answers both questions in two set-based queries:
//
//  1. [FleetRunnerViewStore.FleetRunnerProfileBindings]: every persisted
//     runner LEFT JOINed to its certificate-serial binding AND its
//     runner-ID binding (runner_profile_links), each against
//     runner_profiles. The raw linked/found state is preserved per source, so
//     the caller resolves it through the SAME precedence helper the per-runner
//     lease path uses ([FleetRunnerBinding.Resolve] calls
//     [ResolveLiveProfileBinding]) instead of re-implementing the rules here.
//  2. [FleetRunnerViewStore.RunnerReservationSums]: the live reservation
//     ledger folded with one GROUP BY runner_id over
//     job_resource_reservations, byte-for-byte the same quantities the
//     per-runner SUM ([ResourceReservationStore.RunnerReservedResources])
//     reports. Both count only rows that still describe a live lease
//     (liveReservationExistsSQL), so an orphan row a pre-upgrade replica left
//     behind is invisible to the fleet view exactly as it is to the claim.
//
// The batched answer is a point-in-time read, exactly like the per-runner
// sequence it replaces: the lease claim remains the authoritative decision
// inside its own transaction (and re-reads the binding under the runner-row
// lock), so a concurrent profile edit or binding change can only make the
// explainer's view one pass stale, never the lease itself.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// FleetProfileBinding is one binding source's batched state for one runner:
// Linked reports that the binding row exists, Found that the bound profile
// row exists. Linked && !Found is a dangling binding, decided by the shared
// [LiveProfileResolution.DeniesLease] policy.
type FleetProfileBinding struct {
	Linked  bool
	Found   bool
	Profile model.RunnerProfile
}

// FleetRunnerBinding is one runner's batched binding state: exactly the two
// inputs [ResolveLiveProfileBinding] consults (the certificate-serial source
// and the runner-ID source), with the profile rows already joined.
type FleetRunnerBinding struct {
	Cert   FleetProfileBinding
	Runner FleetProfileBinding
}

// Resolve applies the ONE shared live-profile precedence to the batched
// inputs. serial is the runner row's resolution-derived certificate serial
// (empty for a per-runner bearer identity), exactly as the per-runner
// resolution is called. The function is literally the shared helper, so the
// batched and per-runner answers cannot diverge: a cert binding wins when the
// runner presents a serial, otherwise a runner-ID binding applies, otherwise
// no binding applies; a dangling binding denies the lease.
func (b FleetRunnerBinding) Resolve(serial string) LiveProfileResolution {
	resolution, err := ResolveLiveProfileBinding(serial,
		func() (model.RunnerProfile, bool, bool, error) {
			return b.Cert.Profile, b.Cert.Linked, b.Cert.Found, nil
		},
		func() (model.RunnerProfile, bool, bool, error) {
			return b.Runner.Profile, b.Runner.Linked, b.Runner.Found, nil
		},
	)
	// ResolveLiveProfileBinding only fails when a lookup returns an error;
	// these closures cannot, so the error arm is impossible by construction.
	if err != nil {
		return LiveProfileResolution{}
	}
	return resolution
}

// FleetRunnerViewStore is the set-based fleet-view read contract used by the
// scheduler's batch entry points and the queue-reason explainers. Both
// queries are full-fleet reads (no per-runner round trips):
//
//   - FleetRunnerProfileBindings returns every persisted runner's raw binding
//     state, keyed by runner ID. A runner missing from the map has no batched
//     answer and must be resolved per-runner by the caller.
//   - RunnerReservationSums returns every runner's live reservation sum; a
//     runner without reservations is absent (or zero).
//
// PostgresStore and the in-memory store implement it, so the mem-mode parity
// tests can pin the two implementations against each other.
type FleetRunnerViewStore interface {
	FleetRunnerProfileBindings(ctx context.Context) (map[string]FleetRunnerBinding, error)
	RunnerReservationSums(ctx context.Context) (map[string]model.ResourceCapacity, error)
}

var _ FleetRunnerViewStore = (*PostgresStore)(nil)

// fleetProfileRow is one runner_profiles row scanned out of a LEFT JOIN:
// every column is COALESCEd to its zero value so a missing profile scans as
// the zero row, with Found carried separately by the join predicate.
type fleetProfileRow struct {
	id          string
	labels      []byte
	region      string
	repos       []byte
	caps        []byte
	maxCapacity int
	maxCPU      float64
	maxMemory   int64
	maxDisk     int64
	maxPIDs     int
	cost        float64
	watts       float64
	createdAt   time.Time
}

func (p *fleetProfileRow) targets() []any {
	return []any{
		&p.id, &p.labels, &p.region, &p.repos, &p.caps,
		&p.maxCapacity, &p.maxCPU, &p.maxMemory, &p.maxDisk, &p.maxPIDs,
		&p.cost, &p.watts, &p.createdAt,
	}
}

// profile decodes the scanned row into a model.RunnerProfile with the same
// decoder the per-runner reads use (the field list mirrors scanProfile).
func (p *fleetProfileRow) profile() (model.RunnerProfile, error) {
	var out model.RunnerProfile
	out.ID = p.id
	if err := jsonUnmarshalColumn(p.labels, &out.Labels, "labels"); err != nil {
		return model.RunnerProfile{}, err
	}
	if err := jsonUnmarshalColumn(p.repos, &out.Repositories, "repositories"); err != nil {
		return model.RunnerProfile{}, err
	}
	if err := jsonUnmarshalColumn(p.caps, &out.Capabilities, "capabilities"); err != nil {
		return model.RunnerProfile{}, err
	}
	out.Region = p.region
	out.MaxCapacity = p.maxCapacity
	out.MaxCPU = p.maxCPU
	out.MaxMemory = p.maxMemory
	out.MaxDisk = p.maxDisk
	out.MaxPIDs = p.maxPIDs
	out.CostPerHour = p.cost
	out.PowerWatts = p.watts
	out.CreatedAt = p.createdAt
	return out, nil
}

// jsonUnmarshalColumn decodes one JSONB profile column, tagging the failure
// with the same column name the per-runner reads report.
func jsonUnmarshalColumn(raw []byte, dest any, what string) error {
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("storage: decode profile %s: %w", what, err)
	}
	return nil
}

// fleetCertProfileCols are the runner_profiles columns of the
// certificate-serial join, qualified with the cp alias and COALESCEd so a
// missing binding/profile row scans as the zero profile. The list MUST stay
// in fleetProfileRow.targets order and mirror profileCols.
const fleetCertProfileCols = "COALESCE(cp.id, ''), COALESCE(cp.labels, '[]'::jsonb), COALESCE(cp.region, ''), COALESCE(cp.repositories, '[]'::jsonb), COALESCE(cp.capabilities, '[]'::jsonb), COALESCE(cp.max_capacity, 0), COALESCE(cp.max_cpu, 0), COALESCE(cp.max_memory, 0), COALESCE(cp.max_disk, 0), COALESCE(cp.max_pids, 0), COALESCE(cp.cost_per_hour, 0), COALESCE(cp.power_watts, 0), COALESCE(cp.created_at, to_timestamp(0))"

// fleetRunnerIDProfileCols is fleetCertProfileCols for the runner-ID join
// (the rp alias). The two lists MUST stay identical apart from the alias.
const fleetRunnerIDProfileCols = "COALESCE(rp.id, ''), COALESCE(rp.labels, '[]'::jsonb), COALESCE(rp.region, ''), COALESCE(rp.repositories, '[]'::jsonb), COALESCE(rp.capabilities, '[]'::jsonb), COALESCE(rp.max_capacity, 0), COALESCE(rp.max_cpu, 0), COALESCE(rp.max_memory, 0), COALESCE(rp.max_disk, 0), COALESCE(rp.max_pids, 0), COALESCE(rp.cost_per_hour, 0), COALESCE(rp.power_watts, 0), COALESCE(rp.created_at, to_timestamp(0))"

// FleetRunnerProfileBindings implements FleetRunnerViewStore: ONE query over
// runners LEFT JOINed to both binding sources and their profiles. The join
// predicates mirror the per-runner reads exactly:
//
//   - the certificate-serial join only applies when the runner row carries a
//     non-blank serial (the per-runner resolver skips the cert lookup for a
//     blank serial), and it matches the stored serial verbatim;
//   - the runner-ID join matches runner_profile_links.runner_id = runners.id.
//
// Dangling bindings (the link row exists, the profile row does not) keep
// linked=true/found=false, exactly the input [ResolveLiveProfileBinding]
// needs to deny the lease.
func (s *PostgresStore) FleetRunnerProfileBindings(ctx context.Context) (map[string]FleetRunnerBinding, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.id,
		(cpl.serial IS NOT NULL), (cp.id IS NOT NULL), `+fleetCertProfileCols+`,
		(rpl.runner_id IS NOT NULL), (rp.id IS NOT NULL), `+fleetRunnerIDProfileCols+`
		FROM runners r
		LEFT JOIN cert_profile_links cpl ON btrim(COALESCE(r.payload->>'cert_serial', '')) <> '' AND cpl.serial = r.payload->>'cert_serial'
		LEFT JOIN runner_profiles cp ON cp.id = cpl.profile_id
		LEFT JOIN runner_profile_links rpl ON rpl.runner_id = r.id
		LEFT JOIN runner_profiles rp ON rp.id = rpl.profile_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]FleetRunnerBinding{}
	for rows.Next() {
		var (
			runnerID                  string
			certLinked, certFound     bool
			certRow                   fleetProfileRow
			runnerLinked, runnerFound bool
			runnerRow                 fleetProfileRow
		)
		dest := []any{&runnerID, &certLinked, &certFound}
		dest = append(dest, certRow.targets()...)
		dest = append(dest, &runnerLinked, &runnerFound)
		dest = append(dest, runnerRow.targets()...)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		binding := FleetRunnerBinding{
			Cert:   FleetProfileBinding{Linked: certLinked, Found: certFound},
			Runner: FleetProfileBinding{Linked: runnerLinked, Found: runnerFound},
		}
		if certFound {
			p, err := certRow.profile()
			if err != nil {
				return nil, err
			}
			binding.Cert.Profile = p
		}
		if runnerFound {
			p, err := runnerRow.profile()
			if err != nil {
				return nil, err
			}
			binding.Runner.Profile = p
		}
		out[runnerID] = binding
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// RunnerReservationSums implements FleetRunnerViewStore: ONE GROUP BY
// runner_id fold of the durable ledger, exactly the quantities
// runnerReservedResourcesTx sums per runner (COALESCEd so a runner with no
// rows reads zero on every dimension). Like the per-runner SUM it counts only
// rows that still describe a live lease (liveReservationExistsSQL), so the
// batched and per-runner answers stay equal when an old replica leaves an
// orphan row behind.
func (s *PostgresStore) RunnerReservationSums(ctx context.Context) (map[string]model.ResourceCapacity, error) {
	rows, err := s.pool.Query(ctx, `SELECT r.runner_id, COALESCE(SUM(r.cpu), 0), COALESCE(SUM(r.memory), 0), COALESCE(SUM(r.disk), 0), COALESCE(SUM(r.pids), 0) FROM job_resource_reservations r WHERE `+liveReservationExistsSQL+` GROUP BY r.runner_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]model.ResourceCapacity{}
	for rows.Next() {
		var (
			runnerID string
			sum      model.ResourceCapacity
		)
		if err := rows.Scan(&runnerID, &sum.CPU, &sum.Memory, &sum.Disk, &sum.PIDs); err != nil {
			return nil, err
		}
		out[runnerID] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

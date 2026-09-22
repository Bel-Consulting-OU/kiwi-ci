package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Live-profile resolution: the ONE precedence every lease-time site shares
// (the SQL claim, the mem store, the scheduler prefilter and the queue
// explainers, in DB and fs/dev mode). It answers the residual left by
// migration 0031: a per-runner bearer identity is bound to a profile through
// runner_profile_links, so live resolution must consult that binding too —
// not only the certificate-serial binding — or a profile edit would not take
// effect until the runner re-registers.
//
// The precedence, in order:
//
//  1. an explicit CERTIFICATE-SERIAL binding wins when the runner presents a
//     registered serial (the mTLS path; the serial is the resolution-derived
//     one stored on the runner row, never a client assertion made at lease
//     time). A serial with no cert_profile_links row does not win and falls
//     through.
//  2. otherwise the runner-ID binding (runner_profile_links) applies: this is
//     the per-runner bearer path, and the reason profile edits are visible on
//     the next lease.
//  3. otherwise no binding applies and the registration snapshot is used
//     unchanged.
//
// Dangling bindings (a binding whose profile row is gone) DENY the lease
// closed, identically for both sources ([LiveProfileResolution.DeniesLease]):
// the binding exists, so the profile SELECTED by it is authoritative, and a
// missing profile row must neither silently resurrect the registration
// snapshot (which can carry attributes copied from a profile that no longer
// governs the runner) nor fall back to another binding. Registration still
// treats a dangling binding as not-found — it fails closed under
// RequireProfiles and registers empty otherwise — because a registration is
// the repair point (the admin re-binds or re-creates the profile), whereas a
// lease is a privilege decision that must not trust a stale snapshot.
//
// Revocation is enforced by the SAME store operation that removes a binding:
// [RunnerProfileLinkStore.UnlinkRunnerProfile] clears the profile-derived
// registration-snapshot attributes of a marked runner row (see
// [ClearProfileDerivedRunnerFields]) together with the binding row, so after
// an unlink neither the binding nor the snapshot carries the removed
// profile's grants.

// ProfileBindingSource identifies which binding supplied a runner's effective
// profile.
type ProfileBindingSource string

const (
	// ProfileBindingNone: no binding applies; the registration snapshot is
	// the effective view. It is the zero value.
	ProfileBindingNone ProfileBindingSource = ""
	// ProfileBindingCertSerial: the explicit certificate-serial binding won.
	ProfileBindingCertSerial ProfileBindingSource = "cert-serial"
	// ProfileBindingRunnerID: the runner_profile_links binding applies.
	ProfileBindingRunnerID ProfileBindingSource = "runner-id"
)

// LiveProfileResolution is the outcome of the shared live-profile precedence.
// Source names the binding that decided the resolution (ProfileBindingNone
// when no binding applies); Linked reports that the source's binding row
// exists; Found reports that the bound profile row exists. Linked && !Found
// is a dangling binding.
type LiveProfileResolution struct {
	Profile model.RunnerProfile
	Source  ProfileBindingSource
	Linked  bool
	Found   bool
}

// ProfileBindingLookup resolves one binding source to its profile. linked
// reports whether a binding row exists for the source; found reports whether
// the bound profile row exists. Implementations must return linked=true,
// found=false for a dangling binding and linked=false for "no binding".
type ProfileBindingLookup func() (p model.RunnerProfile, linked, found bool, err error)

// ResolveLiveProfileBinding applies the shared precedence above. serial is
// the runner row's resolution-derived certificate serial (empty for a
// per-runner bearer identity); the cert lookup is consulted only when serial
// is non-empty.
func ResolveLiveProfileBinding(serial string, certLookup, runnerIDLookup ProfileBindingLookup) (LiveProfileResolution, error) {
	if strings.TrimSpace(serial) != "" && certLookup != nil {
		p, linked, found, err := certLookup()
		if err != nil {
			return LiveProfileResolution{}, err
		}
		if linked {
			return LiveProfileResolution{Profile: p, Source: ProfileBindingCertSerial, Linked: true, Found: found}, nil
		}
	}
	if runnerIDLookup != nil {
		p, linked, found, err := runnerIDLookup()
		if err != nil {
			return LiveProfileResolution{}, err
		}
		if linked {
			return LiveProfileResolution{Profile: p, Source: ProfileBindingRunnerID, Linked: true, Found: found}, nil
		}
	}
	return LiveProfileResolution{Source: ProfileBindingNone}, nil
}

// Applies reports whether the resolution carries a LIVE profile that must
// replace the registration snapshot.
func (r LiveProfileResolution) Applies() bool { return r.Found }

// DeniesLease reports whether the resolution fails the lease closed: a
// binding exists but its profile row is gone (a dangling binding), for the
// certificate-serial source AND the runner-ID source alike. A binding is an
// explicit statement of which profile governs the runner, so a missing
// profile must not silently fall back to the registration snapshot — after a
// profile deletion the snapshot may still carry attributes copied from that
// profile. The SQL claim and the mem claim must both deny on this; the
// scheduler prefilter and the explainers present the same runner as
// zero-capacity so they agree with the claim instead of proposing candidates
// it will reject.
func (r LiveProfileResolution) DeniesLease() bool {
	return r.Linked && !r.Found
}

// LiveProfileResolver is the store-level live resolution contract: the shared
// helper wired to one store's durable lookups (link-aware: a dangling binding
// is distinguishable from "no binding"). The scheduler prefilter and the
// queue explainers use it when the store implements it, so every runtime
// resolution site decides identically.
type LiveProfileResolver interface {
	// ResolveLiveRunnerProfile resolves one runner's effective profile.
	// serial is the runner row's resolution-derived certificate serial ("" for
	// a per-runner bearer identity).
	ResolveLiveRunnerProfile(ctx context.Context, runnerID, serial string) (LiveProfileResolution, error)
}

// profileForSerialQ resolves the LIVE profile bound to a certificate serial
// with link awareness. It is the query behind ProfileForSerial AND the
// per-source resolver behind ResolveLiveRunnerProfile. It shares the package
// rowQuerier (pgx.Tx / *pgxpool.Pool) with the reservation reads.
func profileForSerialQ(ctx context.Context, q rowQuerier, serial string) (p model.RunnerProfile, linked, found bool, err error) {
	if strings.TrimSpace(serial) == "" {
		return model.RunnerProfile{}, false, false, nil
	}
	var profileID string
	err = q.QueryRow(ctx, `SELECT profile_id FROM cert_profile_links WHERE serial=$1`, serial).Scan(&profileID)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RunnerProfile{}, false, false, nil
	}
	if err != nil {
		return model.RunnerProfile{}, false, false, err
	}
	p, err = scanProfile(q.QueryRow(ctx, `SELECT `+profileCols+` FROM runner_profiles WHERE id=$1`, profileID))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RunnerProfile{}, true, false, nil
	}
	if err != nil {
		return model.RunnerProfile{}, false, false, err
	}
	return p, true, true, nil
}

// profileForRunnerIDQ resolves the LIVE profile bound to a runner ID with
// link awareness (the runner_profile_links -> runner_profiles join the
// contract documents). found=false with linked=true is a dangling binding.
func profileForRunnerIDQ(ctx context.Context, q rowQuerier, runnerID string) (p model.RunnerProfile, linked, found bool, err error) {
	if strings.TrimSpace(runnerID) == "" {
		return model.RunnerProfile{}, false, false, nil
	}
	var profileID string
	err = q.QueryRow(ctx, `SELECT profile_id FROM runner_profile_links WHERE runner_id=$1`, runnerID).Scan(&profileID)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RunnerProfile{}, false, false, nil
	}
	if err != nil {
		return model.RunnerProfile{}, false, false, err
	}
	p, err = scanProfile(q.QueryRow(ctx, `SELECT `+profileCols+` FROM runner_profiles WHERE id=$1`, profileID))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RunnerProfile{}, true, false, nil
	}
	if err != nil {
		return model.RunnerProfile{}, false, false, err
	}
	return p, true, true, nil
}

// ResolveLiveRunnerProfile implements LiveProfileResolver on the pool: the
// scheduler prefilter and the queue explainers read the same committed
// bindings the claim transaction reads under its runner-row lock.
func (s *PostgresStore) ResolveLiveRunnerProfile(ctx context.Context, runnerID, serial string) (LiveProfileResolution, error) {
	return ResolveLiveProfileBinding(serial,
		func() (model.RunnerProfile, bool, bool, error) { return profileForSerialQ(ctx, s.pool, serial) },
		func() (model.RunnerProfile, bool, bool, error) { return profileForRunnerIDQ(ctx, s.pool, runnerID) },
	)
}

// liveProfileBindingTx resolves BOTH binding sources of one runner in ONE
// statement (K6-D): the per-source lookups cost up to four sequential round
// trips (link, profile, link, profile) while the claim holds the job and
// runner row locks, multiplied by every retry attempt. The query is the
// claim's per-runner form of the fleet view's two LEFT JOINs — the
// certificate-serial binding (matched verbatim, only when the runner
// presents a non-blank serial) and the runner-ID binding, each joined to
// runner_profiles — and the result is the SAME raw linked/found state the
// fleet view carries, so the caller resolves it through the SAME shared
// precedence helper ([FleetRunnerBinding.Resolve] ->
// [ResolveLiveProfileBinding]). Precedence and deny semantics therefore
// cannot drift from the per-source resolver: they are one function.
//
// The blank-serial decision is made in Go with the exact semantics of
// [profileForSerialQ]/[profileForRunnerIDQ] (strings.TrimSpace), passed as
// the use_serial/use_runner flags: a whitespace-only serial or runner ID
// must never match a binding row, and a non-blank serial is matched
// VERBATIM (never trimmed), exactly as the per-source reads do.
func liveProfileBindingTx(ctx context.Context, q rowQuerier, runnerID, serial string) (FleetRunnerBinding, error) {
	var (
		certLinked, certFound     bool
		certRow                   fleetProfileRow
		runnerLinked, runnerFound bool
		runnerRow                 fleetProfileRow
	)
	dest := []any{&certLinked, &certFound}
	dest = append(dest, certRow.targets()...)
	dest = append(dest, &runnerLinked, &runnerFound)
	dest = append(dest, runnerRow.targets()...)
	err := q.QueryRow(ctx, `SELECT (cpl.serial IS NOT NULL), (cp.id IS NOT NULL), `+fleetCertProfileCols+`,
		(rpl.runner_id IS NOT NULL), (rp.id IS NOT NULL), `+fleetRunnerIDProfileCols+`
		FROM (SELECT $1::text AS runner_id, $2::text AS serial, $3::boolean AS use_serial, $4::boolean AS use_runner) q
		LEFT JOIN cert_profile_links cpl ON q.use_serial AND cpl.serial = q.serial
		LEFT JOIN runner_profiles cp ON cp.id = cpl.profile_id
		LEFT JOIN runner_profile_links rpl ON q.use_runner AND rpl.runner_id = q.runner_id
		LEFT JOIN runner_profiles rp ON rp.id = rpl.profile_id`,
		runnerID, serial, strings.TrimSpace(serial) != "", strings.TrimSpace(runnerID) != "").Scan(dest...)
	if err != nil {
		return FleetRunnerBinding{}, err
	}
	binding := FleetRunnerBinding{
		Cert:   FleetProfileBinding{Linked: certLinked, Found: certFound},
		Runner: FleetProfileBinding{Linked: runnerLinked, Found: runnerFound},
	}
	if certFound {
		p, err := certRow.profile()
		if err != nil {
			return FleetRunnerBinding{}, err
		}
		binding.Cert.Profile = p
	}
	if runnerFound {
		p, err := runnerRow.profile()
		if err != nil {
			return FleetRunnerBinding{}, err
		}
		binding.Runner.Profile = p
	}
	return binding, nil
}

// LiveProfileBindingTx resolves a runner's live profile inside the caller's
// transaction through the single-statement resolver above. It is the claim's
// entry point; the returned resolution carries the shared precedence and deny
// semantics.
func liveProfileResolutionTx(ctx context.Context, q rowQuerier, runnerID, serial string) (LiveProfileResolution, error) {
	binding, err := liveProfileBindingTx(ctx, q, runnerID, serial)
	if err != nil {
		return LiveProfileResolution{}, err
	}
	return binding.Resolve(serial), nil
}

// RunnerProfileLinkStore is the durable runner-ID -> profile binding
// contract (migration 0031: runner_profile_links).
//
// It is the ONLY profile-selection source for per-runner bearer identities:
// registration must never resolve a profile from the client-asserted
// cert_serial, because that field is attacker-chosen and would let one
// bearer token inherit another runner's profile (labels, capabilities,
// capacity, repository ACL). runner_id is the PRIMARY KEY, so a binding is
// unique per runner and re-linking is an idempotent replace; the
// one-binding invariant is enforced by the database instead of by scanning
// runner payloads, which two concurrent registrations can both pass.
//
// ProfileForRunnerID joins the LIVE profile row, so a profile edit takes
// effect on the next resolution; a link whose profile row is missing
// resolves to "not found" (false). Registration treats that as unprofiled
// (and fails closed under RequireProfiles); lease-time live resolution
// DENIES the lease (see ResolveLiveProfileBinding for the documented
// dangling-binding policy).
//
// UnlinkRunnerProfile is revocation, not merely row deletion: in one
// operation it removes the binding AND clears the profile-derived
// registration attributes of a marked runner row, so the removed profile
// cannot keep applying through the registration snapshot.
type RunnerProfileLinkStore interface {
	// LinkRunnerProfile binds a runner ID to a profile, replacing any
	// previous binding for the same runner in one statement.
	LinkRunnerProfile(ctx context.Context, runnerID, profileID string) error
	// ProfileForRunnerID resolves the profile bound to a runner ID.
	// found=false means "no binding" or "binding without a profile row";
	// both are treated as unprofiled by the caller.
	ProfileForRunnerID(ctx context.Context, runnerID string) (model.RunnerProfile, bool, error)
	// UnlinkRunnerProfile removes a runner's binding AND clears the
	// profile-derived attributes of the runner's marked registration
	// snapshot (ClearProfileDerivedRunnerFields) in the same operation: a
	// removed profile is revoked immediately, not on the next registration.
	// It is idempotent: a missing row is a successful no-op.
	UnlinkRunnerProfile(ctx context.Context, runnerID string) error
	// RunnerIDsForProfile lists the runner IDs bound to one profile,
	// ordered by runner ID so the answer is deterministic.
	RunnerIDsForProfile(ctx context.Context, profileID string) ([]string, error)
}

var _ RunnerProfileLinkStore = (*PostgresStore)(nil)
var _ LiveProfileResolver = (*PostgresStore)(nil)

// LinkRunnerProfile persists one runner-ID -> profile binding. The PRIMARY
// KEY upsert replaces the previous binding atomically, so concurrent
// bind/unbind calls can never leave two rows for one runner.
func (s *PostgresStore) LinkRunnerProfile(ctx context.Context, runnerID, profileID string) error {
	if runnerID == "" {
		return fmt.Errorf("storage: runner id is required")
	}
	if profileID == "" {
		return fmt.Errorf("storage: profile id is required")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO runner_profile_links (runner_id, profile_id) VALUES ($1,$2) ON CONFLICT (runner_id) DO UPDATE SET profile_id=EXCLUDED.profile_id`, runnerID, profileID)
	return err
}

// ProfileForRunnerID resolves the LIVE profile for a runner-ID binding. A
// dangling link (profile row deleted) reports found=false so the caller
// fails closed instead of resurrecting a deleted profile.
func (s *PostgresStore) ProfileForRunnerID(ctx context.Context, runnerID string) (model.RunnerProfile, bool, error) {
	if runnerID == "" {
		return model.RunnerProfile{}, false, nil
	}
	p, err := scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileColsAliased+` FROM runner_profile_links rl JOIN runner_profiles rp ON rp.id = rl.profile_id WHERE rl.runner_id=$1`, runnerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RunnerProfile{}, false, nil
	}
	if err != nil {
		return model.RunnerProfile{}, false, err
	}
	return p, true, nil
}

// UnlinkRunnerProfile removes a runner's binding AND revokes the
// profile-derived registration attributes copied onto the runner row, in the
// same transaction: after the call returns, neither the binding nor the
// snapshot carries the removed profile's grants. A missing binding is a
// successful no-op (an admin can always assert the unbound state), and a
// runner row without a stored profile marker is never touched (legacy
// dev-mode self-reported attributes are the runner's own). The runner row is
// locked FOR UPDATE, so a concurrent claim either sees the binding and the
// untouched snapshot (the unlink not yet committed) or the cleared row (the
// unlink committed) — never a binding-less row that still carries the
// profile's attributes.
func (s *PostgresStore) UnlinkRunnerProfile(ctx context.Context, runnerID string) error {
	if runnerID == "" {
		return fmt.Errorf("storage: runner id is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM runner_profile_links WHERE runner_id=$1`, runnerID); err != nil {
		return err
	}
	if err := clearRunnerProfileSnapshotTx(ctx, tx, runnerID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// clearRunnerProfileSnapshotTx clears the profile-derived registration
// attributes of one MARKED runner row (payload.profile_id != "") inside the
// unlink transaction. It locks the row and rewrites the payload plus the
// capacity/busy columns, so the runner row and the returned runner view stay
// consistent for the claim's snapshot path. A missing runner row, or a row
// with no profile marker, is a no-op — unlink must stay idempotent for
// runners that never registered.
func clearRunnerProfileSnapshotTx(ctx context.Context, tx pgx.Tx, runnerID string) error {
	var payload []byte
	err := tx.QueryRow(ctx, `SELECT payload FROM runners WHERE id=$1 FOR UPDATE`, runnerID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var r model.Runner
	if err := json.Unmarshal(payload, &r); err != nil {
		return fmt.Errorf("storage: decode runner payload: %w", err)
	}
	cleared, changed := ClearProfileDerivedRunnerFields(r)
	if !changed {
		return nil
	}
	newPayload, err := jsonMarshal(cleared)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE runners SET payload=$2, capacity=$3, busy=$4 WHERE id=$1`,
		runnerID, newPayload, cleared.Capacity, cleared.Busy)
	return err
}

// ClearProfileDerivedRunnerFields clears the registration-snapshot
// attributes a runner profile supplied when the row carries a stored profile
// marker (Runner.ProfileID != ""). changed=false means the row is the
// runner's OWN registration (legacy dev-mode self-reported attributes, or a
// row that never had a profile) and is returned unchanged.
//
// The rule is deliberately all-or-nothing per marked row: while the marker
// is set, every scheduling attribute of the row was copied from a profile
// (labels, region, repository ACL, capabilities, job capacity, resource
// capacity, cost and energy rates), so an unlink clears ALL of them and the
// runner re-registers to regain whatever its current binding grants. Fields
// the runner itself declared (dev-mode labels/capacity/rates on an unmarked
// row, identity, metadata, admin state) are never touched. Busy is
// recomputed for the cleared capacity so the row cannot claim to be busy on
// zero capacity.
func ClearProfileDerivedRunnerFields(r model.Runner) (model.Runner, bool) {
	if r.ProfileID == "" {
		return r, false
	}
	r.ProfileID = ""
	r.Labels = nil
	r.Region = ""
	r.AllowedRepositories = nil
	r.Capabilities = nil
	r.Capacity = 0
	r.ResourceCapacity = model.ResourceCapacity{}
	r.CostPerHour = 0
	r.PowerWatts = 0
	r.Busy = r.Capacity > 0 && len(r.ActiveJobs) >= r.Capacity
	return r, true
}

// RunnerIDsForProfile lists the runner IDs bound to one profile. The empty
// profile ID returns an empty (non-nil) slice instead of every row.
func (s *PostgresStore) RunnerIDsForProfile(ctx context.Context, profileID string) ([]string, error) {
	if profileID == "" {
		return []string{}, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT runner_id FROM runner_profile_links WHERE profile_id=$1 ORDER BY runner_id`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

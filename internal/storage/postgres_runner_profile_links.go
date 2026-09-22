package storage

import (
	"context"
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
// Dangling bindings (a binding whose profile row is gone) are decided
// deliberately and identically everywhere:
//
//   - a dangling CERTIFICATE-SERIAL binding fails the lease closed
//     ([LiveProfileResolution.DeniesLease]): the explicit binding won, so the
//     runner-ID binding must not be consulted, and a deleted profile must not
//     silently resurrect the registration snapshot.
//   - a dangling RUNNER-ID binding resolves as "no profile": no binding
//     applies, so the existing unprofiled semantics hold and the registration
//     snapshot is used. This is bounded by construction — the snapshot is
//     exactly what the runner registered with, never more — and it mirrors
//     registration, where a dangling binding resolves to not-found (and fails
//     closed there under RequireProfiles). It is never the deleted profile.

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

// DeniesLease reports whether the resolution fails the lease closed: only a
// dangling CERTIFICATE-SERIAL binding does (see the precedence comment). The
// SQL claim and the mem claim must both deny on this; the scheduler prefilter
// and the explainers present the same runner as zero-capacity so they agree
// with the claim instead of proposing candidates it will reject.
func (r LiveProfileResolution) DeniesLease() bool {
	return r.Linked && !r.Found && r.Source == ProfileBindingCertSerial
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
// claim's transaction-local resolver. It shares the package rowQuerier
// (pgx.Tx / *pgxpool.Pool) with the reservation reads.
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
// treats it as "no profile" — the registration snapshot applies, never the
// deleted profile (see ResolveLiveProfileBinding for the documented
// dangling-binding policy).
type RunnerProfileLinkStore interface {
	// LinkRunnerProfile binds a runner ID to a profile, replacing any
	// previous binding for the same runner in one statement.
	LinkRunnerProfile(ctx context.Context, runnerID, profileID string) error
	// ProfileForRunnerID resolves the profile bound to a runner ID.
	// found=false means "no binding" or "binding without a profile row";
	// both are treated as unprofiled by the caller.
	ProfileForRunnerID(ctx context.Context, runnerID string) (model.RunnerProfile, bool, error)
	// UnlinkRunnerProfile removes a runner's binding. It is idempotent: a
	// missing row is a successful no-op.
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

// UnlinkRunnerProfile removes a runner's binding; a missing row is a
// successful no-op, so an admin can always assert the unbound state.
func (s *PostgresStore) UnlinkRunnerProfile(ctx context.Context, runnerID string) error {
	if runnerID == "" {
		return fmt.Errorf("storage: runner id is required")
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM runner_profile_links WHERE runner_id=$1`, runnerID)
	return err
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

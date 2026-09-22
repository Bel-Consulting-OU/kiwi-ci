package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

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
// resolves to "not found" (false) and the caller fails closed.
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

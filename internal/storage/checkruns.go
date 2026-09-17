package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
)

// CheckRunStore persists the forge check-run ID of one logical check
// (run + check name). GitHub's POST always creates a NEW check run, so a
// retried publication after a lost outbox ACK must PATCH the previously
// created run instead of duplicating it; that requires the returned ID to
// survive process restarts and be visible to every replica.
type CheckRunStore interface {
	PutCheckRun(ctx context.Context, key, checkRunID string) error
	GetCheckRun(ctx context.Context, key string) (string, bool, error)
}

var _ CheckRunStore = (*PostgresStore)(nil)

// PutCheckRun upserts the mapping (last write wins; a check run is only
// re-created when the previous ID was rejected, in which case the new ID is
// the one to patch).
func (s *PostgresStore) PutCheckRun(ctx context.Context, key, checkRunID string) error {
	if key == "" || checkRunID == "" {
		return fmt.Errorf("storage: check-run store requires key and id")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO check_runs (key, check_run_id, created_at) VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET check_run_id = EXCLUDED.check_run_id, created_at = now()`, key, checkRunID)
	return err
}

func (s *PostgresStore) GetCheckRun(ctx context.Context, key string) (string, bool, error) {
	var id string
	err := s.pool.QueryRow(ctx, `SELECT check_run_id FROM check_runs WHERE key=$1`, key).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return id, true, nil
}

// memStore implementation plus a test-double friendly mutex map.
type checkRunMem struct {
	mu sync.Mutex
	m  map[string]string
}

func (c *checkRunMem) put(key, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]string{}
	}
	c.m[key] = id
	return nil
}

func (c *checkRunMem) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.m[key]
	return id, ok
}

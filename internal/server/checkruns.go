package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// checkRunIDs is the fs-mode mirror of the logical-check → GitHub check-run
// ID mapping; DB mode stores it in PostgreSQL (visible to every replica) and
// the fs mirror is persisted in the data dir with the atomic writer.
type checkRunIDs struct {
	m map[string]string
}

func (s *Server) checkRunKey(runID, name string) string { return runID + "|" + name }

// getCheckRunID resolves the persisted remote check-run ID. A read failure
// is returned, NEVER converted into "no ID": treating an error as a miss
// would POST a duplicate check while the real ID exists.
func (s *Server) getCheckRunID(ctx context.Context, key string) (string, error) {
	if s.DB != nil {
		if store, ok := s.DB.(storage.CheckRunStore); ok {
			id, found, err := store.GetCheckRun(ctx, key)
			if err != nil {
				return "", fmt.Errorf("check-run mapping read: %w", err)
			}
			if found {
				return id, nil
			}
			return "", nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checkRuns == nil {
		return "", nil
	}
	return s.checkRuns.m[key], nil
}

// putCheckRunID persists the mapping. The error is returned so dispatch can
// refuse to ACK: a lost remote ID would make the next retry POST a duplicate
// check. In fs mode the mirror file is written through the atomic writer and
// must succeed before the mapping counts as durable.
func (s *Server) putCheckRunID(ctx context.Context, key, id string) error {
	if key == "" || id == "" {
		return fmt.Errorf("check-run mapping requires key and id")
	}
	if s.DB != nil {
		if store, ok := s.DB.(storage.CheckRunStore); ok {
			return store.PutCheckRun(ctx, key, id)
		}
	}
	s.mu.Lock()
	if s.checkRuns == nil {
		s.checkRuns = &checkRunIDs{m: map[string]string{}}
	}
	prev, hadPrev := s.checkRuns.m[key]
	s.checkRuns.m[key] = id
	dir := s.dataDir
	var snapshot map[string]string
	if dir != "" {
		snapshot = make(map[string]string, len(s.checkRuns.m))
		for k, v := range s.checkRuns.m {
			snapshot[k] = v
		}
	}
	s.mu.Unlock()
	if dir == "" {
		return nil
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		s.mu.Lock()
		if hadPrev {
			s.checkRuns.m[key] = prev
		} else {
			delete(s.checkRuns.m, key)
		}
		s.mu.Unlock()
		return fmt.Errorf("check-run mapping encode: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := storage.AtomicWriteFile(filepath.Join(dir, "check-runs.json"), b, 0o600); err != nil {
		s.mu.Lock()
		if hadPrev {
			s.checkRuns.m[key] = prev
		} else {
			delete(s.checkRuns.m, key)
		}
		s.mu.Unlock()
		return fmt.Errorf("check-run mapping persist: %w", err)
	}
	return nil
}

// lockCheckRunKey serializes publication for one logical check (run+name)
// across dispatchers in this process; the DB mapping row is the cross-replica
// arbiter, and the deterministic mapping key makes a rare cross-replica
// double-create converge on the last write (with a reconciling GET on the
// retry path).
func (s *Server) lockCheckRunKey(key string) func() {
	s.checkRunLocks.mu.Lock()
	if s.checkRunLocks.m == nil {
		s.checkRunLocks.m = map[string]*sync.Mutex{}
	}
	mu, ok := s.checkRunLocks.m[key]
	if !ok {
		mu = &sync.Mutex{}
		s.checkRunLocks.m[key] = mu
	}
	s.checkRunLocks.mu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// loadCheckRunIDs restores the fs-mode mirror at startup; without it a
// restart forgets every remote ID and re-creates checks instead of PATCHing
// them.
func loadCheckRunIDs(dataDir string) map[string]string {
	if dataDir == "" {
		return map[string]string{}
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "check-runs.json"))
	if err != nil {
		return map[string]string{}
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]string{}
	}
	return m
}

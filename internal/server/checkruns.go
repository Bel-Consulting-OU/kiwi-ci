package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// maxCheckRunIDs bounds the fs-mode logical-check → check-run ID mirror. A
// retried publication resolves the mapping to PATCH instead of duplicating a
// check, so dropping a mapping can at worst cause one duplicate publish for a
// very old, already-terminal check. The cap keeps the most recently written
// mappings and evicts oldest-first, so the mirror (and its whole-map rewrite
// per publish) can never grow without bound.
const maxCheckRunIDs = 10000

// checkRunIDs is the fs-mode mirror of the logical-check → GitHub check-run
// ID mapping; DB mode stores it in PostgreSQL (visible to every replica) and
// the fs mirror is persisted in the data dir with the atomic writer.
type checkRunIDs struct {
	m map[string]string
	// order records keys written this process, oldest first, so eviction can
	// drop the least-recently added mapping. Keys loaded from disk have no
	// recorded order and are evicted arbitrarily when the map is full.
	order []string
}

// set records one mapping and prunes the mirror back to maxCheckRunIDs. The
// caller holds s.mu.
func (c *checkRunIDs) set(key, id string) {
	if c.m == nil {
		c.m = map[string]string{}
	}
	if _, exists := c.m[key]; !exists {
		c.order = append(c.order, key)
	}
	c.m[key] = id
	for len(c.m) > maxCheckRunIDs {
		if len(c.order) > 0 {
			victim := c.order[0]
			c.order = c.order[1:]
			delete(c.m, victim)
			continue
		}
		for k := range c.m {
			delete(c.m, k)
			break
		}
	}
}

// checkRunPersistMu serializes mutation + snapshot + write + rollback of the
// whole-map mirror file: two different keys snapshotting independently and
// writing in reverse order could otherwise erase the newer key.
var checkRunPersistMu sync.Mutex

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
// must succeed before the mapping counts as durable. The failure phase decides
// the in-memory outcome: a pre-rename failure rolls the staged mapping back,
// while a post-rename directory-fsync failure (fsutil.Renamed) retains the
// mapping the visible mirror already carries and arms per-directory degraded
// readiness until a same-directory persist reconciles.
func (s *Server) putCheckRunID(ctx context.Context, key, id string) error {
	if key == "" || id == "" {
		return fmt.Errorf("check-run mapping requires key and id")
	}
	if s.DB != nil {
		if store, ok := s.DB.(storage.CheckRunStore); ok {
			return store.PutCheckRun(ctx, key, id)
		}
	}
	checkRunPersistMu.Lock()
	defer checkRunPersistMu.Unlock()
	s.mu.Lock()
	if s.checkRuns == nil {
		s.checkRuns = &checkRunIDs{m: map[string]string{}}
	}
	prev, hadPrev := s.checkRuns.m[key]
	s.checkRuns.set(key, id)
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
		// Pre-rename by construction: nothing was published, so the staged
		// in-memory mapping must not survive.
		s.mu.Lock()
		rollbackCheckRunMappingLocked(s, key, prev, hadPrev)
		s.mu.Unlock()
		return fmt.Errorf("check-run mapping persist: %w", err)
	}
	path := filepath.Join(dir, "check-runs.json")
	if err := storage.AtomicWriteFile(path, b, 0o600); err != nil {
		// A pre-rename failure means the mirror was definitely not replaced:
		// roll the staged mapping back. A post-rename directory-fsync failure
		// (fsutil.Renamed) means the mirror file ALREADY carries the new
		// mapping: rolling memory back would let the next retry POST a
		// duplicate check while the visible file holds the real ID, so the
		// published mapping is retained and readiness stays degraded until a
		// same-directory persist reconciles.
		s.mu.Lock()
		if !fsutil.Renamed(err) {
			rollbackCheckRunMappingLocked(s, key, prev, hadPrev)
		}
		s.mu.Unlock()
		s.noteFilePersistResult(path, err)
		return fmt.Errorf("check-run mapping persist: %w", err)
	}
	s.noteFilePersistResult(path, nil)
	return nil
}

// rollbackCheckRunMappingLocked restores the staged check-run mapping to its
// pre-mutation value. The caller holds s.mu.
func rollbackCheckRunMappingLocked(s *Server, key, prev string, hadPrev bool) {
	if hadPrev {
		s.checkRuns.m[key] = prev
	} else {
		delete(s.checkRuns.m, key)
	}
}

// lockCheckRunKey serializes publication for one logical check (run+name)
// ACROSS REPLICAS: in DB mode the dedicated advisory-lock pool holds a
// namespace/key fence (kiwi-check-run/<mappingKey>) so two replicas cannot
// both read "no mapping" and POST duplicate checks. Memory/fs mode uses a
// refcounted in-process fencer (cancellable, bounded). The returned release
// is idempotent.
func (s *Server) lockCheckRunKey(ctx context.Context, key string) (func(), error) {
	if s.DB != nil {
		if fencer, ok := s.DB.(storage.DigestFenceStore); ok {
			return fencer.AcquireNamedFence(ctx, "check-run", key)
		}
	}
	return s.checkRunFence.Acquire(ctx, key)
}

// loadCheckRunIDs restores the fs-mode mirror at startup. Only a MISSING
// file means "empty": a corrupt or unreadable mirror FAILS startup, because
// silently resetting check identity would re-create every check instead of
// PATCHing it.
func loadCheckRunIDs(dataDir string) (map[string]string, error) {
	if dataDir == "" {
		return map[string]string{}, nil
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "check-runs.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("check-run mirror unreadable: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("check-run mirror corrupt: %w", err)
	}
	return m, nil
}

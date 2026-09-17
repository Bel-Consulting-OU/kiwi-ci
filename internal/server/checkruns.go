package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// checkRunIDs is the fs-mode mirror of the logical-check → GitHub check-run
// ID mapping; DB mode stores it in PostgreSQL (visible to every replica) and
// the fs mirror is persisted in the data dir with the atomic writer.
type checkRunIDs struct {
	m map[string]string
}

func (s *Server) checkRunKey(runID, name string) string { return runID + "|" + name }

func (s *Server) getCheckRunID(ctx context.Context, key string) string {
	if s.DB != nil {
		if store, ok := s.DB.(storage.CheckRunStore); ok {
			id, found, err := store.GetCheckRun(ctx, key)
			if err == nil && found {
				return id
			}
			return ""
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checkRuns == nil {
		return ""
	}
	return s.checkRuns.m[key]
}

func (s *Server) putCheckRunID(ctx context.Context, key, id string) {
	if key == "" || id == "" {
		return
	}
	if s.DB != nil {
		if store, ok := s.DB.(storage.CheckRunStore); ok {
			_ = store.PutCheckRun(ctx, key, id)
			return
		}
	}
	s.mu.Lock()
	if s.checkRuns == nil {
		s.checkRuns = &checkRunIDs{m: map[string]string{}}
	}
	s.checkRuns.m[key] = id
	dir := s.dataDir
	s.mu.Unlock()
	if dir == "" {
		return
	}
	// Best-effort durable mirror; the DB mapping is authoritative when
	// configured.
	s.mu.Lock()
	b, err := json.Marshal(s.checkRuns.m)
	s.mu.Unlock()
	if err != nil {
		return
	}
	_ = os.MkdirAll(dir, 0o700)
	_ = storage.AtomicWriteFile(filepath.Join(dir, "check-runs.json"), b, 0o600)
}

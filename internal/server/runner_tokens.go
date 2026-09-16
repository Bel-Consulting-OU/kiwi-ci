package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// runnerTokensDBTTL bounds how long the "any per-runner tokens
// provisioned" DB answer is cached before re-checking the table.
const runnerTokensDBTTL = 30 * time.Second

// LoadRunnerTokens installs the memory/fs-mode per-runner bearer token
// map (runner ID -> token digest). In DB mode the caller persists the same
// pairs through the RunnerTokenStore instead.
func (s *Server) LoadRunnerTokens(tokens map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runnerTokens == nil {
		s.runnerTokens = map[string]string{}
	}
	for id, digest := range tokens {
		if id != "" && digest != "" {
			s.runnerTokens[digest] = id
		}
	}
}

// runnerBearerID resolves the per-runner bearer identity of a request: the
// SHA-256 digest of the Authorization bearer token looked up in the
// per-runner token store (memory map, or the durable runner_bearer_tokens
// table in DB mode). ok=false means the bearer is not a per-runner token.
func (s *Server) runnerBearerID(r *http.Request) (string, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		return "", false
	}
	digest := auth.TokenDigest(tok)
	if s.DB != nil {
		if ts, ok := s.DB.(storage.RunnerTokenStore); ok {
			id, found, err := ts.RunnerIDForToken(r.Context(), digest)
			if err != nil {
				s.logError("runner token lookup failed", "error", err.Error())
				return "", false
			}
			return id, found
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.runnerTokens[digest]
	return id, ok
}

// runnerTokensConfigured reports whether per-runner bearer credentials are
// provisioned (memory map or DB table). Once per-runner credentials exist
// the shared dev runner token is rejected on runner-tier routes: the
// global token must never impersonate a runner whose identity is
// per-runner-bound.
func (s *Server) runnerTokensConfigured(r *http.Request) bool {
	if s.DB != nil {
		if ts, ok := s.DB.(storage.RunnerTokenStore); ok {
			now := time.Now()
			s.runnerTokensDBMu.Lock()
			if !s.runnerTokensDBAt.IsZero() && now.Sub(s.runnerTokensDBAt) < runnerTokensDBTTL {
				known := s.runnerTokensDBKnown
				s.runnerTokensDBMu.Unlock()
				return known
			}
			s.runnerTokensDBMu.Unlock()
			has, err := ts.HasRunnerTokens(r.Context())
			if err != nil {
				s.logError("runner tokens existence check failed", "error", err.Error())
				return false
			}
			s.runnerTokensDBMu.Lock()
			s.runnerTokensDBKnown = has
			s.runnerTokensDBAt = now
			s.runnerTokensDBMu.Unlock()
			return has
		}
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runnerTokens) > 0
}

// ProvisionRunnerTokensDB persists per-runner bearer credentials into the
// durable runner_bearer_tokens table (production provisioning seam, e.g.
// from auth.runner_tokens_file). tokens maps runner ID -> token digest.
func (s *Server) ProvisionRunnerTokensDB(ctx context.Context, tokens map[string]string) error {
	if s.DB == nil {
		return fmt.Errorf("per-runner bearer tokens require the SQL store")
	}
	ts, ok := s.DB.(storage.RunnerTokenStore)
	if !ok {
		return fmt.Errorf("store does not support per-runner bearer tokens")
	}
	for id, digest := range tokens {
		if err := ts.UpsertRunnerToken(ctx, id, digest); err != nil {
			return fmt.Errorf("provision runner token for %s: %w", id, err)
		}
	}
	return nil
}

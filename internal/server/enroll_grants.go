package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const enrollGrantsFile = "enroll-grants.json"

// EnrollGrant is the server-side state of a single-use runner enrollment
// grant. The raw grant value is never stored: EnrollGrants is keyed by the
// SHA-256 digest of the raw grant, so a data-dir leak does not expose
// usable credentials.
type EnrollGrant struct {
	// ExpiresAt bounds the grant lifetime; expired grants are rejected
	// and pruned.
	ExpiresAt time.Time `json:"expires_at"`
	// BoundLabels, when non-empty, restricts what the enrollment may
	// request: the enroll request must carry every bound label.
	BoundLabels []string `json:"bound_labels,omitempty"`
	// Used marks the grant consumed. Consumption is atomic under s.mu so
	// a racing replay cannot double-enroll.
	Used bool `json:"used"`
}

// enrollTokenFrom extracts the enrollment credential from the Authorization
// bearer or the X-Kiwi-Enroll-Token header.
func enrollTokenFrom(r *http.Request) string {
	if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" {
		return tok
	}
	return strings.TrimPrefix(r.Header.Get("X-Kiwi-Enroll-Token"), "Bearer ")
}

// CreateEnrollGrant mints a single-use enrollment grant: 32 random bytes
// returned raw (hex) to the operator/runner agent, stored server-side only
// as its SHA-256 digest with the given lifetime and label binding. In DB
// mode the grant row is written through the durable EnrollGrantStore so
// every replica honors the same single-use claim.
func (s *Server) CreateEnrollGrant(ttl time.Duration, boundLabels []string) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("enroll grant ttl must be positive")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate enroll grant: %w", err)
	}
	token := hex.EncodeToString(raw)
	expires := time.Now().UTC().Add(ttl)
	if s.DB != nil {
		if gs, ok := s.DB.(storage.EnrollGrantStore); ok {
			if err := gs.PutEnrollGrant(context.Background(), auth.TokenDigest(token), expires, boundLabels); err != nil {
				return "", err
			}
			return token, nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.EnrollGrants == nil {
		s.EnrollGrants = map[string]EnrollGrant{}
	}
	s.pruneEnrollGrantsLocked(time.Now().UTC())
	s.EnrollGrants[auth.TokenDigest(token)] = EnrollGrant{
		ExpiresAt:   expires,
		BoundLabels: append([]string(nil), boundLabels...),
	}
	if err := s.persistEnrollGrants(); err != nil {
		delete(s.EnrollGrants, auth.TokenDigest(token))
		return "", err
	}
	return token, nil
}

// enrollGrantOK reports whether tok corresponds to a grant that is still
// valid: known, unused and unexpired. It is the auth() tier gate; the
// enroll handler re-checks atomically under consumeEnrollGrant to close the
// replay race.
func (s *Server) enrollGrantOK(tok string) bool {
	if tok == "" {
		return false
	}
	digest := auth.TokenDigest(tok)
	if s.DB != nil {
		if gs, ok := s.DB.(storage.EnrollGrantStore); ok {
			rec, found, err := gs.GetEnrollGrant(context.Background(), digest)
			if err != nil || !found {
				return false
			}
			return !rec.Consumed && time.Now().UTC().Before(rec.ExpiresAt)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.EnrollGrants[digest]
	return ok && !g.Used && time.Now().UTC().Before(g.ExpiresAt)
}

// consumeEnrollGrant atomically validates and consumes the grant presented
// by an enroll request: known, unused, unexpired, and — when the grant is
// label-bound — the request must carry every bound label. In DB mode the
// consumption is the store's conditional UPDATE (consumed_at IS NULL AND
// expires_at > now()), so concurrent enrollments of the same grant yield
// exactly one winner; memory mode consumes under s.mu. On success the grant
// is marked used and persisted before any certificate is signed.
func (s *Server) consumeEnrollGrant(tok string, requestLabels []string) error {
	if tok == "" {
		return fmt.Errorf("enrollment grant required")
	}
	digest := auth.TokenDigest(tok)
	if s.DB != nil {
		if gs, ok := s.DB.(storage.EnrollGrantStore); ok {
			rec, err := gs.ConsumeEnrollGrant(context.Background(), digest, "")
			switch {
			case errors.Is(err, storage.ErrNotFound):
				return fmt.Errorf("unknown enrollment grant")
			case errors.Is(err, storage.ErrGrantConsumed):
				return fmt.Errorf("enrollment grant already used")
			case errors.Is(err, storage.ErrGrantExpired):
				return fmt.Errorf("enrollment grant expired")
			case err != nil:
				return fmt.Errorf("consume enrollment grant: %w", err)
			}
			for _, want := range rec.BoundLabels {
				if !containsLabel(requestLabels, want) {
					return fmt.Errorf("enrollment grant requires label %q", want)
				}
			}
			return nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.EnrollGrants[digest]
	if !ok {
		return fmt.Errorf("unknown enrollment grant")
	}
	if g.Used {
		return fmt.Errorf("enrollment grant already used")
	}
	if time.Now().UTC().After(g.ExpiresAt) {
		return fmt.Errorf("enrollment grant expired")
	}
	for _, want := range g.BoundLabels {
		if !containsLabel(requestLabels, want) {
			return fmt.Errorf("enrollment grant requires label %q", want)
		}
	}
	g.Used = true
	s.EnrollGrants[digest] = g
	if err := s.persistEnrollGrants(); err != nil {
		return fmt.Errorf("persist enrollment grants: %w", err)
	}
	return nil
}

// loadEnrollGrants loads the persisted enrollment grants from dataDir,
// pruning expired entries. A missing file leaves an empty map.
func (s *Server) loadEnrollGrants(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dataDir, enrollGrantsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	grants := map[string]EnrollGrant{}
	if err := json.Unmarshal(b, &grants); err != nil {
		return fmt.Errorf("parse enrollment grants: %w", err)
	}
	if s.EnrollGrants == nil {
		s.EnrollGrants = map[string]EnrollGrant{}
	}
	now := time.Now().UTC()
	for k, g := range grants {
		if now.Before(g.ExpiresAt) {
			s.EnrollGrants[k] = g
		}
	}
	return nil
}

// persistEnrollGrants atomically writes the grant state to dataDir
// (digest-keyed only). Memory servers without a data dir keep grants in
// process memory.
func (s *Server) persistEnrollGrants() error {
	if s.dataDir == "" {
		return nil
	}
	return marshalJSONFile(filepath.Join(s.dataDir, enrollGrantsFile), s.EnrollGrants)
}

// pruneEnrollGrantsLocked drops expired grants. Callers hold s.mu.
func (s *Server) pruneEnrollGrantsLocked(now time.Time) {
	for k, g := range s.EnrollGrants {
		if !now.Before(g.ExpiresAt) {
			delete(s.EnrollGrants, k)
		}
	}
}

// containsLabel reports whether labels contains want.
func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

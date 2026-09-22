package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
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
	// BoundLabels is the grant's COMPLETE ALLOWED label set (the field
	// name is retained for wire/storage compatibility; the concept is
	// AllowedLabels). A non-empty list permits exactly those enrollment
	// labels: every label the enroll request carries must appear in this
	// set. An empty/nil list is the legacy no-constraint grant and
	// permits any requested labels. Comparison is exact — byte-for-byte,
	// case-sensitive, no trimming — matching the runner label grammar
	// enforced at registration (runnerLabelRegexp). Enrollment labels are
	// advisory and never become scheduling attributes: those remain
	// server/profile-owned.
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
// as its SHA-256 digest with the given lifetime and allowed-label set. An
// empty allowedLabels list mints the legacy no-label-constraint grant. In DB
// mode the grant row is written through the durable EnrollGrantStore so
// every replica honors the same single-use claim.
//
// ctx is the caller's request context and reaches the durable PutEnrollGrant;
// a canceled context mints nothing (no token is returned, no row written).
// The fs/memory path persists synchronously and is not interruptible, so
// cancellation is honored at the operation boundary, before the map mutation.
//
// The fs persist failure is phase-aware: a pre-rename failure rolls the new
// grant back out of memory (the file never saw it), while a post-rename
// directory-fsync failure RETAINS it, because the visible file already
// carries the grant and memory must not deny what the durable record holds
// (see consumeEnrollGrant for the same rule). Either way the mint returns no
// token and readiness degrades until a later successful persist reconciles.
func (s *Server) CreateEnrollGrant(ctx context.Context, ttl time.Duration, allowedLabels []string) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("enroll grant ttl must be positive")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(randReader, raw); err != nil {
		return "", fmt.Errorf("generate enroll grant: %w", err)
	}
	token := hex.EncodeToString(raw)
	expires := time.Now().UTC().Add(ttl)
	if s.DB != nil {
		// DB mode demands the durable grant store: a grant minted into one
		// replica's memory map could not be consumed on any other replica
		// (HA split-brain), so an unsupported store refuses instead.
		gs, ok := s.DB.(storage.EnrollGrantStore)
		if !ok {
			return "", fmt.Errorf("store does not support enrollment grants")
		}
		if err := gs.PutEnrollGrant(ctx, auth.TokenDigest(token), expires, allowedLabels); err != nil {
			return "", err
		}
		return token, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.EnrollGrants == nil {
		s.EnrollGrants = map[string]EnrollGrant{}
	}
	s.pruneEnrollGrantsLocked(time.Now().UTC())
	digest := auth.TokenDigest(token)
	s.EnrollGrants[digest] = EnrollGrant{
		ExpiresAt:   expires,
		BoundLabels: append([]string(nil), allowedLabels...),
	}
	if err := s.persistEnrollGrants(); err != nil {
		if !fsutil.Renamed(err) {
			// Pre-rename failure: the new grant was definitely not published
			// and the previous file is intact, so roll the in-memory mint
			// back and return no token. The caller never learns a value the
			// store does not contain.
			delete(s.EnrollGrants, digest)
			return "", err
		}
		// Post-rename failure: the grant IS visible in the file with
		// uncertified crash durability. Rolling memory back would leave the
		// visible file holding a live grant memory denies (and a restart
		// would resurrect it), so retain the published grant and let the
		// shared degraded marker fail closed until a later successful
		// persist reconciles. No token is returned: the mint is still not
		// acknowledged.
		return "", err
	}
	return token, nil
}

// enrollGrantOK reports whether tok corresponds to a grant that is still
// valid: known, unused and unexpired. It is the auth() tier gate; the
// enroll handler re-checks atomically under consumeEnrollGrant to close the
// replay race. ctx is the request context: a canceled request reaches no
// store and is never validated (the store read would honor the cancellation
// anyway; the early check also keeps the fs/memory path consistent).
func (s *Server) enrollGrantOK(ctx context.Context, tok string) bool {
	if tok == "" {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	digest := auth.TokenDigest(tok)
	if s.DB != nil {
		gs, ok := s.DB.(storage.EnrollGrantStore)
		if !ok {
			// DB mode without a durable grant store has no grants at all
			// (CreateEnrollGrant refuses); never validate against a
			// replica-local map.
			return false
		}
		rec, found, err := gs.GetEnrollGrant(ctx, digest)
		if err != nil || !found {
			return false
		}
		return !rec.Consumed && time.Now().UTC().Before(rec.ExpiresAt)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.EnrollGrants[digest]
	return ok && !g.Used && time.Now().UTC().Before(g.ExpiresAt)
}

// checkGrantAllowedLabels enforces the grant's allowed-label contract:
// BoundLabels is the COMPLETE ALLOWED set, so every label the enroll request
// carries must appear in it. A grant with an empty allowed set (the legacy
// no-constraint grant) accepts any requested labels. Comparison is exact:
// labels are matched byte-for-byte (case-sensitive, no trimming), the same
// semantics as the runner label grammar (runnerLabelRegexp). The check is
// separate from consumption so a mismatched request never burns the
// single-use grant (memory and DB mode share the contract). Enrollment
// labels are advisory: they are validated here and then discarded, never
// persisted as scheduling attributes (those are server/profile-owned).
func checkGrantAllowedLabels(allowed, requested []string) error {
	if len(allowed) == 0 {
		// Legacy/unconstrained grant: no label contract to enforce.
		return nil
	}
	for _, want := range requested {
		if !containsLabel(allowed, want) {
			return fmt.Errorf("grant does not permit label %q", want)
		}
	}
	return nil
}

// consumeEnrollGrant atomically validates and consumes the grant presented
// by an enroll request: known, unused, unexpired, and — when the grant
// carries an allowed-label set — every requested label must be in that set.
// In DB mode the consumption is the store's conditional UPDATE (consumed_at
// IS NULL AND expires_at > now()), so concurrent enrollments of the same
// grant yield exactly one winner; memory mode consumes under s.mu. Label
// validation happens BEFORE the consume in both modes: a request carrying an
// unpermitted label must not consume (and thereby destroy) the grant it
// cannot use. BoundLabels are immutable for a grant digest, so the pre-read
// cannot be raced into disagreeing with the consumed record. On success the
// grant is marked used and persisted before any certificate is signed.
//
// The memory-mode persist failure handling is phase-aware, because the
// memory-only / disk-only asymmetry it used to assume does not hold across
// the rename (fsutil.AtomicWriteError):
//
//   - pre-rename failure (fsutil.NotPublished): nothing was published, the
//     previous file is intact, and the pre-consume entry is restored — the
//     grant stays consumable and no certificate is issued.
//   - post-rename failure (fsutil.Renamed, the parent-directory fsync): the
//     visible file already records the consumption, so the CONSUMED
//     in-memory state is retained (never rolled back to the permissive
//     unused entry), a replay is refused, readiness stays degraded until a
//     later successful persist reconciles, and still no certificate is
//     issued because the caller returns on this error.
//
// ctx is the enroll REQUEST context and threads into both durable store
// calls. A canceled request aborts the consumption before the conditional
// UPDATE (or before the fs/memory mutation): the grant stays consumable and
// the handler returns without signing any certificate, so no ACK ever
// outlives a persistence that did not happen.
func (s *Server) consumeEnrollGrant(ctx context.Context, tok string, requestLabels []string) error {
	if tok == "" {
		return fmt.Errorf("enrollment grant required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	digest := auth.TokenDigest(tok)
	if s.DB != nil {
		gs, ok := s.DB.(storage.EnrollGrantStore)
		if !ok {
			// DB mode without a durable grant store has no grants at all.
			return fmt.Errorf("store does not support enrollment grants")
		}
		rec, found, gerr := gs.GetEnrollGrant(ctx, digest)
		if gerr != nil {
			return fmt.Errorf("read enrollment grant: %w", gerr)
		}
		if !found {
			return fmt.Errorf("unknown enrollment grant")
		}
		if rec.Consumed {
			return fmt.Errorf("enrollment grant already used")
		}
		if !time.Now().UTC().Before(rec.ExpiresAt) {
			return fmt.Errorf("enrollment grant expired")
		}
		if err := checkGrantAllowedLabels(rec.BoundLabels, requestLabels); err != nil {
			return err
		}
		if _, err := gs.ConsumeEnrollGrant(ctx, digest, ""); err != nil {
			switch {
			case errors.Is(err, storage.ErrNotFound):
				return fmt.Errorf("unknown enrollment grant")
			case errors.Is(err, storage.ErrGrantConsumed):
				return fmt.Errorf("enrollment grant already used")
			case errors.Is(err, storage.ErrGrantExpired):
				return fmt.Errorf("enrollment grant expired")
			default:
				return fmt.Errorf("consume enrollment grant: %w", err)
			}
		}
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, existed := s.EnrollGrants[digest]
	if !existed {
		return fmt.Errorf("unknown enrollment grant")
	}
	g := prev
	if g.Used {
		return fmt.Errorf("enrollment grant already used")
	}
	if time.Now().UTC().After(g.ExpiresAt) {
		return fmt.Errorf("enrollment grant expired")
	}
	if err := checkGrantAllowedLabels(g.BoundLabels, requestLabels); err != nil {
		return err
	}
	g.Used = true
	s.EnrollGrants[digest] = g
	if err := s.persistEnrollGrants(); err != nil {
		if !fsutil.Renamed(err) {
			// Pre-rename failure: the consumption was definitely not
			// published, so restore the pre-consume entry. A restart (which
			// reloads the on-disk, still-unused grant) and a retry then see
			// the grant as consumable, and no certificate is signed for a
			// consume that never reached the file.
			s.EnrollGrants[digest] = prev
			return fmt.Errorf("persist enrollment grants: %w", err)
		}
		// Post-rename failure: the file ALREADY shows the grant as used
		// (only its crash durability is uncertified). Restoring the
		// permissive unused entry would make memory disagree with the
		// visible file in the dangerous direction: a replay could burn the
		// grant again in memory while the durable record says used, and a
		// restart would flip the decision. Keep the CONSUMED state, keep the
		// degraded readiness marker armed (persistEnrollGrants folded it),
		// and still sign no certificate: the caller returns on this error.
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

// persistEnrollGrantsFunc is the persistence seam for grant state.
// Production always uses the filesystem writer below; tests replace it to
// inject persistence failures. It is invoked only while s.mu is held, and
// tests restore it before any further grant state can be persisted.
var persistEnrollGrantsFunc = func(s *Server) error {
	if s.dataDir == "" {
		return nil
	}
	return marshalJSONFile(filepath.Join(s.dataDir, enrollGrantsFile), s.EnrollGrants)
}

// persistEnrollGrants durably writes the grant state to dataDir
// (digest-keyed only) through marshalJSONFile, i.e. fsutil.AtomicWriteFile's
// unique temp file, checked file fsync/close, rename and parent-directory
// fsync. Every outcome is folded into the shared degraded marker
// (noteFilePersistResult): a published-but-uncertified failure arms it and
// any successful persist — including a deliberate re-persist used as the
// reconciliation step — heals it.
//
// The error is a typed *fsutil.AtomicWriteError and the callers decide by
// phase: the mint path rolls a new grant back only on a pre-rename failure
// (returns no token either way), and the consume path keeps the consumed
// entry once the rename has published it, restoring the unused entry only
// for a pre-rename failure. Memory servers without a data dir keep grants in
// process memory (no file, no phase).
func (s *Server) persistEnrollGrants() error {
	err := persistEnrollGrantsFunc(s)
	path := ""
	if s.dataDir != "" {
		path = filepath.Join(s.dataDir, enrollGrantsFile)
	}
	s.noteFilePersistResult(path, err)
	return err
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

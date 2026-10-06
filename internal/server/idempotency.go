package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// errIdempotencyKeyConflict is the ingress-level conflict for a reused
// Idempotency-Key whose canonical request digest differs from the receipt's.
// It maps to HTTP 409 with reason IDEMPOTENCY_KEY_REUSED; the second request
// is never enqueued.
var errIdempotencyKeyConflict = errors.New("idempotency key was already used for a different request")

// maxIdempotencyKeyLen bounds the client key so a receipt row and the fs
// snapshot stay small; the bound is deliberately generous for opaque UUIDs
// and prefixed trace keys.
const maxIdempotencyKeyLen = 200

// validIdempotencyKey accepts a non-empty visible-ASCII token without
// whitespace. The key is used only as an opaque lookup value, but bounding it
// here keeps a hostile client from growing the receipt table or snapshot with
// an enormous key.
func validIdempotencyKey(key string) bool {
	if key == "" || len(key) > maxIdempotencyKeyLen {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return false
		}
	}
	return true
}

// readIdempotencyKey extracts and validates the Idempotency-Key header.
// present=false means the request is not idempotency-tracked; ok=false means
// an invalid header was answered with 400.
func readIdempotencyKey(w http.ResponseWriter, r *http.Request) (key string, present, ok bool) {
	key = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		return "", false, true
	}
	if !validIdempotencyKey(key) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  fmt.Sprintf("Idempotency-Key must be 1..%d visible ASCII characters without whitespace", maxIdempotencyKeyLen),
			"reason": "INVALID_IDEMPOTENCY_KEY",
		})
		return "", false, false
	}
	return key, true, true
}

// submissionIdempotencyDigest computes the canonical digest an
// Idempotency-Key is bound to. kind distinguishes a direct submission from a
// rerun (a key reused across the two route families conflicts), and the
// digest covers the CLIENT-VISIBLE fields only: server-derived identity,
// trust and scheduling claims never enter it, so an internal replay of the
// same client request always matches. json.Marshal sorts map keys, so the
// metadata map is canonical. sourceRunID is empty for a direct submission and
// the source run ID for a rerun.
func submissionIdempotencyDigest(in *SubmitRun, kind, sourceRunID string) string {
	canonical, err := json.Marshal(struct {
		Kind              string            `json:"kind"`
		SourceRunID       string            `json:"source_run_id,omitempty"`
		RepoURL           string            `json:"repo_url"`
		RepoFullName      string            `json:"repo_full_name,omitempty"`
		Ref               string            `json:"ref"`
		SHA               string            `json:"sha,omitempty"`
		Event             string            `json:"event,omitempty"`
		Pipeline          string            `json:"pipeline"`
		ChangedFiles      []string          `json:"changed_files,omitempty"`
		ChangedFilesKnown bool              `json:"changed_files_known,omitempty"`
		Metadata          map[string]string `json:"metadata,omitempty"`
	}{Kind: kind, SourceRunID: sourceRunID, RepoURL: in.RepoURL, RepoFullName: in.RepoFullName,
		Ref: in.Ref, SHA: in.SHA, Event: in.Event, Pipeline: in.Pipeline,
		ChangedFiles: in.ChangedFiles, ChangedFilesKnown: in.ChangedFilesKnown, Metadata: in.Metadata})
	if err != nil {
		// The struct is composed of marshalable values only; an error is
		// impossible, but fail closed with the empty digest (which the
		// caller rejects) instead of a digest that could collide.
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// runIdempotencyReceiptKey namespaces one client key by its canonical
// repository scope for the fs-mode receipt map. NUL cannot occur in either
// part, so the composite is unambiguous.
func runIdempotencyReceiptKey(repoID, key string) string {
	return repoID + "\x00" + key
}

// restoreRunIdempotencyLocked installs the durable fs-mode receipts restored
// from a snapshot, dropping malformed rows and entries past
// storage.IdempotencyReceiptTTL so the restored set stays bounded. The
// caller holds s.mu.
func (s *Server) restoreRunIdempotencyLocked(in map[string]storage.IdempotencyReceipt) {
	if len(in) == 0 {
		return
	}
	now := time.Now().UTC()
	for _, rec := range in {
		if rec.RepoID == "" || rec.Key == "" || rec.RunID == "" || rec.Digest == "" {
			continue
		}
		if !rec.CreatedAt.IsZero() && now.Sub(rec.CreatedAt) > storage.IdempotencyReceiptTTL {
			continue
		}
		s.idempotency[runIdempotencyReceiptKey(rec.RepoID, rec.Key)] = rec
	}
}

// checkRunIdempotencyDB runs the pre-compile replay fast path for a direct
// submission or rerun carrying an Idempotency-Key. It returns:
//
//   - (run, true, nil): the key replays to this already-durable run;
//   - (zero, false, nil): no receipt exists (or the DB is not attached), so
//     the caller proceeds to compile + the in-transaction claim;
//   - (zero, false, err): a digest conflict (409), an unsupported store
//     (fail closed as a durability error) or a store failure.
//
// The fast path deliberately runs BEFORE pipeline resolution and admission:
// a replay must return the ORIGINAL run even when the repository policy or
// components changed after the first submission, and must never re-run
// external resolution for an operation that already committed.
func (s *Server) checkRunIdempotencyDB(ctx context.Context, scope, key, digest string) (model.Run, bool, error) {
	if s.DB == nil {
		return model.Run{}, false, nil
	}
	rs, ok := s.DB.(storage.RunIdempotencyStore)
	if !ok {
		return model.Run{}, false, notDurable(fmt.Errorf("storage: attached store lacks the run-idempotency contract; refusing to ignore Idempotency-Key"))
	}
	runID, storedDigest, found, err := rs.FindRunIdempotency(ctx, scope, key)
	if err != nil {
		return model.Run{}, false, err
	}
	if !found {
		return model.Run{}, false, nil
	}
	if storedDigest != digest {
		return model.Run{}, false, errIdempotencyKeyConflict
	}
	prior, err := s.DB.GetRun(ctx, runID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return model.Run{}, false, fmt.Errorf("%w: receipt run %s is no longer retained; retry with a new key", errIdempotencyKeyConflict, runID)
		}
		return model.Run{}, false, err
	}
	return prior, true, nil
}

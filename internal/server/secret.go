package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// SecretRequest asks the control plane to deliver one declared secret value
// for a job under an active lease. EphemeralPublic is the runner's fresh
// X25519 public key (base64 standard encoding, exactly 32 bytes decoded); the
// sealed value can only be opened by the holder of the matching private key.
type SecretRequest struct {
	RunnerID        string `json:"runner_id"`
	LeaseToken      string `json:"lease_token"`
	LeaseGeneration int64  `json:"lease_generation"`
	Name            string `json:"name"`
	EphemeralPublic string `json:"ephemeral_public"`
}

// SecretResponse carries a sealed secret value and the lease generation it
// was issued under.
type SecretResponse struct {
	Ciphertext      string `json:"ciphertext"`
	EphemeralPublic string `json:"ephemeral_public"`
	Nonce           string `json:"nonce"`
	LeaseGeneration int64  `json:"lease_generation"`
}

// secretAADPrefix tags the additional authenticated data bound into every
// sealed secret envelope. The AAD is "kiwi-secret-v1\x00<runnerID>\x00
// <jobID>\x00<generation>\x00<name>": an envelope can only be opened in the
// exact delivery context it was sealed for.
const secretAADPrefix = "kiwi-secret-v1\x00"

// secretReceiptsFile is the durable one-time delivery receipt journal under
// dataDir in MEMORY mode (dev/local deployments). It is an append-only JSONL
// journal: each delivery appends one {key} line and each compensating release
// appends one {key,del:true} tombstone, so a delivery costs O(1) write+fsync
// instead of a full-file rewrite. Compaction periodically rewrites the
// journal (atomically) to only its live, bounded receipt set. A legacy
// pre-journal JSON array at the same path is detected and migrated on load.
// The receipt set is data-dir state: a server restarted on the same dataDir
// refuses replays of already-delivered secrets. In DB mode the once-only
// record is the SQL secret_claims table (storage.SecretClaimStore) instead;
// the value never leaves the broker.
const secretReceiptsFile = "secrets-receipts.json"

// secretReceiptsMaxEntries bounds the live receipt set kept in memory and on
// disk after compaction. A receipt only matters while a (job, lease
// generation, name) could still be re-requested; the cap keeps the most
// recent receipts and drops older ones, so neither memory nor the journal
// grows without bound.
const secretReceiptsMaxEntries = 16384

// secretReceiptsCompactBytes is the journal size that triggers compaction.
// It bounds tombstones and re-added keys (which do not grow the live set) as
// well as the live set itself.
const secretReceiptsCompactBytes = 1 << 20

// secretReceiptRecord is one JSONL journal line. Del marks a compensating
// removal of an earlier add.
type secretReceiptRecord struct {
	Key string `json:"key"`
	Del bool   `json:"del,omitempty"`
}

// secretAAD renders the authenticated data for a delivery.
func secretAAD(runnerID, jobID string, generation int64, name string) []byte {
	return []byte(secretAADPrefix + runnerID + "\x00" + jobID + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + name)
}

// secretReceiptKey keys one delivery receipt: a secret is delivered at most
// once per (job, lease generation, name).
func secretReceiptKey(jobID string, generation int64, name string) string {
	return jobID + "|" + strconv.FormatInt(generation, 10) + "|" + name
}

// loadSecretReceipts reads the durable delivery receipts from dataDir. A
// missing file starts an empty receipt set. A corrupt journal is refused
// (fail closed) so a truncated receipt store can never silently allow
// replays. A legacy JSON array from before the append-only journal is
// migrated to the journal form immediately so later appends never mix
// formats.
func (s *Server) loadSecretReceipts(dataDir string) error {
	s.secretReceipts = map[string]bool{}
	if dataDir == "" {
		return nil
	}
	path := filepath.Join(dataDir, secretReceiptsFile)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '[' {
		// Legacy JSON array: load and rewrite as the journal form so later
		// appends cannot mix formats. The rewrite targets the same path the
		// caller passed, independent of s.dataDir (which may not be wired
		// yet during construction).
		var keys []string
		if err := json.Unmarshal(trimmed, &keys); err != nil {
			return err
		}
		for _, k := range keys {
			if strings.TrimSpace(k) != "" {
				s.secretReceipts[k] = true
			}
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, k := range keys {
			if strings.TrimSpace(k) == "" {
				continue
			}
			if err := enc.Encode(secretReceiptRecord{Key: k}); err != nil {
				return err
			}
		}
		return fsutil.AtomicWriteFile(path, buf.Bytes(), 0o600)
	}
	return s.replaySecretReceiptsJournalLocked(trimmed)
}

// replaySecretReceiptsJournalLocked replays journal bytes into
// s.secretReceipts. A malformed line fails closed: a receipt store that
// cannot be parsed must never be treated as empty (which would allow
// replays).
func (s *Server) replaySecretReceiptsJournalLocked(b []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec secretReceiptRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("secret receipts: corrupt journal line: %w", err)
		}
		if rec.Key == "" {
			continue
		}
		if rec.Del {
			delete(s.secretReceipts, rec.Key)
		} else {
			s.secretReceipts[rec.Key] = true
		}
	}
	return sc.Err()
}

// appendSecretReceiptLocked appends one journal record and fsyncs it,
// returning whether the record is PUBLISHED (visible in the file). A
// pre-publication failure leaves the file unchanged; a parent-directory
// fsync failure means the line is visible but its crash durability is
// uncertified, so the caller must retain the in-memory decision and arm
// degraded readiness. The caller must hold s.mu.
func (s *Server) appendSecretReceiptLocked(rec secretReceiptRecord) (published bool, err error) {
	if s.dataDir == "" {
		return true, nil
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return false, err
	}
	path := filepath.Join(s.dataDir, secretReceiptsFile)
	line, err := json.Marshal(rec)
	if err != nil {
		return false, err
	}
	line = append(line, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	before, statErr := f.Seek(0, io.SeekEnd)
	n, writeErr := f.Write(line)
	syncErr := f.Sync()
	if writeErr == nil && n != len(line) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		// Truncate a possibly partial line back to its pre-append size so the
		// journal never carries a malformed record that would fail later
		// loads closed.
		if statErr == nil {
			_ = f.Truncate(before)
			_ = f.Sync()
		}
		_ = f.Close()
		return false, writeErr
	}
	if syncErr != nil {
		_ = f.Close()
		return false, syncErr
	}
	closeErr := f.Close()
	if closeErr != nil {
		return false, closeErr
	}
	if err := fsutil.SyncDir(s.dataDir); err != nil {
		if s.stateDegraded.dirs.arm(canonicalPersistDir(path)) {
			s.logError("secret receipts: directory fsync failed; readiness degraded until a same-directory persist succeeds", "error", err.Error())
		}
		return true, err
	}
	s.noteFilePersistResult(path, nil)
	return true, nil
}

// persistSecretReceiptsLocked atomically writes the receipt set to dataDir.
// The caller must hold s.mu. A write failure is returned so callers fail
// closed: a delivery whose receipt cannot be persisted is refused.
//
// It is also the compaction primitive: it replays the append-only journal
// into an ordered live set, keeps the most recent secretReceiptsMaxEntries
// receipts, writes them as a fresh journal atomically, and replaces the
// in-memory set so both the file and memory are bounded. The caller must hold
// s.mu.
func (s *Server) persistSecretReceiptsLocked() error {
	if s.dataDir == "" {
		return nil
	}
	path := filepath.Join(s.dataDir, secretReceiptsFile)
	keys, err := s.compactedReceiptKeysLocked(path)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	next := make(map[string]bool, len(keys))
	for _, k := range keys {
		if err := enc.Encode(secretReceiptRecord{Key: k}); err != nil {
			return err
		}
		next[k] = true
	}
	err = fsutil.AtomicWriteFile(path, buf.Bytes(), 0o600)
	// Pre-rename failure: the receipt file is untouched. Post-rename
	// directory-fsync failure (fsutil.Renamed): the new receipt set is
	// visible but its crash durability is uncertified, so arm the data
	// directory and keep readiness degraded until a same-directory persist
	// succeeds.
	s.noteFilePersistResult(path, err)
	if err != nil {
		return err
	}
	s.secretReceipts = next
	return nil
}

// compactedReceiptKeysLocked replays the journal at path into an ordered live
// receipt set and returns the most recent secretReceiptsMaxEntries keys. A
// missing file yields the in-memory set (so an in-memory-only server still
// compacts). A corrupt file fails closed rather than dropping receipts.
func (s *Server) compactedReceiptKeysLocked(path string) ([]string, error) {
	order := []string{}
	live := map[string]int{}
	if b, err := os.ReadFile(path); err == nil {
		trimmed := bytes.TrimSpace(b)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var keys []string
			if err := json.Unmarshal(trimmed, &keys); err != nil {
				return nil, err
			}
			for _, k := range keys {
				if k == "" {
					continue
				}
				if _, ok := live[k]; !ok {
					order = append(order, k)
					live[k] = len(order) - 1
				}
			}
		} else {
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				line := bytes.TrimSpace(sc.Bytes())
				if len(line) == 0 {
					continue
				}
				var rec secretReceiptRecord
				if err := json.Unmarshal(line, &rec); err != nil {
					return nil, fmt.Errorf("secret receipts: corrupt journal line: %w", err)
				}
				if rec.Key == "" {
					continue
				}
				if rec.Del {
					if i, ok := live[rec.Key]; ok {
						order[i] = ""
						delete(live, rec.Key)
					}
					continue
				}
				if i, ok := live[rec.Key]; ok {
					order[i] = ""
				}
				order = append(order, rec.Key)
				live[rec.Key] = len(order) - 1
			}
			if err := sc.Err(); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		// No file: compact the in-memory set (arbitrary order).
		for k := range s.secretReceipts {
			order = append(order, k)
		}
	}
	compacted := make([]string, 0, len(live))
	for _, k := range order {
		if k != "" {
			compacted = append(compacted, k)
		}
	}
	if len(compacted) > secretReceiptsMaxEntries {
		compacted = compacted[len(compacted)-secretReceiptsMaxEntries:]
	}
	return compacted, nil
}

// maybeCompactSecretReceiptsLocked compacts when the live set or the journal
// has grown past its bound. The caller must hold s.mu. A compaction failure
// is logged, never fatal: the append that triggered it is already durable.
func (s *Server) maybeCompactSecretReceiptsLocked() {
	if s.dataDir == "" {
		return
	}
	over := len(s.secretReceipts) > secretReceiptsMaxEntries
	if !over {
		if fi, err := os.Stat(filepath.Join(s.dataDir, secretReceiptsFile)); err == nil && fi.Size() > secretReceiptsCompactBytes {
			over = true
		}
	}
	if !over {
		return
	}
	if err := s.persistSecretReceiptsLocked(); err != nil {
		s.logError("secret receipts: compaction failed", "error", err.Error())
	}
}

// markSecretDelivered records the delivery receipt durably. It reports
// false when the receipt already existed (replay); a non-nil error means
// the receipt could not be persisted and the delivery must fail closed.
func (s *Server) markSecretDelivered(key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secretReceipts == nil {
		s.secretReceipts = map[string]bool{}
	}
	if s.secretReceipts[key] {
		return false, nil
	}
	s.secretReceipts[key] = true
	published, err := s.appendSecretReceiptLocked(secretReceiptRecord{Key: key})
	if err != nil {
		// A pre-publication failure means the journal definitely does not
		// carry the receipt: roll the in-memory mark back so the delivery can
		// be retried once the data dir is healthy again. A published-but-
		// uncertain failure (the parent-directory fsync) means the journal
		// ALREADY carries the receipt: retain it so memory matches the
		// visible file and keep readiness degraded until a same-directory
		// persist reconciles.
		if !published {
			delete(s.secretReceipts, key)
		}
		return false, err
	}
	s.maybeCompactSecretReceiptsLocked()
	return true, nil
}

// releaseSecretReceipt removes a receipt recorded for a delivery whose
// resolution subsequently failed, so a failed resolution never consumes the
// delivery. A persistence failure is returned so the caller fails closed.
func (s *Server) releaseSecretReceipt(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secretReceipts == nil {
		s.secretReceipts = map[string]bool{}
	}
	delete(s.secretReceipts, key)
	published, err := s.appendSecretReceiptLocked(secretReceiptRecord{Key: key, Del: true})
	if err != nil {
		if !published {
			// The tombstone is not durable: keep the receipt so a restart
			// cannot replay a delivery the failed release did not undo.
			s.secretReceipts[key] = true
		}
		return err
	}
	s.maybeCompactSecretReceiptsLocked()
	return nil
}

// resolveBroker resolves a secret through the configured broker. A OneTime
// wrapper is unwrapped: the server-owned receipt (keyed by job, generation
// and secret name) is the durable once-only record, and the broker stays
// pure retrieval.
func (s *Server) resolveBroker(r *http.Request, name string, scope secretbroker.SecretScope) (string, error) {
	broker := s.SecretBroker
	if ot, ok := broker.(*secretbroker.OneTime); ok && ot.Inner != nil {
		broker = ot.Inner
	}
	value, err := broker.Resolve(r.Context(), name, scope)
	if err != nil {
		if errors.Is(err, secretbroker.ErrAlreadyDelivered) {
			return "", err
		}
		return "", err
	}
	return value, nil
}

// declaredSecrets compiles the deduplicated union of the run's global
// secrets and every step secret declared by one job. It is the allowlist
// issueSecret enforces per job, so a secret declared on one step can never
// be requested through a job that does not declare it.
func declaredSecrets(spec *pipeline.Spec, job pipeline.Job) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, name := range spec.Secrets {
		add(name)
	}
	for _, st := range job.Steps {
		for _, name := range st.Secrets {
			add(name)
		}
	}
	return out
}

// issueSecret delivers one declared secret to the runner holding the job's
// active lease, sealed with an ephemeral X25519 key the runner just minted.
// The value never reaches server logs, audit records, or persistence. The
// durable delivery receipt is server-owned and keyed by (jobID, generation,
// secret name): in DB mode it is the SQL secret_claims row claimed through
// storage.SecretClaimStore BEFORE the broker is resolved (claim-first), and
// in memory mode it is the secrets-receipts.json file under dataDir. A
// replayed delivery conflicts (409); a claim/persistence failure fails
// closed (503/500) without ever returning an envelope. The sealed envelope
// is bound to the delivery context via AEAD authenticated data.
func (s *Server) issueSecret(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in SecretRequest
	if !decode(w, r, &in) {
		return
	}
	j, authErr := s.authorizeRunnerLease(r, in.RunnerID, in.LeaseToken, in.LeaseGeneration)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return
	}
	// Defense in depth: admission already strips secrets from untrusted
	// pipelines, and the declared allowlist is compiled at enqueue time.
	if !j.Trusted || !containsString(j.DeclaredSecrets, in.Name) {
		http.Error(w, "secret not declared for this job", http.StatusForbidden)
		return
	}
	if s.SecretBroker == nil {
		http.Error(w, "secret broker not configured", http.StatusServiceUnavailable)
		return
	}
	receiptKey := secretReceiptKey(jobID, in.LeaseGeneration, in.Name)
	if s.DB != nil {
		// DB mode: the durable once-only record is the SQL claim row.
		// Claim FIRST: exactly one of concurrent or replayed deliveries of
		// the same (job, generation, name) wins, and only a successful
		// durable claim can return the sealed envelope. Claim errors fail
		// closed (503): an envelope is never delivered without a durable
		// claim.
		cs, ok := s.DB.(storage.SecretClaimStore)
		if !ok {
			http.Error(w, "secret delivery claims unavailable", http.StatusServiceUnavailable)
			return
		}
		claimed, err := cs.ClaimSecretDelivery(r.Context(), jobID, in.LeaseGeneration, in.Name)
		if err != nil {
			http.Error(w, "secret delivery claim failed", http.StatusServiceUnavailable)
			return
		}
		if !claimed {
			http.Error(w, "secret already delivered for this lease generation", http.StatusConflict)
			return
		}
		s.deliverSecret(w, r, j, in, jobID, true)
		return
	}
	// Memory mode: the receipt file under dataDir is the once-only record.
	// A persistence failure is a server-side durability failure, not a client
	// error: answer 503 with the fixed opaque body so the runner retries
	// instead of the delivery being read as invalid — never log-and-continue
	// for delivery state. A post-rename failure retains the published receipt
	// (see markSecretDelivered), so a same-directory persist reconciles it.
	claimed, err := s.markSecretDelivered(receiptKey)
	if err != nil {
		s.serverError(w, r, http.StatusServiceUnavailable, err, "state not durable")
		return
	}
	if !claimed {
		http.Error(w, "secret already delivered for this lease generation", http.StatusConflict)
		return
	}
	s.deliverSecret(w, r, j, in, jobID, false)
}

// deliverSecret resolves the broker, seals the value for the runner's
// ephemeral key, and writes the response for an already-claimed delivery.
// Any post-claim failure releases the claim (SQL row or memory receipt) so
// a failed resolution never consumes the once-only delivery. The release
// is a compensation that must outlive the request: it runs on its own
// short-lived context, because a client disconnect cancels r.Context() and
// must never strand a consumed claim.
func (s *Server) deliverSecret(w http.ResponseWriter, r *http.Request, j model.Job, in SecretRequest, jobID string, dbClaimed bool) {
	release := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if dbClaimed {
			if rel, ok := s.DB.(storage.SecretClaimReleaser); ok {
				if err := rel.ReleaseSecretDelivery(ctx, jobID, in.LeaseGeneration, in.Name); err != nil {
					s.logError("secret delivery: claim release failed", "error", err.Error())
				}
			}
			return
		}
		if err := s.releaseSecretReceipt(secretReceiptKey(jobID, in.LeaseGeneration, in.Name)); err != nil {
			s.logError("secret receipts: release persist failed", "error", err.Error())
		}
	}
	value, err := s.resolveBroker(r, in.Name, secretbroker.SecretScope{Repository: j.RepoURL, Environment: j.Environment, Trusted: j.Trusted})
	if err != nil {
		release()
		if errors.Is(err, secretbroker.ErrAlreadyDelivered) {
			http.Error(w, "secret already delivered", http.StatusConflict)
			return
		}
		http.Error(w, "secret resolution failed", http.StatusInternalServerError)
		return
	}
	pubRaw, err := base64.StdEncoding.DecodeString(in.EphemeralPublic)
	if err != nil || len(pubRaw) != 32 {
		release()
		http.Error(w, "invalid ephemeral_public: want base64-encoded 32 bytes", http.StatusBadRequest)
		return
	}
	var pub [32]byte
	copy(pub[:], pubRaw)
	aad := secretAAD(in.RunnerID, jobID, in.LeaseGeneration, in.Name)
	enc, err := secretbroker.SealEnvelope([]byte(value), pub, aad)
	if err != nil {
		release()
		http.Error(w, "sealing secret failed", http.StatusInternalServerError)
		return
	}
	// The audit trail records the secret name only, never the value.
	s.auditLocked("secret.issued", in.RunnerID, j.RunID, j.ID, "secret delivered", map[string]string{"secret": in.Name, "generation": strconv.FormatInt(in.LeaseGeneration, 10)})
	s.metricAdd("kiwi_secret_deliveries_total", 1, nil)
	generation := j.LeaseGeneration
	writeJSON(w, http.StatusOK, SecretResponse{
		Ciphertext:      base64.StdEncoding.EncodeToString(enc.Ciphertext),
		EphemeralPublic: base64.StdEncoding.EncodeToString(enc.EphemeralPublic),
		Nonce:           base64.StdEncoding.EncodeToString(enc.Nonce),
		LeaseGeneration: generation,
	})
}

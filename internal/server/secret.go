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
	"regexp"
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
// record is the SQL secret_claims row inserted by
// storage.SecretIssuanceStore.CommitSecretIssuance instead; the value never
// leaves the broker.
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
	return s.markSecretDeliveredLocked(key)
}

// markSecretDeliveredLocked is markSecretDelivered with the caller already
// holding s.mu, so the receipt decision can be made in the same critical
// section that re-validates the lease at commit time. The caller must hold
// s.mu.
func (s *Server) markSecretDeliveredLocked(key string) (bool, error) {
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
	return s.releaseSecretReceiptLocked(key)
}

// releaseSecretReceiptLocked is releaseSecretReceipt with the caller already
// holding s.mu. The caller must hold s.mu.
func (s *Server) releaseSecretReceiptLocked(key string) error {
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

// secretNameRequestRegexp pins the secret identifier grammar at the delivery
// boundary to the same env-safe grammar pipeline validation enforces
// (pipeline.secretNameRegexp). A malformed name is answered 400 BEFORE any
// store or broker work, because the broker and the claim are keyed by it.
var secretNameRequestRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// issueSecret delivers one declared secret to the runner holding the job's
// active lease, sealed with an ephemeral X25519 key the runner just minted.
// The value never reaches server logs, audit records, or persistence.
//
// The handler order is deliberate:
//
//  1. cheap preliminary lease authentication (authorizeRunnerLease);
//  2. the declaration allowlist and trust bit from that preliminary read;
//  3. request-shape validation (secret-name grammar, ephemeral public key)
//     BEFORE any store or broker work;
//  4. broker resolution (may span seconds) and in-memory envelope sealing;
//  5. CommitSecretIssuance — the FINAL authority: under the job's row lock (or
//     s.mu in memory mode) it re-evaluates the whole lease predicate against
//     the locked job and the database clock, and records the once-only claim
//     plus the durable secret.issued audit in one unit;
//  6. only then is the ciphertext written.
//
// Because the arbitration happens at commit time, a cancellation,
// completion, expiry or lease replacement that lands during step 4 can no
// longer be outrun: the commit refuses with a typed error mapped to 409 and
// no envelope leaves the server. Because broker resolution unwraps OneTime as
// pure retrieval, two concurrent requests may both retrieve the value, but
// only one commit wins and only that one returns the envelope.
func (s *Server) issueSecret(w http.ResponseWriter, r *http.Request) {
	var in SecretRequest
	if !decode(w, r, &in) {
		return
	}
	j, authErr := s.authorizeRunnerLease(r, in.RunnerID, in.LeaseToken, in.LeaseGeneration)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return
	}
	// A superseded registration session may not retrieve secrets for the
	// remaining lease TTL even though the lease token still validates.
	if !s.requireCurrentRunnerIncarnation(w, r, in.RunnerID) {
		return
	}
	// Defense in depth: admission already strips secrets from untrusted
	// pipelines, and the declared allowlist is compiled at enqueue time. The
	// commit re-checks both against the locked job.
	if !j.Trusted || !containsString(j.DeclaredSecrets, in.Name) {
		http.Error(w, "secret not declared for this job", http.StatusForbidden)
		return
	}
	if s.SecretBroker == nil {
		http.Error(w, "secret broker not configured", http.StatusServiceUnavailable)
		return
	}
	// Reject malformed requests before any store or broker work: an invalid
	// name must never select a broker lookup or touch the claim store, and an
	// invalid ephemeral key must never trigger a resolution.
	if !secretNameRequestRegexp.MatchString(in.Name) {
		http.Error(w, "invalid secret name", http.StatusBadRequest)
		return
	}
	pubRaw, err := base64.StdEncoding.DecodeString(in.EphemeralPublic)
	if err != nil || len(pubRaw) != 32 {
		http.Error(w, "invalid ephemeral_public: want base64-encoded 32 bytes", http.StatusBadRequest)
		return
	}
	s.deliverSecret(w, r, j, in, pubRaw)
}

// secretScopeForJob builds the broker scope from the job. Repository is the
// CANONICAL authorization identity every policy/quota/cache decision uses
// (PolicyRepoID first, then the RepoID/URL/full-name derivation) — never the
// clone transport URL, which for a fork PR can point at a different
// repository than the one whose policy governs the job. The checkout
// coordinate is carried separately for scope-aware brokers that need it.
func secretScopeForJob(j model.Job) secretbroker.SecretScope {
	return secretbroker.SecretScope{
		Repository:            storage.RepoIDForJob(j),
		CheckoutRepositoryURL: j.RepoURL,
		Environment:           j.Environment,
		Trusted:               j.Trusted,
	}
}

// deliverSecret resolves the broker, seals the value for the runner's
// ephemeral key, crosses the commit-time issuance authority and only then
// writes the response. The sealed envelope is kept in memory until the commit
// succeeds; a refusal or a commit failure returns no envelope at all.
func (s *Server) deliverSecret(w http.ResponseWriter, r *http.Request, j model.Job, in SecretRequest, pubRaw []byte) {
	if len(pubRaw) != 32 {
		// Defense in depth for direct callers: issueSecret already validated
		// the encoded key before any broker work.
		http.Error(w, "invalid ephemeral_public: want base64-encoded 32 bytes", http.StatusBadRequest)
		return
	}
	value, err := s.resolveBroker(r, in.Name, secretScopeForJob(j))
	if err != nil {
		if errors.Is(err, secretbroker.ErrAlreadyDelivered) {
			http.Error(w, "secret already delivered", http.StatusConflict)
			return
		}
		http.Error(w, "secret resolution failed", http.StatusInternalServerError)
		return
	}
	var pub [32]byte
	copy(pub[:], pubRaw)
	aad := secretAAD(in.RunnerID, j.ID, in.LeaseGeneration, in.Name)
	enc, err := secretbroker.SealEnvelope([]byte(value), pub, aad)
	if err != nil {
		http.Error(w, "sealing secret failed", http.StatusInternalServerError)
		return
	}
	// FINAL AUTHORITY. The preliminary read authorized the request cheaply,
	// but broker resolution and sealing can span seconds, and a concurrent
	// cancel/complete/expiry/replacement could land in that window. The
	// commit re-evaluates the entire predicate against the authoritative job
	// and records the once-only claim plus the durable audit atomically
	// (PostgreSQL: row locked FOR UPDATE; memory/fs: s.mu held). The sealed
	// envelope is discarded on any refusal.
	req := storage.SecretIssuance{
		JobID:           j.ID,
		RunnerID:        in.RunnerID,
		LeaseGeneration: in.LeaseGeneration,
		LeaseTokenHash:  j.LeaseTokenHash,
		SecretName:      in.Name,
		IssuedAt:        time.Now().UTC(),
	}
	if err := s.commitSecretIssuance(r.Context(), req); err != nil {
		s.secretIssuanceRefusal(w, r, err)
		return
	}
	s.metricAdd("kiwi_secret_deliveries_total", 1, nil)
	writeJSON(w, http.StatusOK, SecretResponse{
		Ciphertext:      base64.StdEncoding.EncodeToString(enc.Ciphertext),
		EphemeralPublic: base64.StdEncoding.EncodeToString(enc.EphemeralPublic),
		Nonce:           base64.StdEncoding.EncodeToString(enc.Nonce),
		LeaseGeneration: in.LeaseGeneration,
	})
}

// errSecretIssuanceStoreUnsupported reports a DB-mode store that cannot commit
// deliveries transactionally. It is a wiring failure (the startup capability
// check refuses such a store) and is answered 503, never by delivering without
// the lease-fenced claim and audit.
var errSecretIssuanceStoreUnsupported = errors.New("server: database store lacks SecretIssuanceStore")

// errSecretIssuanceReceipt marks a failure to durably record the once-only
// delivery receipt in memory/fs mode. The handler answers 503 and no envelope
// is returned: a delivery whose receipt is not durable is refused.
var errSecretIssuanceReceipt = errors.New("secret issuance receipt not durable")

// errSecretIssuanceAudit marks a failure to durably append the secret.issued
// audit event on the in-process (memory/fs) commit path. The handler answers
// 500 and the envelope is never returned.
var errSecretIssuanceAudit = errors.New("secret issuance audit failed")

// commitSecretIssuance runs the commit-time delivery authority for the
// server's storage mode: DB mode delegates to the store's transactional
// CommitSecretIssuance, while memory/fs mode executes the identical predicate,
// once-only receipt and durable audit append under s.mu.
func (s *Server) commitSecretIssuance(ctx context.Context, req storage.SecretIssuance) error {
	if s.DB != nil {
		store, ok := s.DB.(storage.SecretIssuanceStore)
		if !ok {
			return errSecretIssuanceStoreUnsupported
		}
		return store.CommitSecretIssuance(ctx, req)
	}
	return s.commitSecretIssuanceLocked(req)
}

// commitSecretIssuanceLocked is the memory/fs-mode delivery authority. The
// authoritative job, the predicate, the once-only receipt and the durable
// audit append all happen inside ONE s.mu critical section, so a concurrent
// server mutation (cancel/complete/revoke/re-lease) can never interleave
// between the check and the delivery record. The receipt is written first so
// a returned envelope always has a durable claim; if the audit append then
// fails the receipt is released again (best effort) so a failed delivery does
// not consume it. A store without an audit sink (pure in-memory dev mode) has
// no durable trail to require; every store-backed mode appends the event and
// fails the delivery closed when the append fails.
func (s *Server) commitSecretIssuanceLocked(req storage.SecretIssuance) error {
	if err := storage.ValidateSecretIssuanceRequest(req); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[req.JobID]
	if !ok {
		return storage.ErrNotFound
	}
	if err := storage.ValidateSecretIssuance(storage.LockedSecretLeaseForJob(j), req, time.Now().UTC()); err != nil {
		return err
	}
	key := secretReceiptKey(req.JobID, req.LeaseGeneration, req.SecretName)
	claimed, err := s.markSecretDeliveredLocked(key)
	if err != nil {
		return fmt.Errorf("%w: %v", errSecretIssuanceReceipt, err)
	}
	if !claimed {
		return fmt.Errorf("%w: job %s generation %d secret %q", storage.ErrSecretIssuanceDuplicate, req.JobID, req.LeaseGeneration, req.SecretName)
	}
	if s.store != nil {
		auditID, err := newID()
		if err == nil {
			err = s.store.AppendAudit(storage.SecretIssuanceAuditEvent(req, j.RunID, auditID))
		}
		if err != nil {
			if relErr := s.releaseSecretReceiptLocked(key); relErr != nil {
				s.logError("secret issuance: receipt release failed after audit failure", "error", relErr.Error())
			}
			return fmt.Errorf("%w: %v", errSecretIssuanceAudit, err)
		}
	}
	return nil
}

// secretIssuanceRefusal maps a commit-time delivery refusal onto its HTTP
// response: a vanished job is 404; every lease/declaration refusal and the
// once-only duplicate is 409 (the same semantics as a stale lease at request
// start); an unsupported store or an undurable receipt is 503; an audit
// failure is 500. Anything else fails closed (503) — never an envelope.
func (s *Server) secretIssuanceRefusal(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		http.NotFound(w, r)
	case errors.Is(err, storage.ErrSecretIssuanceDuplicate):
		http.Error(w, "secret already delivered for this lease generation", http.StatusConflict)
	case errors.Is(err, storage.ErrSecretIssuanceRevoked),
		errors.Is(err, storage.ErrSecretIssuanceRunner),
		errors.Is(err, storage.ErrSecretIssuanceGeneration),
		errors.Is(err, storage.ErrSecretIssuanceToken),
		errors.Is(err, storage.ErrSecretIssuanceExpired),
		errors.Is(err, storage.ErrSecretIssuanceUntrusted),
		errors.Is(err, storage.ErrSecretIssuanceNotDeclared):
		http.Error(w, "job lease is not active", http.StatusConflict)
	case errors.Is(err, storage.ErrSecretIssuanceInvalid):
		http.Error(w, "invalid secret issuance request", http.StatusBadRequest)
	case errors.Is(err, errSecretIssuanceStoreUnsupported):
		s.serverError(w, r, http.StatusServiceUnavailable, err, "secret delivery store unavailable")
	case errors.Is(err, errSecretIssuanceReceipt):
		s.serverError(w, r, http.StatusServiceUnavailable, err, "state not durable")
	case errors.Is(err, errSecretIssuanceAudit):
		s.internalError(w, r, err, "secret delivery audit failed")
	default:
		s.serverError(w, r, http.StatusServiceUnavailable, err, "secret delivery not durable")
	}
}

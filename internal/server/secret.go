package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

// secretReceiptsFile is the durable one-time delivery receipt file under
// dataDir in MEMORY mode (dev/local deployments). The receipt set is
// data-dir state: a server restarted on the same dataDir refuses replays of
// already-delivered secrets. In DB mode the once-only record is the SQL
// secret_claims table (storage.SecretClaimStore) instead; the value never
// leaves the broker.
const secretReceiptsFile = "secrets-receipts.json"

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
// missing file starts an empty receipt set; a corrupt file is refused so a
// truncated receipt store can never silently allow replays.
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
	var keys []string
	if err := json.Unmarshal(b, &keys); err != nil {
		return err
	}
	for _, k := range keys {
		if strings.TrimSpace(k) != "" {
			s.secretReceipts[k] = true
		}
	}
	return nil
}

// persistSecretReceiptsLocked atomically writes the receipt set to dataDir.
// The caller must hold s.mu. A write failure is returned so callers fail
// closed: a delivery whose receipt cannot be persisted is refused.
func (s *Server) persistSecretReceiptsLocked() error {
	if s.dataDir == "" {
		return nil
	}
	keys := make([]string, 0, len(s.secretReceipts))
	for k := range s.secretReceipts {
		keys = append(keys, k)
	}
	return marshalJSONFile(filepath.Join(s.dataDir, secretReceiptsFile), keys)
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
	if err := s.persistSecretReceiptsLocked(); err != nil {
		// Roll the in-memory mark back so the delivery can be retried once
		// the data dir is healthy again.
		delete(s.secretReceipts, key)
		return false, err
	}
	return true, nil
}

// releaseSecretReceipt removes a receipt recorded for a delivery whose
// resolution subsequently failed, so a failed resolution never consumes the
// delivery. A persistence failure is returned so the caller fails closed.
func (s *Server) releaseSecretReceipt(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secretReceipts, key)
	return s.persistSecretReceiptsLocked()
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
	// A persistence failure fails closed (500): no delivery state, no
	// envelope — never log-and-continue for delivery state.
	claimed, err := s.markSecretDelivered(receiptKey)
	if err != nil {
		http.Error(w, "secret delivery receipt persistence failed", http.StatusInternalServerError)
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
// a failed resolution never consumes the once-only delivery.
func (s *Server) deliverSecret(w http.ResponseWriter, r *http.Request, j model.Job, in SecretRequest, jobID string, dbClaimed bool) {
	release := func() {
		if dbClaimed {
			if rel, ok := s.DB.(storage.SecretClaimReleaser); ok {
				if err := rel.ReleaseSecretDelivery(r.Context(), jobID, in.LeaseGeneration, in.Name); err != nil {
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

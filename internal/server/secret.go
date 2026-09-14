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
	"time"

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
// dataDir (both dev and DB mode; the value never leaves the broker).
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
// The caller must hold s.mu.
func (s *Server) persistSecretReceiptsLocked() {
	if s.dataDir == "" {
		return
	}
	keys := make([]string, 0, len(s.secretReceipts))
	for k := range s.secretReceipts {
		keys = append(keys, k)
	}
	if err := marshalJSONFile(filepath.Join(s.dataDir, secretReceiptsFile), keys); err != nil {
		s.logError("secret receipts: persist failed", "error", err.Error())
	}
}

// markSecretDelivered records the delivery receipt durably. It reports
// false when the receipt already existed (replay).
func (s *Server) markSecretDelivered(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secretReceipts == nil {
		s.secretReceipts = map[string]bool{}
	}
	if s.secretReceipts[key] {
		return false
	}
	s.secretReceipts[key] = true
	s.persistSecretReceiptsLocked()
	return true
}

// releaseSecretReceipt removes a receipt recorded for a delivery whose
// resolution subsequently failed, so a failed resolution never consumes the
// delivery.
func (s *Server) releaseSecretReceipt(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secretReceipts, key)
	s.persistSecretReceiptsLocked()
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
// secret name): replaying the same delivery conflicts (409), and the sealed
// envelope is bound to the delivery context via AEAD authenticated data.
func (s *Server) issueSecret(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in SecretRequest
	if !decode(w, r, &in) {
		return
	}
	now := time.Now().UTC()
	j, err := s.jobForLease(r.Context(), jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.verifyRunnerIdentity(r, in.RunnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
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
	// The server-owned receipt is the once-only record: the same (job,
	// lease generation, secret) is delivered exactly once, even across
	// control-plane restarts.
	receiptKey := secretReceiptKey(jobID, in.LeaseGeneration, in.Name)
	if !s.markSecretDelivered(receiptKey) {
		http.Error(w, "secret already delivered for this lease generation", http.StatusConflict)
		return
	}
	value, err := s.resolveBroker(r, in.Name, secretbroker.SecretScope{Repository: j.RepoURL, Environment: j.Environment, Trusted: j.Trusted})
	if err != nil {
		// A failed resolution does not consume the delivery.
		s.releaseSecretReceipt(receiptKey)
		if errors.Is(err, secretbroker.ErrAlreadyDelivered) {
			http.Error(w, "secret already delivered", http.StatusConflict)
			return
		}
		http.Error(w, "secret resolution failed", http.StatusInternalServerError)
		return
	}
	pubRaw, err := base64.StdEncoding.DecodeString(in.EphemeralPublic)
	if err != nil || len(pubRaw) != 32 {
		s.releaseSecretReceipt(receiptKey)
		http.Error(w, "invalid ephemeral_public: want base64-encoded 32 bytes", http.StatusBadRequest)
		return
	}
	var pub [32]byte
	copy(pub[:], pubRaw)
	aad := secretAAD(in.RunnerID, jobID, in.LeaseGeneration, in.Name)
	enc, err := secretbroker.SealEnvelope([]byte(value), pub, aad)
	if err != nil {
		s.releaseSecretReceipt(receiptKey)
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

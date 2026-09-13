package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/kiwici/kiwi/internal/pipeline"
	"github.com/kiwici/kiwi/internal/secretbroker"
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
// The value never reaches server logs, audit records, or persistence.
func (s *Server) issueSecret(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in SecretRequest
	if !decode(w, r, &in) {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		s.mu.Unlock()
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	// Defense in depth: admission already strips secrets from untrusted
	// pipelines, and the declared allowlist is compiled at enqueue time.
	if !j.Trusted || !containsString(j.DeclaredSecrets, in.Name) {
		s.mu.Unlock()
		http.Error(w, "secret not declared for this job", http.StatusForbidden)
		return
	}
	if s.SecretBroker == nil {
		s.mu.Unlock()
		http.Error(w, "secret broker not configured", http.StatusServiceUnavailable)
		return
	}
	value, err := s.SecretBroker.Resolve(r.Context(), in.Name, secretbroker.SecretScope{Repository: j.RepoURL, Environment: j.Environment, Trusted: j.Trusted})
	if err != nil {
		s.mu.Unlock()
		if errors.Is(err, secretbroker.ErrAlreadyDelivered) {
			http.Error(w, "secret already delivered", http.StatusConflict)
			return
		}
		http.Error(w, "secret resolution failed", http.StatusInternalServerError)
		return
	}
	pubRaw, err := base64.StdEncoding.DecodeString(in.EphemeralPublic)
	if err != nil || len(pubRaw) != 32 {
		s.mu.Unlock()
		http.Error(w, "invalid ephemeral_public: want base64-encoded 32 bytes", http.StatusBadRequest)
		return
	}
	var pub [32]byte
	copy(pub[:], pubRaw)
	enc, err := secretbroker.SealEnvelope([]byte(value), pub)
	if err != nil {
		s.mu.Unlock()
		http.Error(w, "sealing secret failed", http.StatusInternalServerError)
		return
	}
	// The audit trail records the secret name only, never the value.
	s.auditLocked("secret.issued", in.RunnerID, j.RunID, j.ID, "secret delivered", map[string]string{"secret": in.Name})
	generation := j.LeaseGeneration
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, SecretResponse{
		Ciphertext:      base64.StdEncoding.EncodeToString(enc.Ciphertext),
		EphemeralPublic: base64.StdEncoding.EncodeToString(enc.EphemeralPublic),
		Nonce:           base64.StdEncoding.EncodeToString(enc.Nonce),
		LeaseGeneration: generation,
	})
}

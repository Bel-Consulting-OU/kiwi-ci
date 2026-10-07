package secretbroker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// remoteSecretAADPrefix is the additional authenticated data prefix bound
// into every remotely delivered secret envelope. It must match the control
// plane's secretAADPrefix: an envelope can only be opened in the exact
// (runner, job, generation, name) delivery context it was sealed for.
const remoteSecretAADPrefix = "kiwi-secret-v1\x00"

// maxSecretDeliveryBytes bounds the JSON delivery body read from the control
// plane so a misbehaving endpoint can never make the runner buffer an
// unbounded response.
const maxSecretDeliveryBytes = 1 << 20

// RemoteProvider resolves secrets through the control plane's lease-bound
// delivery endpoint (POST /api/v1/jobs/{id}/secrets). Every request mints a
// fresh ephemeral X25519 keypair, so a delivery can only be opened by the
// process that requested it and only in the exact job/lease context it was
// sealed for. It is the only secret provider distributed runners use; host
// environment and Keychain providers are local-CLI-only.
type RemoteProvider struct {
	Server, Token   string
	JobID           string
	LeaseToken      string
	LeaseGeneration int64
	RunnerID        string
	Client          *http.Client
}

// secretDeliveryAAD renders the authenticated data for one remote delivery.
// The layout mirrors the server's secretAAD: prefix, runner, job, lease
// generation, and secret name, each NUL-separated.
func secretDeliveryAAD(runnerID, jobID string, generation int64, name string) []byte {
	return []byte(remoteSecretAADPrefix + runnerID + "\x00" + jobID + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + name)
}

// client returns a hardened copy of the configured HTTP client: bounded
// total timeout, hardened transport and redirect refusal. Credential-bearing
// secret traffic must never follow redirects to a different origin; a
// redirect response is surfaced as an error instead.
func (p *RemoteProvider) client() *http.Client {
	return providerClient(p.Client)
}

// Get implements secrets.Provider: it requests one declared secret under
// the job's active lease, sealed with a per-request ephemeral X25519 key.
func (p *RemoteProvider) Get(ctx context.Context, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("remote secret: empty secret name")
	}
	priv, err := generateX25519Key()
	if err != nil {
		return "", classError("remote", ErrUnavailable, "generate ephemeral key", err)
	}
	ephemeralPublic := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	body, err := json.Marshal(map[string]any{
		"runner_id":        p.RunnerID,
		"lease_token":      p.LeaseToken,
		"lease_generation": p.LeaseGeneration,
		"name":             name,
		"ephemeral_public": ephemeralPublic,
	})
	if err != nil {
		return "", classError("remote", ErrUnavailable, "marshal request", err)
	}
	endpoint := strings.TrimRight(p.Server, "/") + "/api/v1/jobs/" + p.JobID + "/secrets"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", classError("remote", ErrUnavailable, "build request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return "", transportError("remote", "request failed", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSecretDeliveryBytes+1))
	if err != nil {
		return "", transportError("remote", "read response", err)
	}
	if len(raw) > maxSecretDeliveryBytes {
		return "", classError("remote", ErrMalformedResponse, fmt.Sprintf("delivery for secret %q exceeds %d bytes", name, maxSecretDeliveryBytes), nil)
	}
	if resp.StatusCode != http.StatusOK {
		// Never echo the response body: the error travels into runner/job
		// error surfaces. Only the status class and code are included.
		return "", classError("remote", httpStatusClass(resp.StatusCode), fmt.Sprintf("secret %q: status %d", name, resp.StatusCode), nil)
	}
	var delivery struct {
		Ciphertext      string `json:"ciphertext"`
		EphemeralPublic string `json:"ephemeral_public"`
		Nonce           string `json:"nonce"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	if err := json.Unmarshal(raw, &delivery); err != nil {
		return "", decodeError("remote", fmt.Sprintf("secret %q: decode delivery", name), err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(delivery.Ciphertext)
	if err != nil {
		return "", decodeError("remote", fmt.Sprintf("secret %q: decode ciphertext", name), err)
	}
	ephPub, err := base64.StdEncoding.DecodeString(delivery.EphemeralPublic)
	if err != nil {
		return "", decodeError("remote", fmt.Sprintf("secret %q: decode ephemeral public", name), err)
	}
	nonce, err := base64.StdEncoding.DecodeString(delivery.Nonce)
	if err != nil {
		return "", decodeError("remote", fmt.Sprintf("secret %q: decode nonce", name), err)
	}
	if delivery.LeaseGeneration != p.LeaseGeneration {
		return "", classError("remote", ErrMalformedResponse, fmt.Sprintf("secret %q: delivery sealed for lease generation %d, want %d", name, delivery.LeaseGeneration, p.LeaseGeneration), nil)
	}
	aad := secretDeliveryAAD(p.RunnerID, p.JobID, p.LeaseGeneration, name)
	var own [32]byte
	copy(own[:], priv.Bytes())
	plain, err := OpenEnvelope(EncryptedDelivery{
		Ciphertext:      ciphertext,
		EphemeralPublic: ephPub,
		Nonce:           nonce,
		LeaseGeneration: delivery.LeaseGeneration,
	}, own, aad)
	if err != nil {
		return "", decodeError("remote", fmt.Sprintf("secret %q: open envelope", name), err)
	}
	return string(plain), nil
}

var _ secrets.Provider = (*RemoteProvider)(nil)

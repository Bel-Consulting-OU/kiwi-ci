package secretbroker

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// client returns a redirect-refusing copy of the configured HTTP client.
// Credential-bearing secret traffic must never follow redirects to a
// different origin; a redirect response is surfaced as an error instead.
func (p *RemoteProvider) client() *http.Client {
	base := p.Client
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Second}
	}
	c := *base
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// Get implements secrets.Provider: it requests one declared secret under
// the job's active lease, sealed with a per-request ephemeral X25519 key.
func (p *RemoteProvider) Get(ctx context.Context, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("remote secret: empty secret name")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("remote secret: generate ephemeral key: %w", err)
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
		return "", err
	}
	endpoint := strings.TrimRight(p.Server, "/") + "/api/v1/jobs/" + p.JobID + "/secrets"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSecretDeliveryBytes+1))
	if err != nil {
		return "", err
	}
	if len(raw) > maxSecretDeliveryBytes {
		return "", fmt.Errorf("remote secret %q: delivery exceeds %d bytes", name, maxSecretDeliveryBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remote secret %q: %s: %s", name, resp.Status, strings.TrimSpace(string(raw)))
	}
	var delivery struct {
		Ciphertext      string `json:"ciphertext"`
		EphemeralPublic string `json:"ephemeral_public"`
		Nonce           string `json:"nonce"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	if err := json.Unmarshal(raw, &delivery); err != nil {
		return "", fmt.Errorf("remote secret %q: decode delivery: %w", name, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(delivery.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("remote secret %q: decode ciphertext: %w", name, err)
	}
	ephPub, err := base64.StdEncoding.DecodeString(delivery.EphemeralPublic)
	if err != nil {
		return "", fmt.Errorf("remote secret %q: decode ephemeral public: %w", name, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(delivery.Nonce)
	if err != nil {
		return "", fmt.Errorf("remote secret %q: decode nonce: %w", name, err)
	}
	if delivery.LeaseGeneration != p.LeaseGeneration {
		return "", fmt.Errorf("remote secret %q: delivery sealed for lease generation %d, want %d", name, delivery.LeaseGeneration, p.LeaseGeneration)
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
		return "", fmt.Errorf("remote secret %q: open envelope: %w", name, err)
	}
	return string(plain), nil
}

var _ secrets.Provider = (*RemoteProvider)(nil)

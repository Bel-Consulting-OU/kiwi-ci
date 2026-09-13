package cache

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const ManifestPayloadType = "application/vnd.kiwi.cache-manifest+json"

var sha256RE = regexp.MustCompile(`^[a-f0-9]{64}$`)

// CacheManifest binds a logical cache key to an immutable payload digest so
// concurrent writers can race on the key-to-manifest mapping while the payload
// itself can never be corrupted or mixed.
type CacheManifest struct {
	Version     int       `json:"version"`
	Repository  string    `json:"repository"`
	TrustDomain string    `json:"trust_domain"`
	LogicalKey  string    `json:"logical_key"`
	BlobSHA256  string    `json:"blob_sha256"`
	BlobSize    int64     `json:"blob_size"`
	ProducerRun string    `json:"producer_run"`
	ProducerJob string    `json:"producer_job"`
	CreatedAt   time.Time `json:"created_at"`
}

type manifestEnvelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

func ValidateManifest(m CacheManifest) error {
	if m.Version != 1 {
		return fmt.Errorf("cache: unsupported manifest version %d", m.Version)
	}
	if !sha256RE.MatchString(m.BlobSHA256) {
		return fmt.Errorf("cache: invalid blob digest")
	}
	if strings.TrimSpace(m.LogicalKey) == "" {
		return fmt.Errorf("cache: empty logical key")
	}
	if m.BlobSize < 0 {
		return fmt.Errorf("cache: negative blob size")
	}
	return nil
}

// SignManifest returns a DSSE-like signed envelope over the canonical manifest
// JSON.
func SignManifest(m CacheManifest, keyID string, priv ed25519.PrivateKey) ([]byte, error) {
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	preauth := dssePAE(ManifestPayloadType, payload)
	sig := ed25519.Sign(priv, preauth)
	return json.Marshal(manifestEnvelope{
		PayloadType: ManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
}

func VerifyManifest(b []byte, pub ed25519.PublicKey) (CacheManifest, error) {
	var env manifestEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return CacheManifest{}, fmt.Errorf("cache: decode envelope: %w", err)
	}
	if env.PayloadType != ManifestPayloadType {
		return CacheManifest{}, fmt.Errorf("cache: unexpected payload type %q", env.PayloadType)
	}
	if len(env.Signatures) == 0 {
		return CacheManifest{}, fmt.Errorf("cache: manifest has no signature")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return CacheManifest{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return CacheManifest{}, err
	}
	if !ed25519.Verify(pub, dssePAE(env.PayloadType, payload), sig) {
		return CacheManifest{}, fmt.Errorf("cache: invalid manifest signature")
	}
	var m CacheManifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return CacheManifest{}, fmt.Errorf("cache: decode manifest: %w", err)
	}
	if err := ValidateManifest(m); err != nil {
		return CacheManifest{}, err
	}
	return m, nil
}

func ManifestDigest(m CacheManifest) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func dssePAE(t string, p []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(t), t, len(p), p))
}

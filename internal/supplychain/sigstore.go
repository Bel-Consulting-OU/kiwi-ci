package supplychain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const (
	// AttestationPayloadType is the DSSE payload type kiwi attestations use.
	AttestationPayloadType = "application/vnd.kiwi.attestation+json"
	// StatementType is the in-toto statement type of kiwi attestations.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateType identifies the kiwi attestation predicate schema.
	PredicateType = "https://kiwi.dev/attestation/v1"
	// SigstoreBundleMediaType is the only accepted Sigstore bundle media type.
	SigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	maxEnvelopeBytes = 8 << 20
	maxLogEntries    = 4
)

// Attestation pairs a DSSE envelope with the claims it was produced under.
type Attestation struct {
	Envelope []byte
	Digest   string
	Issuer   string
	Identity string
}

// SignOptions carries optional predicate claims applied at signing time.
type SignOptions struct {
	Issuer    string
	Identity  string
	Builder   string
	CreatedAt time.Time
}

// VerifyOptions declares non-empty claims that must all match the statement
// predicate exactly.
type VerifyOptions struct {
	Digest     string
	Issuer     string
	Identity   string
	Repository string
	Ref        string
}

// SigstoreVerifyConfig is the verification gate configuration for Sigstore
// bundles: every non-empty expectation must match, and TrustedKey pins the
// only acceptable verification key.
type SigstoreVerifyConfig struct {
	ExpectedIssuer   string
	ExpectedIdentity string
	ExpectedRepo     string
	ExpectedRef      string
	TrustedKey       ed25519.PublicKey
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Predicate struct {
	Issuer     string    `json:"issuer"`
	Identity   string    `json:"identity"`
	Repository string    `json:"repository,omitempty"`
	Ref        string    `json:"ref,omitempty"`
	Builder    string    `json:"builder,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// SignArtifact produces a DSSE envelope over a Sigstore-style in-toto
// statement binding artifactDigest to repo/ref and the optional identity
// claims.
func SignArtifact(priv ed25519.PrivateKey, keyID, artifactDigest, repo, ref string, opts SignOptions) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("supplychain: invalid Ed25519 private key")
	}
	if artifactDigest == "" {
		return nil, fmt.Errorf("supplychain: empty artifact digest")
	}
	subjectName := repo
	if ref != "" {
		subjectName += "@" + ref
	}
	when := opts.CreatedAt
	if when.IsZero() {
		when = time.Now().UTC()
	}
	st := Statement{
		Type: StatementType,
		Subject: []Subject{{
			Name:   subjectName,
			Digest: map[string]string{"sha256": artifactDigest},
		}},
		PredicateType: PredicateType,
		Predicate: Predicate{
			Issuer:     opts.Issuer,
			Identity:   opts.Identity,
			Repository: repo,
			Ref:        ref,
			Builder:    opts.Builder,
			CreatedAt:  when,
		},
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, pae(AttestationPayloadType, payload))
	env := dsseEnvelope{
		PayloadType: AttestationPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []dsseSignature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	return json.Marshal(env)
}

// VerifyAttestation strictly parses and verifies a kiwi DSSE attestation
// envelope against the given public key and returns the statement.
func VerifyAttestation(envelope []byte, pub ed25519.PublicKey, want VerifyOptions) (*Statement, error) {
	if len(envelope) > maxEnvelopeBytes {
		return nil, fmt.Errorf("supplychain: envelope exceeds %d byte limit", maxEnvelopeBytes)
	}
	env, payload, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("supplychain: invalid Ed25519 public key")
	}
	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("supplychain: missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, fmt.Errorf("supplychain: decode signature: %w", err)
	}
	if !ed25519.Verify(pub, pae(env.PayloadType, payload), sig) {
		return nil, fmt.Errorf("supplychain: invalid attestation signature")
	}
	st, err := parseStatement(payload)
	if err != nil {
		return nil, err
	}
	if err := checkClaims(st, want); err != nil {
		return nil, err
	}
	return st, nil
}

type sigstoreBundle struct {
	MediaType            string                     `json:"mediaType"`
	VerificationMaterial bundleVerificationMaterial `json:"verificationMaterial"`
	DSSEEnvelope         *dsseEnvelope              `json:"dsseEnvelope"`
}

type bundleVerificationMaterial struct {
	PublicKey  *bundlePublicKey `json:"publicKey"`
	LogEntries []bundleLogEntry `json:"logEntries"`
}

type bundlePublicKey struct {
	RawBytes   string `json:"rawBytes"`
	KeyDetails string `json:"keyDetails"`
}

type bundleLogEntry struct {
	IntegratedTime int64  `json:"integratedTime"`
	BodyHash       string `json:"bodyHash"`
}

// VerifySigstoreBundle strictly parses a Sigstore bundle (DSSE envelope plus
// verification material). The envelope signature must verify against the
// configured trusted key or the key embedded in the bundle, the statement
// digest must match artifactDigest, every non-empty expectation must match,
// and any log entries must carry an integratedTime and a body hash equal to
// the SHA-256 of the statement payload. Any parse inconsistency fails the
// verification.
func VerifySigstoreBundle(bundle []byte, artifactDigest string, verifyCfg SigstoreVerifyConfig) error {
	if len(bundle) > maxEnvelopeBytes {
		return fmt.Errorf("supplychain: bundle exceeds %d byte limit", maxEnvelopeBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(bundle))
	var b sigstoreBundle
	if err := dec.Decode(&b); err != nil {
		return fmt.Errorf("supplychain: decode bundle: %w", err)
	}
	if err := rejectTrailing(dec); err != nil {
		return fmt.Errorf("supplychain: decode bundle: %w", err)
	}
	if b.MediaType != SigstoreBundleMediaType {
		return fmt.Errorf("supplychain: unexpected bundle media type %q", b.MediaType)
	}
	if b.DSSEEnvelope == nil {
		return fmt.Errorf("supplychain: bundle has no DSSE envelope")
	}
	env := b.DSSEEnvelope
	if env.PayloadType != AttestationPayloadType {
		return fmt.Errorf("supplychain: unexpected payload type %q", env.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("supplychain: decode payload: %w", err)
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("supplychain: missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return fmt.Errorf("supplychain: decode signature: %w", err)
	}
	var pub ed25519.PublicKey
	if len(verifyCfg.TrustedKey) > 0 {
		pub = verifyCfg.TrustedKey
	} else {
		if b.VerificationMaterial.PublicKey == nil || b.VerificationMaterial.PublicKey.RawBytes == "" {
			return fmt.Errorf("supplychain: bundle has no verification key")
		}
		raw, derr := base64.StdEncoding.DecodeString(b.VerificationMaterial.PublicKey.RawBytes)
		if derr != nil {
			return fmt.Errorf("supplychain: decode embedded key: %w", derr)
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("supplychain: embedded key is not Ed25519")
		}
		pub = ed25519.PublicKey(raw)
	}
	if !ed25519.Verify(pub, pae(env.PayloadType, payload), sig) {
		return fmt.Errorf("supplychain: invalid attestation signature")
	}
	st, err := parseStatement(payload)
	if err != nil {
		return err
	}
	if err := checkClaims(st, VerifyOptions{
		Digest:     artifactDigest,
		Issuer:     verifyCfg.ExpectedIssuer,
		Identity:   verifyCfg.ExpectedIdentity,
		Repository: verifyCfg.ExpectedRepo,
		Ref:        verifyCfg.ExpectedRef,
	}); err != nil {
		return err
	}
	if len(b.VerificationMaterial.LogEntries) > maxLogEntries {
		return fmt.Errorf("supplychain: bundle has %d log entries, limit is %d", len(b.VerificationMaterial.LogEntries), maxLogEntries)
	}
	sum := sha256.Sum256(payload)
	for _, le := range b.VerificationMaterial.LogEntries {
		if le.IntegratedTime <= 0 {
			return fmt.Errorf("supplychain: log entry missing integratedTime")
		}
		if le.BodyHash == "" {
			return fmt.Errorf("supplychain: log entry missing body hash")
		}
		bodyHash, derr := base64.StdEncoding.DecodeString(le.BodyHash)
		if derr != nil {
			return fmt.Errorf("supplychain: decode log entry body hash: %w", derr)
		}
		if !bytes.Equal(bodyHash, sum[:]) {
			return fmt.Errorf("supplychain: log entry body hash mismatch")
		}
	}
	return nil
}

func parseEnvelope(envelope []byte) (*dsseEnvelope, []byte, error) {
	dec := json.NewDecoder(bytes.NewReader(envelope))
	var env dsseEnvelope
	if err := dec.Decode(&env); err != nil {
		return nil, nil, fmt.Errorf("supplychain: decode envelope: %w", err)
	}
	if err := rejectTrailing(dec); err != nil {
		return nil, nil, fmt.Errorf("supplychain: decode envelope: %w", err)
	}
	if env.PayloadType != AttestationPayloadType {
		return nil, nil, fmt.Errorf("supplychain: unexpected payload type %q", env.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("supplychain: decode payload: %w", err)
	}
	if len(payload) == 0 {
		return nil, nil, fmt.Errorf("supplychain: empty payload")
	}
	return &env, payload, nil
}

func parseStatement(payload []byte) (*Statement, error) {
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("supplychain: decode statement: %w", err)
	}
	if st.Type != StatementType {
		return nil, fmt.Errorf("supplychain: unexpected statement type %q", st.Type)
	}
	if len(st.Subject) == 0 {
		return nil, fmt.Errorf("supplychain: statement has no subject")
	}
	return &st, nil
}

func checkClaims(st *Statement, want VerifyOptions) error {
	if want.Digest != "" {
		if d := st.Subject[0].Digest["sha256"]; d != want.Digest {
			return fmt.Errorf("supplychain: subject digest mismatch: want %s, got %s", want.Digest, d)
		}
	}
	for _, c := range []struct {
		want, got, label string
	}{
		{want.Issuer, st.Predicate.Issuer, "issuer"},
		{want.Identity, st.Predicate.Identity, "identity"},
		{want.Repository, st.Predicate.Repository, "repository"},
		{want.Ref, st.Predicate.Ref, "ref"},
	} {
		if c.want != "" && c.got != c.want {
			return fmt.Errorf("supplychain: %s mismatch: want %q, got %q", c.label, c.want, c.got)
		}
	}
	return nil
}

func rejectTrailing(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing data after JSON value")
		}
		return err
	}
	return nil
}

func pae(t string, p []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(t), t, len(p), p))
}

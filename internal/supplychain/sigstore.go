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
	// maxIntegratedTimeSkew bounds how far in the future a log entry's
	// integratedTime may be relative to the verifier's clock. Past times are
	// legitimate (artifacts are verified long after they were built); an
	// absurd future timestamp indicates a broken or hostile log.
	maxIntegratedTimeSkew = 24 * time.Hour
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

// SigstoreTrustRoot is the operator-configured trust material Sigstore
// bundle verification is anchored in. A bundle can never be its own trust
// root: verification fails closed unless at least one of Keys or Rekor is
// configured and satisfied.
type SigstoreTrustRoot struct {
	// Keys pins the only acceptable verification keys, keyed by key ID
	// (the DSSE signature keyid). When non-empty, the bundle's
	// verification key must match one of these pins, either by key ID or
	// by key content.
	Keys map[string]ed25519.PublicKey
	// Rekor, when non-nil, requires every bundle to carry a log entry
	// that passes transparency-log inclusion verification (the signed
	// entry timestamp). A key is never trusted merely because it appears
	// in the log.
	Rekor *RekorConfig
}

// RekorConfig configures inclusion verification against a
// Rekor-compatible transparency log.
type RekorConfig struct {
	// PublicKey is the log's Ed25519 key that verifies signed entry
	// timestamps.
	PublicKey ed25519.PublicKey
	// BaseURL is the log's HTTPS base URL. Log entries are fetched from
	// {BaseURL}/api/v1/log/entries/{uuid} over strict HTTPS without
	// following redirects, with responses bounded at 1 MiB.
	BaseURL string
}

// SigstoreVerifyConfig is the verification gate configuration for Sigstore
// bundles: every non-empty expectation must match, and TrustRoot anchors
// the only acceptable verification key and transparency log.
type SigstoreVerifyConfig struct {
	ExpectedIssuer   string
	ExpectedIdentity string
	ExpectedRepo     string
	ExpectedRef      string
	// TrustedKey is a legacy single-key pin; it is honored only when
	// TrustRoot.Keys is empty and is otherwise equivalent to pinning one
	// key by content.
	TrustedKey ed25519.PublicKey
	// TrustRoot is the verification trust anchor. When neither Keys nor
	// Rekor are configured, verification fails closed.
	TrustRoot SigstoreTrustRoot
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
	UUID           string `json:"uuid"`
	IntegratedTime int64  `json:"integratedTime"`
	BodyHash       string `json:"bodyHash"`
}

// VerifySigstoreBundle strictly parses a Sigstore bundle (DSSE envelope
// plus verification material) and verifies it against the configured
// trust root. The envelope signature must verify against a pinned trust
// key (or, only when Rekor inclusion verification is configured and
// passes, the key embedded in the bundle), the statement digest must match
// artifactDigest, and every non-empty expectation must match. A bundle
// carrying log entries cannot be verified without a configured Rekor log.
// Without any configured trust root, verification fails closed. Any parse
// inconsistency fails the verification.
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

	// Trust-root resolution: the pinned keys are the primary anchor; the
	// legacy single-key pin is honored only when no key map is configured.
	keys := verifyCfg.TrustRoot.Keys
	if len(keys) == 0 && len(verifyCfg.TrustedKey) > 0 {
		keys = map[string]ed25519.PublicKey{"": verifyCfg.TrustedKey}
	}
	rekor := verifyCfg.TrustRoot.Rekor
	if len(keys) == 0 && rekor == nil {
		return fmt.Errorf("supplychain: no sigstore trust root configured")
	}
	for id, pk := range keys {
		if len(pk) != ed25519.PublicKeySize {
			return fmt.Errorf("supplychain: invalid pinned trust key %q", id)
		}
	}
	if rekor != nil {
		if len(rekor.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("supplychain: invalid Rekor public key")
		}
		if rekor.BaseURL == "" {
			return fmt.Errorf("supplychain: Rekor base URL is not configured")
		}
	}

	var bundlePub ed25519.PublicKey
	if b.VerificationMaterial.PublicKey != nil && b.VerificationMaterial.PublicKey.RawBytes != "" {
		raw, derr := base64.StdEncoding.DecodeString(b.VerificationMaterial.PublicKey.RawBytes)
		if derr != nil {
			return fmt.Errorf("supplychain: decode embedded key: %w", derr)
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("supplychain: embedded key is not Ed25519")
		}
		bundlePub = ed25519.PublicKey(raw)
	}
	keyID := env.Signatures[0].KeyID
	var pub ed25519.PublicKey
	if len(keys) > 0 {
		pub, err = pinnedVerificationKey(keys, keyID, bundlePub)
		if err != nil {
			return err
		}
	} else {
		// Rekor-only trust root: the embedded key verifies the envelope
		// but is never a trust root by itself — acceptance additionally
		// requires a valid inclusion proof below.
		if bundlePub == nil {
			return fmt.Errorf("supplychain: bundle has no verification key and no pinned trust keys")
		}
		pub = bundlePub
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
	if rekor != nil {
		if len(b.VerificationMaterial.LogEntries) == 0 {
			return fmt.Errorf("supplychain: bundle has no log entry: Rekor inclusion verification is required")
		}
		payloadSum := sha256.Sum256(payload)
		for _, le := range b.VerificationMaterial.LogEntries {
			if le.UUID == "" {
				return fmt.Errorf("supplychain: log entry missing uuid")
			}
			if le.IntegratedTime <= 0 {
				return fmt.Errorf("supplychain: log entry missing integratedTime")
			}
			if maxFuture := time.Now().Add(maxIntegratedTimeSkew).Unix(); le.IntegratedTime > maxFuture {
				return fmt.Errorf("supplychain: log entry integratedTime %d is implausibly in the future", le.IntegratedTime)
			}
			if le.BodyHash == "" {
				return fmt.Errorf("supplychain: log entry missing body hash")
			}
			bodyHash, derr := base64.StdEncoding.DecodeString(le.BodyHash)
			if derr != nil {
				return fmt.Errorf("supplychain: decode log entry body hash: %w", derr)
			}
			if !bytes.Equal(bodyHash, payloadSum[:]) {
				return fmt.Errorf("supplychain: log entry body hash does not match the statement payload")
			}
			if verr := verifyRekorInclusion(*rekor, le.UUID, bodyHash, le.IntegratedTime); verr != nil {
				return verr
			}
		}
	} else if len(b.VerificationMaterial.LogEntries) > 0 {
		return fmt.Errorf("supplychain: bundle log entries cannot be verified: no Rekor trust root configured")
	}
	return nil
}

// pinnedVerificationKey resolves the bundle's verification key against the
// pinned trust keys. A match is accepted either by key ID (the DSSE
// signature keyid naming a pinned key) or by key content; when the bundle
// also embeds key material, it must be consistent with the matched pin.
func pinnedVerificationKey(keys map[string]ed25519.PublicKey, keyID string, bundlePub ed25519.PublicKey) (ed25519.PublicKey, error) {
	if keyID != "" {
		if pk, ok := keys[keyID]; ok {
			if bundlePub != nil && !bytes.Equal(bundlePub, pk) {
				return nil, fmt.Errorf("supplychain: embedded key does not match pinned key %q", keyID)
			}
			return pk, nil
		}
	}
	if bundlePub != nil {
		for _, pk := range keys {
			if bytes.Equal(pk, bundlePub) {
				return pk, nil
			}
		}
	}
	return nil, fmt.Errorf("supplychain: verification key is not a pinned trust key")
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

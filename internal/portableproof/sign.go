package portableproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// SignatureSchemaVersion is the portable-signature envelope schema. An
// incompatible change to the signed payload or the envelope shape bumps it;
// decoders refuse unknown versions rather than guessing.
const SignatureSchemaVersion = 1

// AlgorithmEd25519 is the only portable-signature algorithm. The name is
// the exact wire token; a decoder that does not know it fails closed.
const AlgorithmEd25519 = "Ed25519"

// DiscoverySchemaVersion is the public-key discovery document schema.
const DiscoverySchemaVersion = 1

// Refusals. Callers must treat every error here as "this envelope is not
// proven" — never as a soft signal to continue with reduced trust.
var (
	// ErrSignature is returned when the signature envelope is malformed or
	// does not verify under the named key.
	ErrSignature = errors.New("portableproof: signature check failed")
	// ErrKey is returned when the named key is unknown, revoked, or is not
	// an Ed25519 verification key.
	ErrKey = errors.New("portableproof: signing key refused")
	// ErrSchema is returned for an unknown envelope or discovery schema
	// version.
	ErrSchema = errors.New("portableproof: unsupported schema version")
)

// KeyStatus is the lifecycle state of a published verification key.
type KeyStatus string

const (
	// KeyActive: the key may verify new signatures.
	KeyActive KeyStatus = "active"
	// KeyRotated: the key was superseded by a successor but may still
	// verify historical signatures made before the rotation. Consumers
	// that require freshness may refuse it; archival consumers accept it.
	KeyRotated KeyStatus = "rotated"
	// KeyRevoked: the key is untrustworthy (compromise, operator
	// retirement). Signatures under it are refused everywhere.
	KeyRevoked KeyStatus = "revoked"
)

// Valid reports whether s is one of the closed key-status vocabulary values.
func (s KeyStatus) Valid() bool {
	switch s {
	case KeyActive, KeyRotated, KeyRevoked:
		return true
	}
	return false
}

// PortableSignature is the asymmetric signature envelope over one
// VerificationProof. It names the schema, the algorithm and the key, and
// carries the signature over the exact JSON encoding of the proof (see
// SignedProof). The public half of KeyID is enough to verify.
type PortableSignature struct {
	// SchemaVersion is SignatureSchemaVersion.
	SchemaVersion int `json:"schema_version"`
	// Algorithm is AlgorithmEd25519.
	Algorithm string `json:"algorithm"`
	// KeyID identifies the signing key in the discovery document.
	KeyID string `json:"key_id"`
	// SignedAt is when the signature was produced (operator clock; audit
	// only — it is not freshness authority).
	SignedAt time.Time `json:"signed_at"`
	// Signature is the base64 raw Ed25519 signature (64 bytes decoded).
	Signature string `json:"signature"`
}

// SignedProof is the portable unit: the exact proof JSON bytes plus the
// signature that covers those bytes. Proof is held as raw JSON on purpose —
// the signature covers the bytes as transmitted, so any byte-level tamper
// breaks the signature, and a consumer never re-encodes before checking.
type SignedProof struct {
	// Proof is the JSON encoding of verifyapi.VerificationProof. The
	// signature covers these exact bytes.
	Proof json.RawMessage `json:"proof"`
	// Signature is the asymmetric envelope over Proof.
	Signature PortableSignature `json:"signature"`
}

// DecodeProof returns the VerificationProof the envelope carries. It does
// not check the signature — call Verify first (or VerifySignedProof).
func (s SignedProof) DecodeProof() (verifyapi.VerificationProof, error) {
	if len(s.Proof) == 0 {
		return verifyapi.VerificationProof{}, fmt.Errorf("%w: envelope carries no proof bytes", ErrSignature)
	}
	var p verifyapi.VerificationProof
	if err := json.Unmarshal(s.Proof, &p); err != nil {
		return verifyapi.VerificationProof{}, fmt.Errorf("%w: proof is not a verification proof: %v", ErrSignature, err)
	}
	return p, nil
}

// Signer produces portable signatures. It holds the Ed25519 private key
// that the deployment's acceptance identity controls. Consumers never see
// this value.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewSigner builds a signer from an existing Ed25519 private key. The key
// id is the discovery-document identity of the matching public key.
func NewSigner(keyID string, priv ed25519.PrivateKey) (*Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("%w: signer key id is required", ErrKey)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signer requires an Ed25519 private key", ErrKey)
	}
	return &Signer{keyID: keyID, priv: append(ed25519.PrivateKey(nil), priv...)}, nil
}

// GenerateSigner mints a fresh Ed25519 keypair and returns the signer plus
// the raw public key to publish in a discovery document. Tests and
// first-boot provisioning use it; production key custody is external.
func GenerateSigner(keyID string) (*Signer, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generate Ed25519 key: %v", ErrKey, err)
	}
	s, err := NewSigner(keyID, priv)
	if err != nil {
		return nil, nil, err
	}
	return s, pub, nil
}

// KeyID returns the discovery identity of this signer's key.
func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// SignProof encodes the proof to its canonical JSON bytes (encoding/json
// emits struct fields in declaration order and sorts map keys, so the
// encoding is byte-stable for a given Go value) and signs those exact
// bytes. The returned envelope carries the same bytes.
func (s *Signer) SignProof(proof verifyapi.VerificationProof, at time.Time) (SignedProof, error) {
	if s == nil || len(s.priv) != ed25519.PrivateKeySize {
		return SignedProof{}, fmt.Errorf("%w: signer is not configured", ErrKey)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return SignedProof{}, fmt.Errorf("%w: encode proof: %v", ErrSignature, err)
	}
	if at.IsZero() {
		at = time.Now()
	}
	sig := ed25519.Sign(s.priv, raw)
	return SignedProof{
		Proof: append(json.RawMessage(nil), raw...),
		Signature: PortableSignature{
			SchemaVersion: SignatureSchemaVersion,
			Algorithm:     AlgorithmEd25519,
			KeyID:         s.keyID,
			SignedAt:      at.UTC(),
			Signature:     base64.StdEncoding.EncodeToString(sig),
		},
	}, nil
}

// Verify checks the portable signature with a bare public key. It is the
// consumer-side entry point: no secret, no store, no ambient authority —
// only the envelope and the public key the consumer trusts. The proof bytes
// are checked exactly as transmitted; any mutation is a refusal.
//
// Verify does NOT evaluate the proof's internal HMAC acceptance record
// (the consumer does not hold that secret) and does not interpret the
// proof's claims. It answers exactly one question: were these bytes signed
// by the holder of the private half of this key.
func Verify(signed SignedProof, keyID string, pub ed25519.PublicKey) error {
	if signed.Signature.SchemaVersion != SignatureSchemaVersion {
		return fmt.Errorf("%w: signature schema %d", ErrSchema, signed.Signature.SchemaVersion)
	}
	if signed.Signature.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("%w: algorithm %q is not %s", ErrKey, signed.Signature.Algorithm, AlgorithmEd25519)
	}
	if keyID == "" || signed.Signature.KeyID != keyID {
		return fmt.Errorf("%w: envelope key id %q does not match trusted key %q", ErrKey, signed.Signature.KeyID, keyID)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: verification key %q is not an Ed25519 public key", ErrKey, keyID)
	}
	if len(signed.Proof) == 0 {
		return fmt.Errorf("%w: envelope carries no proof bytes", ErrSignature)
	}
	raw, err := base64.StdEncoding.DecodeString(signed.Signature.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not base64: %v", ErrSignature, err)
	}
	if !ed25519.Verify(pub, signed.Proof, raw) {
		return fmt.Errorf("%w: signature does not verify under key %q", ErrSignature, keyID)
	}
	return nil
}

// VerifySignedProof verifies the envelope and returns the decoded proof
// only when the signature checks. The proof is never returned from a
// failed check.
func VerifySignedProof(signed SignedProof, keyID string, pub ed25519.PublicKey) (verifyapi.VerificationProof, error) {
	if err := Verify(signed, keyID, pub); err != nil {
		return verifyapi.VerificationProof{}, err
	}
	return signed.DecodeProof()
}

// PublicKeyDoc is one published verification key. The public key is raw
// base64 (32 decoded bytes). Status and the operator note carry the
// rotation / revocation story so a consumer can refuse a key the operator
// has retired without a second channel.
type PublicKeyDoc struct {
	// KeyID is the discovery identity (matches PortableSignature.KeyID).
	KeyID string `json:"key_id"`
	// Algorithm is AlgorithmEd25519.
	Algorithm string `json:"algorithm"`
	// PublicKey is the base64 raw Ed25519 public key (32 bytes decoded).
	PublicKey string `json:"public_key"`
	// Status is the lifecycle state of this key.
	Status KeyStatus `json:"status"`
	// CreatedAt is when the key was first published.
	CreatedAt time.Time `json:"created_at"`
	// SupersededByKeyID names the successor when Status is KeyRotated.
	SupersededByKeyID string `json:"superseded_by_key_id,omitempty"`
	// Note is the operator's rotation / revocation note: why the key
	// changed state, when, and what a consumer should do about it.
	Note string `json:"note,omitempty"`
}

// PublicKeyBytes decodes the raw Ed25519 public key. A malformed entry is a
// refusal, never a fallback.
func (d PublicKeyDoc) PublicKeyBytes() (ed25519.PublicKey, error) {
	if d.Algorithm != AlgorithmEd25519 {
		return nil, fmt.Errorf("%w: key %q algorithm %q is not %s", ErrKey, d.KeyID, d.Algorithm, AlgorithmEd25519)
	}
	raw, err := base64.StdEncoding.DecodeString(d.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key %q public key is not base64 Ed25519", ErrKey, d.KeyID)
	}
	return ed25519.PublicKey(raw), nil
}

// Verifiable reports whether this key may verify a signature right now:
// the key must be present, active or rotated (rotated keys still verify
// historical signatures), never revoked, and well-formed.
func (d PublicKeyDoc) Verifiable() error {
	if d.KeyID == "" {
		return fmt.Errorf("%w: key id is required", ErrKey)
	}
	switch d.Status {
	case KeyActive, KeyRotated:
	case KeyRevoked:
		return fmt.Errorf("%w: key %q is revoked", ErrKey, d.KeyID)
	default:
		return fmt.Errorf("%w: key %q has unknown status %q", ErrKey, d.KeyID, d.Status)
	}
	_, err := d.PublicKeyBytes()
	return err
}

// PublicKeyDiscovery is the public-key discovery document: the set of
// portable-signature verification keys a deployment publishes, each with
// its lifecycle state and rotation / revocation note. A consumer fetches
// this document over its own channel and verifies envelopes against it.
type PublicKeyDiscovery struct {
	// SchemaVersion is DiscoverySchemaVersion.
	SchemaVersion int `json:"schema_version"`
	// IssuedAt is when this document was published.
	IssuedAt time.Time `json:"issued_at"`
	// Keys is the published key set. Order is operator-defined; lookup is
	// by KeyID.
	Keys []PublicKeyDoc `json:"keys"`
}

// NewDiscovery builds an empty discovery document stamped now.
func NewDiscovery(at time.Time) PublicKeyDiscovery {
	if at.IsZero() {
		at = time.Now()
	}
	return PublicKeyDiscovery{SchemaVersion: DiscoverySchemaVersion, IssuedAt: at.UTC()}
}

// PublishDoc returns a document entry for a raw Ed25519 public key.
func PublishDoc(keyID string, pub ed25519.PublicKey, status KeyStatus, at time.Time, note string) (PublicKeyDoc, error) {
	if keyID == "" {
		return PublicKeyDoc{}, fmt.Errorf("%w: key id is required", ErrKey)
	}
	if len(pub) != ed25519.PublicKeySize {
		return PublicKeyDoc{}, fmt.Errorf("%w: key %q is not an Ed25519 public key", ErrKey, keyID)
	}
	if !status.Valid() {
		return PublicKeyDoc{}, fmt.Errorf("%w: key %q has unknown status %q", ErrKey, keyID, status)
	}
	if at.IsZero() {
		at = time.Now()
	}
	return PublicKeyDoc{
		KeyID:     keyID,
		Algorithm: AlgorithmEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Status:    status,
		CreatedAt: at.UTC(),
		Note:      note,
	}, nil
}

// Find returns the doc for one key id.
func (d PublicKeyDiscovery) Find(keyID string) (PublicKeyDoc, bool) {
	for _, k := range d.Keys {
		if k.KeyID == keyID {
			return k, true
		}
	}
	return PublicKeyDoc{}, false
}

// Rotate installs successor as the new active key and marks predecessor as
// KeyRotated with the operator note and successor pointer. The retired
// key stays in the document so historical signatures remain explainable.
func (d *PublicKeyDiscovery) Rotate(predecessorID, successorID, note string) error {
	if d == nil {
		return fmt.Errorf("%w: discovery document is nil", ErrKey)
	}
	var pred, succ *PublicKeyDoc
	for i := range d.Keys {
		switch d.Keys[i].KeyID {
		case predecessorID:
			pred = &d.Keys[i]
		case successorID:
			succ = &d.Keys[i]
		}
	}
	if pred == nil {
		return fmt.Errorf("%w: predecessor key %q not in discovery", ErrKey, predecessorID)
	}
	if succ == nil {
		return fmt.Errorf("%w: successor key %q not in discovery", ErrKey, successorID)
	}
	if pred.Status == KeyRevoked {
		return fmt.Errorf("%w: refusing to rotate a revoked key %q", ErrKey, predecessorID)
	}
	pred.Status = KeyRotated
	pred.SupersededByKeyID = successorID
	if note != "" {
		pred.Note = note
	}
	succ.Status = KeyActive
	if note != "" && succ.Note == "" {
		succ.Note = note
	}
	return nil
}

// Revoke marks a key revoked with the operator note. Signatures under it
// are refused from that moment on.
func (d *PublicKeyDiscovery) Revoke(keyID, note string) error {
	if d == nil {
		return fmt.Errorf("%w: discovery document is nil", ErrKey)
	}
	for i := range d.Keys {
		if d.Keys[i].KeyID == keyID {
			d.Keys[i].Status = KeyRevoked
			if note != "" {
				d.Keys[i].Note = note
			}
			return nil
		}
	}
	return fmt.Errorf("%w: key %q not in discovery", ErrKey, keyID)
}

// VerifyWithDiscovery verifies a portable signature against the published
// key set. The named key must be present and verifiable (active or rotated,
// never revoked). It is the discovery-shaped wrapper over Verify.
func VerifyWithDiscovery(signed SignedProof, disc PublicKeyDiscovery) error {
	if disc.SchemaVersion != DiscoverySchemaVersion {
		return fmt.Errorf("%w: discovery schema %d", ErrSchema, disc.SchemaVersion)
	}
	doc, ok := disc.Find(signed.Signature.KeyID)
	if !ok {
		return fmt.Errorf("%w: key %q not in discovery document", ErrKey, signed.Signature.KeyID)
	}
	if err := doc.Verifiable(); err != nil {
		return err
	}
	pub, err := doc.PublicKeyBytes()
	if err != nil {
		return err
	}
	return Verify(signed, doc.KeyID, pub)
}

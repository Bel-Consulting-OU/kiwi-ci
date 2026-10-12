package verifyapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Acceptance integrity contract.
//
// A durable store's database row is NOT authority: the unexported seal
// cannot be serialized, and without an integrity binding a tampered row (or a
// flipped is_verified flag) could recreate a proven pass. Acceptance is the
// durable stand-in for the seal:
//
//   - Accept() computes an AcceptanceRecord at persist time: versioned
//     digests of the exact (obligation, outcome, evidence) triple, the
//     algorithm, the acceptance timestamp, the acceptance key id, and a
//     MAC/signature under the acceptance key.
//   - RestoreVerifiedOutcome() re-checks that record at load time. Only a row
//     whose canonical digests match and whose MAC verifies is restored
//     sealed; an unsigned, edited or key-mismatched row can never produce
//     ProvenPass.
//
// The acceptance key is deliberately separate from runner evidence keys:
// evidence keys prove what an execution produced; the acceptance key proves
// that THIS verifier accepted THIS triple at THIS time. The test hook and
// single-node deployments use a local HMAC key (HMACAcceptanceKey).

// AcceptanceVersion is the acceptance-record schema version. Any change to
// the canonical MAC input must bump it.
const AcceptanceVersion = 1

// AcceptanceAlgorithmHMACSHA256 is the MAC algorithm of HMACAcceptanceKey.
const AcceptanceAlgorithmHMACSHA256 = "HMAC-SHA256"

// acceptanceDomain separates acceptance MAC inputs from any other MAC use.
const acceptanceDomain = "kiwi-ci/verify-acceptance/v1"

// AcceptanceRecord is the durable integrity record of one accepted
// verification. It binds the exact (obligation, outcome, evidence) triple
// that was sealed, under a MAC or signature produced with the acceptance key.
type AcceptanceRecord struct {
	// AcceptanceVersion is the record schema version (AcceptanceVersion).
	AcceptanceVersion int `json:"acceptance_version"`
	// ObligationDigest commits the canonical encoding of the obligation the
	// record answers.
	ObligationDigest Digest `json:"obligation_digest"`
	// OutcomeDigest commits the canonical encoding of the DERIVED
	// authoritative outcome.
	OutcomeDigest Digest `json:"outcome_digest"`
	// VerifiedEvidenceDigest commits the canonical encoding of the resolved
	// evidence.
	VerifiedEvidenceDigest Digest `json:"verified_evidence_digest"`
	// Algorithm names the MAC/signature algorithm ("HMAC-SHA256", …).
	Algorithm string `json:"algorithm"`
	// VerifiedAt is when the acceptance record was produced (acceptance
	// clock; may differ from Evidence.VerifiedAt).
	VerifiedAt time.Time `json:"verified_at"`
	// KeyID identifies the acceptance key that produced MAC.
	KeyID string `json:"key_id"`
	// MAC is the lowercase-hex MAC/signature over the canonical acceptance
	// payload (everything in this record except MAC itself).
	MAC string `json:"mac"`
}

// AcceptanceKey signs and verifies acceptance records. Implementations hold
// the durable-acceptance trust root and must be independent of the runner
// evidence keys used to resolve attestations.
type AcceptanceKey interface {
	// KeyID identifies the key in persisted acceptance records.
	KeyID() string
	// Algorithm names the MAC/signature algorithm.
	Algorithm() string
	// Sign returns the lowercase-hex MAC/signature over payload.
	Sign(payload []byte) (string, error)
	// Verify reports whether mac is a valid MAC/signature over payload.
	Verify(payload []byte, mac string) bool
}

// HMACAcceptanceKey is a local HMAC-SHA256 acceptance key: the test hook and
// the single-node deployment key. It is NOT an evidence key.
type HMACAcceptanceKey struct {
	id     string
	secret []byte
}

// NewHMACAcceptanceKey builds a local HMAC-SHA256 acceptance key. The id must
// be non-empty (it is recorded in every acceptance record) and the secret
// must be non-empty.
func NewHMACAcceptanceKey(id string, secret []byte) (*HMACAcceptanceKey, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: acceptance key id is required", ErrAcceptance)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: acceptance key secret is required", ErrAcceptance)
	}
	s := make([]byte, len(secret))
	copy(s, secret)
	return &HMACAcceptanceKey{id: id, secret: s}, nil
}

// KeyID implements AcceptanceKey.
func (k *HMACAcceptanceKey) KeyID() string { return k.id }

// Algorithm implements AcceptanceKey.
func (k *HMACAcceptanceKey) Algorithm() string { return AcceptanceAlgorithmHMACSHA256 }

// Sign implements AcceptanceKey with HMAC-SHA256.
func (k *HMACAcceptanceKey) Sign(payload []byte) (string, error) {
	if k == nil || len(k.secret) == 0 {
		return "", fmt.Errorf("%w: acceptance key is not configured", ErrAcceptance)
	}
	mac := hmac.New(sha256.New, k.secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify implements AcceptanceKey with constant-time HMAC-SHA256 comparison.
func (k *HMACAcceptanceKey) Verify(payload []byte, mac string) bool {
	if k == nil || len(k.secret) == 0 || mac == "" {
		return false
	}
	want, err := k.Sign(payload)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(want), []byte(mac))
}

// PersistedVerified is the complete durable acceptance payload a store must
// persist together and hand back on restore. Nothing inside is authority on
// its own: RestoreVerifiedOutcome re-derives trust from the acceptance record.
type PersistedVerified struct {
	// Obligation is the obligation the record answers (needed so the
	// obligation digest can be re-checked on restore).
	Obligation VerificationObligation `json:"obligation"`
	// SubmittedClaim is the caller's proposal, preserved for audit.
	SubmittedClaim VerificationOutcome `json:"submitted_claim"`
	// Outcome is the DERIVED authoritative outcome.
	Outcome VerificationOutcome `json:"outcome"`
	// Evidence is the resolved evidence backing Outcome.
	Evidence VerifiedEvidence `json:"evidence"`
	// Acceptance is the integrity record computed at persist time.
	Acceptance AcceptanceRecord `json:"acceptance"`
}

// Accept computes the durable acceptance record for a verifier-produced
// record under the given obligation. Call it at persist time (with the
// acceptance clock instant); RestoreVerifiedOutcome re-checks it at load
// time. An unsealed record is refused — acceptance never mints first
// authority.
func Accept(obligation VerificationObligation, derived DerivedVerifiedOutcome, key AcceptanceKey, at time.Time) (AcceptanceRecord, error) {
	if !derived.Sealed() {
		return AcceptanceRecord{}, fmt.Errorf("%w: Accept requires a verifier-produced record", ErrUnverified)
	}
	if key == nil {
		return AcceptanceRecord{}, fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	if at.IsZero() {
		return AcceptanceRecord{}, fmt.Errorf("%w: acceptance time is required", ErrAcceptance)
	}
	obDig, err := obligationDigest(obligation)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	outDig, err := outcomeDigest(derived.Outcome)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	evDig, err := evidenceDigest(derived.Evidence)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	rec := AcceptanceRecord{
		AcceptanceVersion:      AcceptanceVersion,
		ObligationDigest:       obDig,
		OutcomeDigest:          outDig,
		VerifiedEvidenceDigest: evDig,
		Algorithm:              key.Algorithm(),
		VerifiedAt:             at.UTC(),
		KeyID:                  key.KeyID(),
	}
	payload, err := acceptancePayload(rec)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	mac, err := key.Sign(payload)
	if err != nil {
		return AcceptanceRecord{}, fmt.Errorf("%w: sign acceptance: %v", ErrAcceptance, err)
	}
	rec.MAC = mac
	return rec, nil
}

// RestoreVerifiedOutcome rehydrates a persisted authoritative record through
// the acceptance integrity path. It is the ONLY way authority survives a
// process restart, and it never mints first authority: the stored triple must
// hash to the digests the acceptance record commits and the MAC must verify
// under the given acceptance key, and only then are the same completeness
// rules as first sealing applied. An unsigned row, a tampered payload, a
// flipped verified flag or a wrong MAC can never produce ProvenPass.
func RestoreVerifiedOutcome(p PersistedVerified, key AcceptanceKey) (DerivedVerifiedOutcome, error) {
	if key == nil {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	rec := p.Acceptance
	if rec.AcceptanceVersion != AcceptanceVersion {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: unsupported acceptance version %d (want %d)", ErrAcceptance, rec.AcceptanceVersion, AcceptanceVersion)
	}
	if rec.MAC == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance record is unsigned", ErrAcceptance)
	}
	if rec.KeyID == "" || rec.Algorithm == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance record is missing key id or algorithm", ErrAcceptance)
	}
	if rec.Algorithm != key.Algorithm() {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance algorithm %q does not match key algorithm %q", ErrAcceptance, rec.Algorithm, key.Algorithm())
	}
	if rec.KeyID != key.KeyID() {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance key id %q does not match key %q", ErrAcceptance, rec.KeyID, key.KeyID())
	}
	// Canonical re-encoding: the stored triple must hash to the digests the
	// acceptance record commits, so a tampered payload cannot ride along
	// under a stale MAC.
	obDig, err := obligationDigest(p.Obligation)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if obDig != rec.ObligationDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: obligation digest mismatch", ErrAcceptance)
	}
	outDig, err := outcomeDigest(p.Outcome)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if outDig != rec.OutcomeDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: outcome digest mismatch", ErrAcceptance)
	}
	evDig, err := evidenceDigest(p.Evidence)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if evDig != rec.VerifiedEvidenceDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: evidence digest mismatch", ErrAcceptance)
	}
	payload, err := acceptancePayload(rec)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if !key.Verify(payload, rec.MAC) {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance MAC verification failed", ErrAcceptance)
	}
	// Completeness rules identical to first sealing: a truncated or edited
	// row is refused instead of quietly losing the proven-pass bit.
	return sealDerivedOutcome(p.SubmittedClaim, p.Outcome, p.Evidence)
}

// acceptancePayload is the canonical MAC input: a domain-separated, ordered
// encoding of every acceptance field except MAC itself.
func acceptancePayload(rec AcceptanceRecord) ([]byte, error) {
	if rec.AcceptanceVersion != AcceptanceVersion {
		return nil, fmt.Errorf("%w: unsupported acceptance version %d", ErrAcceptance, rec.AcceptanceVersion)
	}
	if err := validateDigest("obligation_digest", rec.ObligationDigest); err != nil {
		return nil, err
	}
	if err := validateDigest("outcome_digest", rec.OutcomeDigest); err != nil {
		return nil, err
	}
	if err := validateDigest("verified_evidence_digest", rec.VerifiedEvidenceDigest); err != nil {
		return nil, err
	}
	if rec.Algorithm == "" || rec.KeyID == "" {
		return nil, fmt.Errorf("%w: acceptance algorithm and key id are required", ErrAcceptance)
	}
	if rec.VerifiedAt.IsZero() {
		return nil, fmt.Errorf("%w: acceptance verified_at is required", ErrAcceptance)
	}
	return []byte(fmt.Sprintf("%s\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n",
		acceptanceDomain,
		rec.AcceptanceVersion,
		rec.ObligationDigest,
		rec.OutcomeDigest,
		rec.VerifiedEvidenceDigest,
		rec.Algorithm,
		rec.VerifiedAt.UTC().Format(time.RFC3339Nano),
		rec.KeyID)), nil
}

// obligationDigest commits the canonical encoding of an obligation.
func obligationDigest(o VerificationObligation) (Digest, error) {
	return canonicalDigest("obligation", normalizeObligation(o))
}

// outcomeDigest commits the canonical encoding of a derived outcome.
func outcomeDigest(v VerificationOutcome) (Digest, error) {
	return canonicalDigest("outcome", normalizeOutcome(v))
}

// evidenceDigest commits the canonical encoding of resolved evidence.
func evidenceDigest(e VerifiedEvidence) (Digest, error) {
	return canonicalDigest("evidence", normalizeEvidence(e))
}

// canonicalDigest is the single digest rule for acceptance: domain-separated
// SHA-256 over the canonical JSON encoding of v. Callers pass time-normalized
// values so equal instants hash equal across a storage round trip.
func canonicalDigest(label string, v any) (Digest, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("%w: encode %s for digest: %v", ErrAcceptance, label, err)
	}
	sum := sha256.Sum256(append([]byte(acceptanceDomain+"/"+label+"\n"), raw...))
	return Digest(hex.EncodeToString(sum[:])), nil
}

func normalizeObligation(o VerificationObligation) VerificationObligation {
	n := o
	n.IssuedAt = n.IssuedAt.UTC()
	if n.Freshness.NotBefore != nil {
		t := n.Freshness.NotBefore.UTC()
		n.Freshness.NotBefore = &t
	}
	if n.Freshness.NotAfter != nil {
		t := n.Freshness.NotAfter.UTC()
		n.Freshness.NotAfter = &t
	}
	return n
}

func normalizeOutcome(v VerificationOutcome) VerificationOutcome {
	n := v
	n.StartedAt = n.StartedAt.UTC()
	n.CompletedAt = n.CompletedAt.UTC()
	return n
}

func normalizeEvidence(e VerifiedEvidence) VerifiedEvidence {
	n := e
	n.VerifiedAt = n.VerifiedAt.UTC()
	if n.Attested != nil {
		a := *n.Attested
		a.StartedAt = a.StartedAt.UTC()
		a.FinishedAt = a.FinishedAt.UTC()
		n.Attested = &a
	}
	return n
}

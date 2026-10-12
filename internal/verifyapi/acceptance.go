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
//     digests of the exact (obligation, submitted claim, outcome, evidence)
//     bundle, the subject identity, the algorithm, the acceptance timestamp,
//     the acceptance key id, and a MAC/signature under the acceptance key.
//   - RestoreVerifiedOutcome() re-checks that record at load time. Only a row
//     whose canonical digests match and whose MAC verifies is restored
//     sealed; an unsigned, edited or key-mismatched row can never produce
//     ProvenPass.
//
// The acceptance key is deliberately separate from runner evidence keys:
// evidence keys prove what an execution produced; the acceptance key proves
// that THIS verifier accepted THIS bundle at THIS time. The test hook and
// single-node deployments use a local HMAC key (HMACAcceptanceKey); the
// production seam is an AcceptanceKeyring that rotates keys without breaking
// verification of already-persisted records.
//
// Version history:
//
//   - v1 (AcceptanceVersion) bound (obligation, outcome, evidence) digests
//     but NOT the submitted claim. An attacker with database write could
//     therefore alter the claim column on restore. v1 records still restore
//     when their v1 MAC verifies.
//   - v2 (AcceptanceVersionV2) is the current write format. It domain-
//     separates under kiwi-ci/verification-acceptance/v2, binds a submitted
//     claim digest and the subject identity, and uses the FROZEN canonical
//     encoding (see frozen.go) rather than opportunistic Go struct JSON.

// AcceptanceVersion is the v1 acceptance-record schema version. Retained so
// pre-existing rows keep restoring; no new record is written at this version.
const AcceptanceVersion = 1

// AcceptanceVersionV2 is the current acceptance-record schema version. Any
// change to the v2 canonical MAC input must bump it (and the domain).
const AcceptanceVersionV2 = 2

// AcceptanceAlgorithmHMACSHA256 is the MAC algorithm of HMACAcceptanceKey.
const AcceptanceAlgorithmHMACSHA256 = "HMAC-SHA256"

// acceptanceDomain separates v1 acceptance MAC inputs from any other MAC use.
const acceptanceDomain = "kiwi-ci/verify-acceptance/v1"

// acceptanceDomainV2 is the v2 acceptance MAC domain. The domain string is
// frozen together with the v2 field list.
const acceptanceDomainV2 = "kiwi-ci/verification-acceptance/v2"

// AcceptanceRecord is the durable integrity record of one accepted
// verification. It binds the exact bundle that was sealed, under a MAC or
// signature produced with the acceptance key.
//
// v1 rows populate only the v1 field set (AcceptanceVersion = 1).
// v2 rows populate the full field set (AcceptanceVersionV2 = 2).
type AcceptanceRecord struct {
	// AcceptanceVersion is the record schema version (1 or 2).
	AcceptanceVersion int `json:"acceptance_version"`
	// SchemaVersion is the verifyapi wire schema the record was written
	// under (v2 only; zero on v1 rows).
	SchemaVersion int `json:"schema_version,omitempty"`
	// ObligationDigest commits the canonical encoding of the obligation the
	// record answers.
	ObligationDigest Digest `json:"obligation_digest"`
	// SubmittedClaimDigest commits the canonical encoding of the caller's
	// submitted claim (v2 only). This is the field whose absence let a
	// database-writer swap the claim on restore.
	SubmittedClaimDigest Digest `json:"submitted_claim_digest,omitempty"`
	// OutcomeDigest commits the canonical encoding of the DERIVED
	// authoritative outcome.
	OutcomeDigest Digest `json:"outcome_digest"`
	// VerifiedEvidenceDigest commits the canonical encoding of the resolved
	// evidence.
	VerifiedEvidenceDigest Digest `json:"verified_evidence_digest"`
	// Subject is the obligation's subject identity (v2 only).
	Subject string `json:"subject,omitempty"`
	// SubjectRef is the obligation's authority subject (v2 only).
	SubjectRef *SubjectRef `json:"subject_ref,omitempty"`
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

// AcceptanceKeyring is the rotation-aware acceptance trust root.
//
// CurrentSigningKeyID names the key new records are sealed under.
// VerifyKeys holds every key that may still verify a persisted record, keyed
// by KeyID. Rotation is: install the new key, move CurrentSigningKeyID to it,
// keep the old key in VerifyKeys until every record that references it has
// been resealed, then retire the old key. A record whose KeyID is absent from
// VerifyKeys fails closed — an unknown or tampered key id can never restore.
type AcceptanceKeyring struct {
	// CurrentSigningKeyID is the key new acceptance records are signed with.
	CurrentSigningKeyID string
	// VerifyKeys maps key id → key for every key that may still verify.
	VerifyKeys map[string]AcceptanceKey
}

// NewAcceptanceKeyring builds a keyring. currentID must name a key present in
// keys. The map is copied so later mutation of the caller's map cannot
// silently extend the trust root.
func NewAcceptanceKeyring(currentID string, keys map[string]AcceptanceKey) (*AcceptanceKeyring, error) {
	if currentID == "" {
		return nil, fmt.Errorf("%w: keyring current signing key id is required", ErrAcceptance)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: keyring must hold at least one key", ErrAcceptance)
	}
	copied := make(map[string]AcceptanceKey, len(keys))
	for id, k := range keys {
		if id == "" || k == nil {
			return nil, fmt.Errorf("%w: keyring entry with empty id or nil key", ErrAcceptance)
		}
		copied[id] = k
	}
	if _, ok := copied[currentID]; !ok {
		return nil, fmt.Errorf("%w: keyring current signing key %q is not in the key set", ErrAcceptance, currentID)
	}
	return &AcceptanceKeyring{CurrentSigningKeyID: currentID, VerifyKeys: copied}, nil
}

// NewSingleKeyring wraps one key as a keyring that both signs and verifies
// with it. Convenience for tests and single-node deployments.
func NewSingleKeyring(key AcceptanceKey) (*AcceptanceKeyring, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	return NewAcceptanceKeyring(key.KeyID(), map[string]AcceptanceKey{key.KeyID(): key})
}

// SigningKey returns the key new records are signed with.
func (r *AcceptanceKeyring) SigningKey() (AcceptanceKey, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	k, ok := r.VerifyKeys[r.CurrentSigningKeyID]
	if !ok || k == nil {
		return nil, fmt.Errorf("%w: keyring has no current signing key %q", ErrAcceptance, r.CurrentSigningKeyID)
	}
	return k, nil
}

// KeyByID returns the verification key for id. Unknown ids are a hard
// refusal (fail closed) — never a fallback to some other key.
func (r *AcceptanceKeyring) KeyByID(id string) (AcceptanceKey, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	if id == "" {
		return nil, fmt.Errorf("%w: acceptance record has no key id", ErrAcceptance)
	}
	k, ok := r.VerifyKeys[id]
	if !ok || k == nil {
		return nil, fmt.Errorf("%w: acceptance key %q is not in the keyring", ErrAcceptance, id)
	}
	return k, nil
}

// Retire removes a verification key. It refuses to remove the current
// signing key. The caller must ensure no persisted record still references
// the key (see ResealPersisted): a record whose KeyID has been retired fails
// closed on restore.
func (r *AcceptanceKeyring) Retire(keyID string) error {
	if r == nil {
		return fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	if keyID == r.CurrentSigningKeyID {
		return fmt.Errorf("%w: refusing to retire the current signing key %q", ErrAcceptance, keyID)
	}
	if _, ok := r.VerifyKeys[keyID]; !ok {
		return fmt.Errorf("%w: acceptance key %q is not in the keyring", ErrAcceptance, keyID)
	}
	delete(r.VerifyKeys, keyID)
	return nil
}

// Rotate installs newKey as the current signing key while keeping the
// previous key available for verification. This is the "rotate K2 keep K1
// verify" step: after Rotate, new records are sealed under K2 and existing
// K1 records still restore.
func (r *AcceptanceKeyring) Rotate(newKey AcceptanceKey) error {
	if r == nil {
		return fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	if newKey == nil {
		return fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	if newKey.KeyID() == "" {
		return fmt.Errorf("%w: acceptance key id is required", ErrAcceptance)
	}
	if r.VerifyKeys == nil {
		r.VerifyKeys = make(map[string]AcceptanceKey, 2)
	}
	r.VerifyKeys[newKey.KeyID()] = newKey
	r.CurrentSigningKeyID = newKey.KeyID()
	return nil
}

// ResealPersisted verifies a persisted bundle under its existing key (the
// record's KeyID) and re-seals it under the keyring's current signing key.
// This is the migration step "verify K1 → reseal under K2": the returned
// AcceptanceRecord must be persisted in place of the old one; only then may
// K1 be retired.
func (r *AcceptanceKeyring) ResealPersisted(p PersistedVerified, at time.Time) (AcceptanceRecord, DerivedVerifiedOutcome, error) {
	sealed, err := RestoreVerifiedOutcomeWithKeyring(p, nil, r)
	if err != nil {
		return AcceptanceRecord{}, DerivedVerifiedOutcome{}, err
	}
	rec, err := AcceptWithKeyring(p.Obligation, sealed, nil, r, at)
	if err != nil {
		return AcceptanceRecord{}, DerivedVerifiedOutcome{}, err
	}
	return rec, sealed, nil
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

// AcceptanceSigner is the signing half of the acceptance trust root: either
// a bare AcceptanceKey or an *AcceptanceKeyring. Accept picks the key that
// signs new records from this value.
type AcceptanceSigner interface {
	// SigningKey returns the key new records are sealed under.
	SigningKey() (AcceptanceKey, error)
}

// AcceptanceVerifier is the verifying half: either a bare AcceptanceKey or
// an *AcceptanceKeyring. RestoreVerifiedOutcome resolves the record's KeyID
// through this value.
type AcceptanceVerifier interface {
	// KeyByID returns the verification key for a persisted key id.
	KeyByID(id string) (AcceptanceKey, error)
}

// keyringAdapter lets a bare AcceptanceKey satisfy the signer/verifier
// interfaces (single-key deployments and tests).
type keyringAdapter struct{ key AcceptanceKey }

func (a keyringAdapter) SigningKey() (AcceptanceKey, error) {
	if a.key == nil {
		return nil, fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	return a.key, nil
}

func (a keyringAdapter) KeyByID(id string) (AcceptanceKey, error) {
	if a.key == nil {
		return nil, fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	if id == "" || id != a.key.KeyID() {
		return nil, fmt.Errorf("%w: acceptance key %q does not match key %q", ErrAcceptance, id, a.key.KeyID())
	}
	return a.key, nil
}

// asSigner normalizes a bare key or keyring to an AcceptanceSigner.
func asSigner(k AcceptanceKey, r *AcceptanceKeyring) (AcceptanceSigner, error) {
	if r != nil {
		if k != nil {
			return nil, fmt.Errorf("%w: pass either a key or a keyring, not both", ErrAcceptance)
		}
		return r, nil
	}
	if k == nil {
		return nil, fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	return keyringAdapter{key: k}, nil
}

// asVerifier normalizes a bare key or keyring to an AcceptanceVerifier.
func asVerifier(k AcceptanceKey, r *AcceptanceKeyring) (AcceptanceVerifier, error) {
	if r != nil {
		if k != nil {
			return nil, fmt.Errorf("%w: pass either a key or a keyring, not both", ErrAcceptance)
		}
		return r, nil
	}
	if k == nil {
		return nil, fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	return keyringAdapter{key: k}, nil
}

// Accept computes the durable acceptance record for a verifier-produced
// record under the given obligation. Call it at persist time (with the
// acceptance clock instant); RestoreVerifiedOutcome re-checks it at load
// time. An unsealed record is refused — acceptance never mints first
// authority.
//
// New records are always written at AcceptanceVersionV2 under the signer's
// current key. Pass an *AcceptanceKeyring to sign with the rotated key, or a
// bare AcceptanceKey for single-key deployments.
func Accept(obligation VerificationObligation, derived DerivedVerifiedOutcome, key AcceptanceKey, at time.Time) (AcceptanceRecord, error) {
	return AcceptWithKeyring(obligation, derived, key, nil, at)
}

// AcceptWithKeyring is the keyring-aware accept. Exactly one of key / keyring
// must be non-nil.
func AcceptWithKeyring(obligation VerificationObligation, derived DerivedVerifiedOutcome, key AcceptanceKey, keyring *AcceptanceKeyring, at time.Time) (AcceptanceRecord, error) {
	if !derived.Sealed() {
		return AcceptanceRecord{}, fmt.Errorf("%w: Accept requires a verifier-produced record", ErrUnverified)
	}
	signer, err := asSigner(key, keyring)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	if at.IsZero() {
		return AcceptanceRecord{}, fmt.Errorf("%w: acceptance time is required", ErrAcceptance)
	}
	sk, err := signer.SigningKey()
	if err != nil {
		return AcceptanceRecord{}, err
	}
	obDig, err := obligationDigestV2(obligation)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	claimDig, err := submittedClaimDigest(derived.SubmittedClaim)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	outDig, err := outcomeDigestV2(derived.Outcome)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	evDig, err := evidenceDigestV2(derived.Evidence)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	rec := AcceptanceRecord{
		AcceptanceVersion:      AcceptanceVersionV2,
		SchemaVersion:          SchemaVersion,
		ObligationDigest:       obDig,
		SubmittedClaimDigest:   claimDig,
		OutcomeDigest:          outDig,
		VerifiedEvidenceDigest: evDig,
		Subject:                obligation.Subject,
		Algorithm:              sk.Algorithm(),
		VerifiedAt:             at.UTC(),
		KeyID:                  sk.KeyID(),
	}
	if obligation.SubjectRef != nil {
		s := *obligation.SubjectRef
		rec.SubjectRef = &s
	}
	payload, err := acceptancePayload(rec)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	mac, err := sk.Sign(payload)
	if err != nil {
		return AcceptanceRecord{}, fmt.Errorf("%w: sign acceptance: %v", ErrAcceptance, err)
	}
	rec.MAC = mac
	return rec, nil
}

// RestoreVerifiedOutcome rehydrates a persisted authoritative record through
// the acceptance integrity path. It is the ONLY way authority survives a
// process restart, and it never mints first authority: the stored bundle must
// hash to the digests the acceptance record commits and the MAC must verify
// under the key the record names, and only then are the same completeness
// rules as first sealing applied. An unsigned row, a tampered payload, a
// flipped verified flag or a wrong MAC can never produce ProvenPass.
//
// v1 records restore when their v1 MAC verifies (legacy compatibility); v2
// records additionally bind the submitted claim and the subject identity.
// Pass an *AcceptanceKeyring so a record signed under an older key still
// verifies via its KeyID.
func RestoreVerifiedOutcome(p PersistedVerified, key AcceptanceKey) (DerivedVerifiedOutcome, error) {
	return RestoreVerifiedOutcomeWithKeyring(p, key, nil)
}

// RestoreVerifiedOutcomeWithKeyring is the keyring-aware restore. Exactly one
// of key / keyring must be non-nil.
func RestoreVerifiedOutcomeWithKeyring(p PersistedVerified, key AcceptanceKey, keyring *AcceptanceKeyring) (DerivedVerifiedOutcome, error) {
	verifier, err := asVerifier(key, keyring)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	rec := p.Acceptance
	switch rec.AcceptanceVersion {
	case AcceptanceVersion:
		return restoreV1(p, rec, verifier)
	case AcceptanceVersionV2:
		return restoreV2(p, rec, verifier)
	default:
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: unsupported acceptance version %d", ErrAcceptance, rec.AcceptanceVersion)
	}
}

// restoreV1 verifies a legacy acceptance record. v1 bound (obligation,
// outcome, evidence) but not the claim; the record still restores when its
// v1 MAC is valid, and sealDerivedOutcome's identity rule is applied so a
// claim swapped into a v1 row cannot carry a mismatched identity.
func restoreV1(p PersistedVerified, rec AcceptanceRecord, verifier AcceptanceVerifier) (DerivedVerifiedOutcome, error) {
	if rec.MAC == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance record is unsigned", ErrAcceptance)
	}
	if rec.KeyID == "" || rec.Algorithm == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance record is missing key id or algorithm", ErrAcceptance)
	}
	key, err := verifier.KeyByID(rec.KeyID)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if rec.Algorithm != key.Algorithm() {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance algorithm %q does not match key algorithm %q", ErrAcceptance, rec.Algorithm, key.Algorithm())
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

// restoreV2 verifies a current acceptance record. The v2 MAC binds the
// submitted claim digest and the subject identity in addition to the
// obligation / outcome / evidence digests, so a database writer who swaps the
// claim column (or the subject) breaks the MAC.
func restoreV2(p PersistedVerified, rec AcceptanceRecord, verifier AcceptanceVerifier) (DerivedVerifiedOutcome, error) {
	if rec.MAC == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance record is unsigned", ErrAcceptance)
	}
	if rec.KeyID == "" || rec.Algorithm == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance record is missing key id or algorithm", ErrAcceptance)
	}
	if rec.SchemaVersion != SchemaVersion {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: unsupported schema version %d (want %d)", ErrAcceptance, rec.SchemaVersion, SchemaVersion)
	}
	key, err := verifier.KeyByID(rec.KeyID)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if rec.Algorithm != key.Algorithm() {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance algorithm %q does not match key algorithm %q", ErrAcceptance, rec.Algorithm, key.Algorithm())
	}
	obDig, err := obligationDigestV2(p.Obligation)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if obDig != rec.ObligationDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: obligation digest mismatch", ErrAcceptance)
	}
	claimDig, err := submittedClaimDigest(p.SubmittedClaim)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if claimDig != rec.SubmittedClaimDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: submitted claim digest mismatch", ErrAcceptance)
	}
	outDig, err := outcomeDigestV2(p.Outcome)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if outDig != rec.OutcomeDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: outcome digest mismatch", ErrAcceptance)
	}
	evDig, err := evidenceDigestV2(p.Evidence)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if evDig != rec.VerifiedEvidenceDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: evidence digest mismatch", ErrAcceptance)
	}
	// Subject identity is bound by the MAC: a claim swapped under a different
	// subject is a different record.
	if rec.Subject != p.Obligation.Subject {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance subject %q does not match obligation subject %q", ErrAcceptance, rec.Subject, p.Obligation.Subject)
	}
	if !subjectRefsEqual(rec.SubjectRef, p.Obligation.SubjectRef) {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance subject_ref does not match obligation subject_ref", ErrAcceptance)
	}
	payload, err := acceptancePayload(rec)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if !key.Verify(payload, rec.MAC) {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: acceptance MAC verification failed", ErrAcceptance)
	}
	return sealDerivedOutcome(p.SubmittedClaim, p.Outcome, p.Evidence)
}

func subjectRefsEqual(a, b *SubjectRef) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		// A nil ref and a zero ref are the same "no subject" shape.
		if a == nil {
			return b.IsZero()
		}
		return a.IsZero()
	}
	return a.Equal(*b)
}

// acceptancePayload is the canonical MAC input. v2 uses the FROZEN
// length-prefixed encoding (see frozen.go); v1 keeps its original
// newline-joined form so legacy MACs keep verifying.
func acceptancePayload(rec AcceptanceRecord) ([]byte, error) {
	switch rec.AcceptanceVersion {
	case AcceptanceVersion:
		return acceptancePayloadV1(rec)
	case AcceptanceVersionV2:
		return acceptancePayloadV2(rec)
	default:
		return nil, fmt.Errorf("%w: unsupported acceptance version %d", ErrAcceptance, rec.AcceptanceVersion)
	}
}

// acceptancePayloadV1 is the frozen v1 MAC input: domain-separated, ordered,
// newline-joined. Retained verbatim so existing rows keep restoring.
func acceptancePayloadV1(rec AcceptanceRecord) ([]byte, error) {
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

// acceptancePayloadV2 is the FROZEN v2 MAC input: domain-separated,
// length-prefixed fields in a fixed order. This is the contract encoding —
// never Go struct JSON.
func acceptancePayloadV2(rec AcceptanceRecord) ([]byte, error) {
	if err := validateDigest("obligation_digest", rec.ObligationDigest); err != nil {
		return nil, err
	}
	if err := validateDigest("submitted_claim_digest", rec.SubmittedClaimDigest); err != nil {
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
	f := frozenDomain(acceptanceDomainV2)
	f.int64(int64(rec.SchemaVersion))
	f.str(string(rec.ObligationDigest))
	f.str(string(rec.SubmittedClaimDigest))
	f.str(string(rec.OutcomeDigest))
	f.str(string(rec.VerifiedEvidenceDigest))
	f.str(rec.Subject)
	encodeSubjectRefFrozen(f, rec.SubjectRef)
	f.str(rec.Algorithm)
	f.time(rec.VerifiedAt)
	f.str(rec.KeyID)
	return f.buf, nil
}

// obligationDigest commits the canonical encoding of an obligation (v1
// rule, retained for legacy restore).
func obligationDigest(o VerificationObligation) (Digest, error) {
	return canonicalDigest("obligation", normalizeObligation(o))
}

// outcomeDigest commits the canonical encoding of a derived outcome (v1
// rule, retained for legacy restore).
func outcomeDigest(v VerificationOutcome) (Digest, error) {
	return canonicalDigest("outcome", normalizeOutcome(v))
}

// evidenceDigest commits the canonical encoding of resolved evidence (v1
// rule, retained for legacy restore).
func evidenceDigest(e VerifiedEvidence) (Digest, error) {
	return canonicalDigest("evidence", normalizeEvidence(e))
}

// obligationDigestV2 commits the FROZEN encoding of an obligation.
func obligationDigestV2(o VerificationObligation) (Digest, error) {
	return encodeObligationFrozen(normalizeObligation(o)).frozenHash("obligation")
}

// outcomeDigestV2 commits the FROZEN encoding of a derived outcome.
func outcomeDigestV2(v VerificationOutcome) (Digest, error) {
	return encodeOutcomeFrozen(normalizeOutcome(v)).frozenHash("outcome")
}

// evidenceDigestV2 commits the FROZEN encoding of resolved evidence.
func evidenceDigestV2(e VerifiedEvidence) (Digest, error) {
	return encodeEvidenceFrozen(normalizeEvidence(e)).frozenHash("evidence")
}

// submittedClaimDigest commits the FROZEN encoding of the caller's submitted
// claim. This is the v2 binding whose absence let a database writer alter the
// claim on restore. The substrate-filled Measured subset is excluded (it is
// filled at record time and is never claim identity — the same rule
// verifystore.ClaimContentDigest applies), so a store that stamps Measured on
// the way to disk still hashes equal to the claim the acceptance record bound.
func submittedClaimDigest(v VerificationOutcome) (Digest, error) {
	n := normalizeOutcome(v)
	n.Resources.Measured = nil
	return encodeOutcomeFrozen(n).frozenHash("submitted-claim")
}

// canonicalDigest is the v1 digest rule: domain-separated SHA-256 over the
// JSON encoding of v. Retained so v1 acceptance records keep verifying; new
// records use the frozen v2 digests above.
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

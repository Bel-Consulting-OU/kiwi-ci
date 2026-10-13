package verifyapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
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
//   - v2 (AcceptanceVersionV2) domain-
//     separates under kiwi-ci/verification-acceptance/v2, binds a submitted
//     claim digest and the subject identity, and uses the FROZEN canonical
//     encoding (see frozen.go) rather than opportunistic Go struct JSON.
//   - v3 (AcceptanceVersionV3) binds the resolved verification demand.
//   - v4 (AcceptanceVersionV4) is the current write format. Its evidence
//     digest uses the evidence/v3 encoding, which additionally binds the
//     resolved Window and the evidence-kind list; restore re-derives both
//     from MAC-verified primitives instead of trusting the persisted fields.

// AcceptanceVersion is the v1 acceptance-record schema version. Retained so
// pre-existing rows keep restoring; no new record is written at this version.
const AcceptanceVersion = 1

// AcceptanceVersionV2 is the v2 acceptance-record schema version. Retained
// so pre-existing rows keep restoring; no new record is written at this
// version.
const AcceptanceVersionV2 = 2

// AcceptanceVersionV3 is the v3 acceptance-record schema version. It
// binds the resolved verification demand (DemandDigest) and includes the
// recipe digest in the frozen obligation encoding. Any change to the v3
// canonical MAC input must bump it (and the domain).
const AcceptanceVersionV3 = 3

// AcceptanceVersionV4 is the current acceptance-record schema version. The
// v4 change is the evidence encoding: evidence/v3 additionally binds the
// resolved Window (source and bracket) and the evidence-kind list, both
// authority-bearing and previously forgeable by a database writer. Any
// change to the v4 canonical MAC input must bump it (and the domain).
const AcceptanceVersionV4 = 4

// AcceptanceVersionCurrent is the version new acceptance records are written
// at.
const AcceptanceVersionCurrent = AcceptanceVersionV4

// AcceptanceAlgorithmHMACSHA256 is the MAC algorithm of HMACAcceptanceKey.
const AcceptanceAlgorithmHMACSHA256 = "HMAC-SHA256"

// acceptanceDomain separates v1 acceptance MAC inputs from any other MAC use.
const acceptanceDomain = "kiwi-ci/verify-acceptance/v1"

// acceptanceDomainV2 is the v2 acceptance MAC domain. The domain string is
// frozen together with the v2 field list.
const acceptanceDomainV2 = "kiwi-ci/verification-acceptance/v2"

// acceptanceDomainV3 is the v3 acceptance MAC domain. The domain string is
// frozen together with the v3 field list.
const acceptanceDomainV3 = "kiwi-ci/verification-acceptance/v3"

// acceptanceDomainV4 is the v4 acceptance MAC domain. The domain string is
// frozen together with the v4 field list.
const acceptanceDomainV4 = "kiwi-ci/verification-acceptance/v4"

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
	// DemandDigest commits the canonical resolved verification demand
	// (EffectiveVerificationDemand) the record was accepted under — the
	// recipe-owned rules when a recipe is bound, else the obligation's
	// inline rules. v3 only. A discharge is pinned to the exact rules it
	// was measured against.
	DemandDigest Digest `json:"demand_digest,omitempty"`
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

// keyringState is an immutable snapshot of the acceptance trust root. Once
// published through AcceptanceKeyring.state it is never mutated; every
// structural change (Rotate / Retire / Install) builds a fresh snapshot and
// swaps the pointer, so concurrent readers always observe a consistent view
// without locks.
type keyringState struct {
	currentID  string
	verifyKeys map[string]AcceptanceKey
}

// AcceptanceKeyring is the rotation-aware acceptance trust root. It is safe
// for concurrent use: the trust root is an immutable snapshot held behind an
// atomic pointer, and Rotate/Retire/Install swap in a new snapshot. The
// mutators are serialized by a mutex so concurrent Rotate/Retire/Install
// cannot lose an update (read-modify-write on the verify-key map).
//
// The current signing key id names the key new records are sealed under.
// The verify-key set holds every key that may still verify a persisted
// record, keyed by KeyID. Rotation is: install the new key, move the current
// signing key id to it, keep the old key in the verify set until every record
// that references it has been resealed, then retire the old key. A record
// whose KeyID is absent from the verify set fails closed — an unknown or
// tampered key id can never restore. Rotate and Install refuse to overwrite
// a different key that already occupies the same KeyID.
type AcceptanceKeyring struct {
	// mu serializes Retire/Rotate/Install so their read-modify-write of
	// the verify-key map is atomic with respect to each other. Readers use
	// the atomic pointer and take no lock.
	mu    sync.Mutex
	state atomic.Pointer[keyringState]
}

// NewAcceptanceKeyring builds a keyring. currentID must name a key present in
// keys, and every map key must equal the key's own KeyID() — a mislabeled
// entry would let a record's KeyID resolve to the wrong secret. The map is
// copied so later mutation of the caller's map cannot silently extend the
// trust root.
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
		if k.KeyID() != id {
			return nil, fmt.Errorf("%w: keyring map key %q does not match key id %q", ErrAcceptance, id, k.KeyID())
		}
		copied[id] = k
	}
	if _, ok := copied[currentID]; !ok {
		return nil, fmt.Errorf("%w: keyring current signing key %q is not in the key set", ErrAcceptance, currentID)
	}
	r := &AcceptanceKeyring{}
	r.state.Store(&keyringState{currentID: currentID, verifyKeys: copied})
	return r, nil
}

// NewSingleKeyring wraps one key as a keyring that both signs and verifies
// with it. Convenience for tests and single-node deployments.
func NewSingleKeyring(key AcceptanceKey) (*AcceptanceKeyring, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	return NewAcceptanceKeyring(key.KeyID(), map[string]AcceptanceKey{key.KeyID(): key})
}

// snapshot returns the current immutable trust-root snapshot.
func (r *AcceptanceKeyring) snapshot() *keyringState {
	if r == nil {
		return nil
	}
	return r.state.Load()
}

// CurrentSigningKeyID returns the key id new acceptance records are signed
// with.
func (r *AcceptanceKeyring) CurrentSigningKeyID() string {
	s := r.snapshot()
	if s == nil {
		return ""
	}
	return s.currentID
}

// SigningKey returns the key new records are signed with.
func (r *AcceptanceKeyring) SigningKey() (AcceptanceKey, error) {
	s := r.snapshot()
	if s == nil {
		return nil, fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	k, ok := s.verifyKeys[s.currentID]
	if !ok || k == nil {
		return nil, fmt.Errorf("%w: keyring has no current signing key %q", ErrAcceptance, s.currentID)
	}
	return k, nil
}

// KeyByID returns the verification key for id. Unknown ids are a hard
// refusal (fail closed) — never a fallback to some other key.
func (r *AcceptanceKeyring) KeyByID(id string) (AcceptanceKey, error) {
	s := r.snapshot()
	if s == nil {
		return nil, fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	if id == "" {
		return nil, fmt.Errorf("%w: acceptance record has no key id", ErrAcceptance)
	}
	k, ok := s.verifyKeys[id]
	if !ok || k == nil {
		return nil, fmt.Errorf("%w: acceptance key %q is not in the keyring", ErrAcceptance, id)
	}
	return k, nil
}

// sameAcceptanceKey reports whether a and b are the same signing key. Two
// keys that MAC a fixed probe identically (same secret, same algorithm) are
// interchangeable; a different secret under the same KeyID is a distinct key
// and must never silently overwrite it. The probe-MAC comparison is total
// (no interface equality) so uncomparable key implementations are safe.
func sameAcceptanceKey(a, b AcceptanceKey) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.KeyID() != b.KeyID() || a.Algorithm() != b.Algorithm() {
		return false
	}
	probe := []byte("kiwi-ci/acceptance-keyring-same-key/v1")
	ma, errA := a.Sign(probe)
	mb, errB := b.Sign(probe)
	return errA == nil && errB == nil && ma != "" && ma == mb
}

// ensureKeySlot reports whether key may occupy key's KeyID in the map: the
// slot must be empty or already hold the same key. Overwriting a different
// key under one KeyID is refused (a tampered or swapped secret would then
// verify records the original key sealed).
func ensureKeySlot(keys map[string]AcceptanceKey, key AcceptanceKey) error {
	id := key.KeyID()
	if existing, ok := keys[id]; ok && !sameAcceptanceKey(existing, key) {
		return fmt.Errorf("%w: refusing to overwrite key %q with a different key under the same id", ErrAcceptance, id)
	}
	return nil
}

// Retire removes a verification key. It refuses to remove the current
// signing key. The caller must ensure no persisted record still references
// the key (see ResealPersisted): a record whose KeyID has been retired fails
// closed on restore.
func (r *AcceptanceKeyring) Retire(keyID string) error {
	if r == nil {
		return fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.state.Load()
	if s == nil {
		return fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	if keyID == s.currentID {
		return fmt.Errorf("%w: refusing to retire the current signing key %q", ErrAcceptance, keyID)
	}
	if _, ok := s.verifyKeys[keyID]; !ok {
		return fmt.Errorf("%w: acceptance key %q is not in the keyring", ErrAcceptance, keyID)
	}
	next := make(map[string]AcceptanceKey, len(s.verifyKeys)-1)
	for id, k := range s.verifyKeys {
		if id != keyID {
			next[id] = k
		}
	}
	r.state.Store(&keyringState{currentID: s.currentID, verifyKeys: next})
	return nil
}

// Rotate installs newKey as the current signing key while keeping the
// previous key available for verification. This is the "rotate K2 keep K1
// verify" step: after Rotate, new records are sealed under K2 and existing
// K1 records still restore. A different key that already occupies newKey's
// KeyID is refused rather than overwritten.
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
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.state.Load()
	if s == nil {
		return fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	next := make(map[string]AcceptanceKey, len(s.verifyKeys)+1)
	for id, k := range s.verifyKeys {
		next[id] = k
	}
	if err := ensureKeySlot(next, newKey); err != nil {
		return err
	}
	next[newKey.KeyID()] = newKey
	r.state.Store(&keyringState{currentID: newKey.KeyID(), verifyKeys: next})
	return nil
}

// Install adds a verification key without changing the current signing key.
// It is the migration helper for putting a retired key back (e.g. to finish a
// reseal that was interrupted); it never demotes the current signing key. A
// different key that already occupies the same KeyID is refused rather than
// overwritten.
func (r *AcceptanceKeyring) Install(key AcceptanceKey) error {
	if r == nil {
		return fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	if key == nil {
		return fmt.Errorf("%w: acceptance key is required", ErrAcceptance)
	}
	if key.KeyID() == "" {
		return fmt.Errorf("%w: acceptance key id is required", ErrAcceptance)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.state.Load()
	if s == nil {
		return fmt.Errorf("%w: acceptance keyring is nil", ErrAcceptance)
	}
	next := make(map[string]AcceptanceKey, len(s.verifyKeys)+1)
	for id, k := range s.verifyKeys {
		next[id] = k
	}
	if err := ensureKeySlot(next, key); err != nil {
		return err
	}
	next[key.KeyID()] = key
	r.state.Store(&keyringState{currentID: s.currentID, verifyKeys: next})
	return nil
}

// ResealPersisted verifies a persisted bundle under its existing key (the
// record's KeyID) and re-seals it under the keyring's current signing key.
// This is the migration step "verify K1 → reseal under K2": the returned
// AcceptanceRecord must be persisted in place of the old one; only then may
// K1 be retired.
func (r *AcceptanceKeyring) ResealPersisted(p PersistedVerified, at time.Time) (AcceptanceRecord, DerivedVerifiedOutcome, error) {
	return r.ResealPersistedWithRecipe(p, nil, at)
}

// ResealPersistedWithRecipe is the recipe-aware reseal. Recipe-bound records
// must pass the resolved recipe so the recomputed demand digest matches the
// original accept.
func (r *AcceptanceKeyring) ResealPersistedWithRecipe(p PersistedVerified, recipe *Recipe, at time.Time) (AcceptanceRecord, DerivedVerifiedOutcome, error) {
	sealed, err := RestoreVerifiedOutcomeWithRecipe(p, nil, r, recipe)
	if err != nil {
		return AcceptanceRecord{}, DerivedVerifiedOutcome{}, err
	}
	rec, err := AcceptWithRecipe(p.Obligation, sealed, nil, r, recipe, at)
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
// New records are always written at AcceptanceVersionCurrent under the
// signer's current key. Pass an *AcceptanceKeyring to sign with the rotated
// key, or a bare AcceptanceKey for single-key deployments.
func Accept(obligation VerificationObligation, derived DerivedVerifiedOutcome, key AcceptanceKey, at time.Time) (AcceptanceRecord, error) {
	return AcceptWithKeyring(obligation, derived, key, nil, at)
}

// AcceptWithKeyring is the keyring-aware accept. Exactly one of key / keyring
// must be non-nil. When the obligation pins a RecipeDigest the caller must
// supply the resolved *Recipe (AcceptOptions.Recipe): the demand digest is
// then the recipe's rule set, and the obligation's inline fields must already
// match it (BindRecipe). Accepting a recipe-bound obligation without a
// resolved recipe is refused — otherwise a caller could mint a valid MAC
// over weaker inline rules while advertising a strong recipe label.
func AcceptWithKeyring(obligation VerificationObligation, derived DerivedVerifiedOutcome, key AcceptanceKey, keyring *AcceptanceKeyring, at time.Time) (AcceptanceRecord, error) {
	return acceptWithKeyringRecipe(obligation, derived, key, keyring, nil, at)
}

// AcceptWithRecipe is the recipe-aware accept: required whenever
// obligation.RecipeDigest is set. The recipe is resolved once at submit and
// passed here so the demand digest is the recipe's canonical rule set.
func AcceptWithRecipe(obligation VerificationObligation, derived DerivedVerifiedOutcome, key AcceptanceKey, keyring *AcceptanceKeyring, recipe *Recipe, at time.Time) (AcceptanceRecord, error) {
	return acceptWithKeyringRecipe(obligation, derived, key, keyring, recipe, at)
}

func acceptWithKeyringRecipe(obligation VerificationObligation, derived DerivedVerifiedOutcome, key AcceptanceKey, keyring *AcceptanceKeyring, recipe *Recipe, at time.Time) (AcceptanceRecord, error) {
	if !derived.Sealed() {
		return AcceptanceRecord{}, fmt.Errorf("%w: Accept requires a verifier-produced record", ErrUnverified)
	}
	if at.IsZero() {
		return AcceptanceRecord{}, fmt.Errorf("%w: acceptance time is required", ErrAcceptance)
	}
	// The recipe identity is not free: when a recipe is supplied it must be
	// exactly the recipe the obligation pins, or the demand digest would
	// measure a different rule set than the obligation identity claims.
	if recipe != nil {
		d, err := RecipeDigest(*recipe)
		if err != nil {
			return AcceptanceRecord{}, err
		}
		if obligation.RecipeDigest != d {
			return AcceptanceRecord{}, fmt.Errorf("%w: obligation recipe digest %s disagrees with supplied recipe %s", ErrBinding, obligation.RecipeDigest, d)
		}
	}
	if obligation.RecipeDigest != "" && recipe == nil {
		return AcceptanceRecord{}, fmt.Errorf("%w: recipe-bound obligation requires the resolved recipe at accept time", ErrBinding)
	}
	// Bind the recipe onto the obligation and digest the BOUND copy: the
	// recipe-owned fields (checks, assurance, freshness) are part of the
	// obligation identity the acceptance record commits, so they can never
	// ride along empty or weaker under a strong recipe digest. Liveness is
	// checked at the acceptance clock `at` — a recipe withdrawn before
	// acceptance cannot mint a new accepted record (historical restores are
	// liveness-free; see restore).
	bound := obligation
	if recipe != nil {
		var err error
		bound, err = BindRecipe(obligation, *recipe, at)
		if err != nil {
			return AcceptanceRecord{}, fmt.Errorf("%w: obligation does not match its recipe: %v", ErrBinding, err)
		}
	}
	// The derived outcome must actually discharge THIS obligation: candidate,
	// snapshot, contract, required checks and assurance. A sealed outcome
	// from another obligation must never ride along under this record.
	if err := Bind(bound, derived.Outcome, at); err != nil {
		return AcceptanceRecord{}, fmt.Errorf("%w: sealed outcome does not bind the obligation: %v", ErrBinding, err)
	}
	signer, err := asSigner(key, keyring)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	sk, err := signer.SigningKey()
	if err != nil {
		return AcceptanceRecord{}, err
	}
	obDig, err := obligationDigestV3(bound)
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
	evDig, err := evidenceDigestV3(derived.Evidence)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	// Bind the canonical resolved demand: the recipe's rules when a recipe
	// is pinned, else the obligation's inline rules. This is the rule set
	// the discharge was measured against.
	demandDig, err := EffectiveVerificationDemandDigest(bound, recipe)
	if err != nil {
		return AcceptanceRecord{}, err
	}
	rec := AcceptanceRecord{
		AcceptanceVersion:      AcceptanceVersionCurrent,
		SchemaVersion:          SchemaVersion,
		ObligationDigest:       obDig,
		SubmittedClaimDigest:   claimDig,
		OutcomeDigest:          outDig,
		VerifiedEvidenceDigest: evDig,
		DemandDigest:           demandDig,
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
	return RestoreVerifiedOutcomeWithRecipe(p, key, keyring, nil)
}

// RestoreVerifiedOutcomeWithRecipe restores a record and, for v3
// recipe-bound records, recomputes the demand digest from the resolved
// recipe. A recipe-bound record restored without its recipe is refused
// rather than silently matching a weaker inline demand.
func RestoreVerifiedOutcomeWithRecipe(p PersistedVerified, key AcceptanceKey, keyring *AcceptanceKeyring, recipe *Recipe) (DerivedVerifiedOutcome, error) {
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
	case AcceptanceVersionV3:
		return restoreV3(p, rec, verifier, recipe)
	case AcceptanceVersionV4:
		return restoreV4(p, rec, verifier, recipe)
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

// restoreV3 verifies a v3 acceptance record. The v3 MAC binds the resolved
// verification demand digest (DemandDigest) in addition to the v2 field set,
// so a database writer who swaps the demanded rules (or the recipe identity)
// breaks the MAC. Its evidence digest is the legacy evidence/v2 encoding
// (no Window / Kinds), so those two fields are re-derived at restore and
// never trusted; new records are written at AcceptanceVersionV4, whose
// evidence digest binds them too.
func restoreV3(p PersistedVerified, rec AcceptanceRecord, verifier AcceptanceVerifier, recipe *Recipe) (DerivedVerifiedOutcome, error) {
	return restoreCurrent(p, rec, verifier, recipe, evidenceDigestV2)
}

// restoreV4 verifies a v4 acceptance record. Identical to restoreV3 except
// the evidence digest uses the evidence/v3 encoding, which additionally
// binds the resolved Window and the evidence-kind list — tampering either
// breaks the MAC. Restore still re-derives both from MAC-verified primitives
// rather than trusting the persisted fields.
func restoreV4(p PersistedVerified, rec AcceptanceRecord, verifier AcceptanceVerifier, recipe *Recipe) (DerivedVerifiedOutcome, error) {
	return restoreCurrent(p, rec, verifier, recipe, evidenceDigestV3)
}

// restoreCurrent is the shared restore path for v3 and v4 records.
// evDigest selects the evidence encoding the record was signed with.
func restoreCurrent(p PersistedVerified, rec AcceptanceRecord, verifier AcceptanceVerifier, recipe *Recipe, evDigest func(VerifiedEvidence) (Digest, error)) (DerivedVerifiedOutcome, error) {
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
	// Recipe identity is not free at restore either: the supplied recipe
	// must be exactly the one the obligation pins, or the recomputed demand
	// would measure a different rule set than the record was accepted under.
	if p.Obligation.RecipeDigest != "" && recipe == nil {
		// Recipe-bound records must restore against the resolved recipe;
		// without it the demand digest cannot be recomputed faithfully.
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: recipe-bound record requires the resolved recipe at restore time", ErrBinding)
	}
	bound := p.Obligation
	if recipe != nil {
		d, err := RecipeDigest(*recipe)
		if err != nil {
			return DerivedVerifiedOutcome{}, err
		}
		if p.Obligation.RecipeDigest != d {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: obligation recipe digest %s disagrees with supplied recipe %s", ErrBinding, p.Obligation.RecipeDigest, d)
		}
		// Historical restores are liveness-free: bindRecipe fills the
		// recipe-owned fields without consulting withdrawal, so a proof
		// accepted under a since-withdrawn recipe keeps restoring.
		bound, err = bindRecipe(p.Obligation, *recipe)
		if err != nil {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: obligation does not match its recipe: %v", ErrBinding, err)
		}
	}
	obDig, err := obligationDigestV3(bound)
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
	evDig, err := evDigest(p.Evidence)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if evDig != rec.VerifiedEvidenceDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: evidence digest mismatch", ErrAcceptance)
	}
	demandDig, err := EffectiveVerificationDemandDigest(bound, recipe)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if demandDig != rec.DemandDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: demand digest mismatch", ErrAcceptance)
	}
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
	// Re-apply the obligation-binding rule at restore so a MAC-valid pair
	// of (other-obligation outcome, this obligation) cannot restore. The
	// acceptance clock is the record's own acceptance instant, so a
	// historical record is judged as of when it was accepted.
	if err := Bind(bound, p.Outcome, rec.VerifiedAt); err != nil {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: restored outcome does not bind the obligation: %v", ErrBinding, err)
	}
	// Never trust the persisted Window / Kinds: both are authority-bearing
	// (freshness floor and EvidenceMinimum.RequiredKinds) and are re-derived
	// from the MAC-verified primitives. The sealed output and every policy
	// check see only the re-derived values.
	evidence := rederiveEvidenceWindowKinds(p.Evidence, p.SubmittedClaim)
	if recipe != nil {
		if err := recipe.EvidenceMin.Check(evidence); err != nil {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: restored record fails the recipe evidence floor: %v", ErrUnverified, err)
		}
	}
	return sealDerivedOutcome(p.SubmittedClaim, p.Outcome, evidence)
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

// acceptancePayload is the canonical MAC input. v4 uses the FROZEN
// length-prefixed encoding (see frozen.go) including the demand digest; v3
// and earlier keep their original frozen forms so legacy MACs keep verifying.
func acceptancePayload(rec AcceptanceRecord) ([]byte, error) {
	switch rec.AcceptanceVersion {
	case AcceptanceVersion:
		return acceptancePayloadV1(rec)
	case AcceptanceVersionV2:
		return acceptancePayloadV2(rec)
	case AcceptanceVersionV3:
		return acceptancePayloadV3(rec)
	case AcceptanceVersionV4:
		return acceptancePayloadV4(rec)
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

// acceptancePayloadV3 is the FROZEN v3 MAC input: the v2 field list plus the
// resolved-demand digest. Domain-separated, length-prefixed, fixed order.
func acceptancePayloadV3(rec AcceptanceRecord) ([]byte, error) {
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
	if err := validateDigest("demand_digest", rec.DemandDigest); err != nil {
		return nil, err
	}
	if rec.Algorithm == "" || rec.KeyID == "" {
		return nil, fmt.Errorf("%w: acceptance algorithm and key id are required", ErrAcceptance)
	}
	if rec.VerifiedAt.IsZero() {
		return nil, fmt.Errorf("%w: acceptance verified_at is required", ErrAcceptance)
	}
	f := frozenDomain(acceptanceDomainV3)
	f.int64(int64(rec.SchemaVersion))
	f.str(string(rec.ObligationDigest))
	f.str(string(rec.SubmittedClaimDigest))
	f.str(string(rec.OutcomeDigest))
	f.str(string(rec.VerifiedEvidenceDigest))
	f.str(string(rec.DemandDigest))
	f.str(rec.Subject)
	encodeSubjectRefFrozen(f, rec.SubjectRef)
	f.str(rec.Algorithm)
	f.time(rec.VerifiedAt)
	f.str(rec.KeyID)
	return f.buf, nil
}

// acceptancePayloadV4 is the FROZEN v4 MAC input: the v3 field list under a
// new domain. The v4 change lives in the evidence digest (evidence/v3 binds
// Window and Kinds); the record field list is unchanged, but the domain is
// bumped so a v3 payload can never verify as v4 (or vice versa).
func acceptancePayloadV4(rec AcceptanceRecord) ([]byte, error) {
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
	if err := validateDigest("demand_digest", rec.DemandDigest); err != nil {
		return nil, err
	}
	if rec.Algorithm == "" || rec.KeyID == "" {
		return nil, fmt.Errorf("%w: acceptance algorithm and key id are required", ErrAcceptance)
	}
	if rec.VerifiedAt.IsZero() {
		return nil, fmt.Errorf("%w: acceptance verified_at is required", ErrAcceptance)
	}
	f := frozenDomain(acceptanceDomainV4)
	f.int64(int64(rec.SchemaVersion))
	f.str(string(rec.ObligationDigest))
	f.str(string(rec.SubmittedClaimDigest))
	f.str(string(rec.OutcomeDigest))
	f.str(string(rec.VerifiedEvidenceDigest))
	f.str(string(rec.DemandDigest))
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

// obligationDigestV3 commits the FROZEN v3 encoding of an obligation
// (including the recipe digest).
func obligationDigestV3(o VerificationObligation) (Digest, error) {
	return encodeObligationFrozenV3(normalizeObligation(o)).frozenHash("obligation")
}

// outcomeDigestV2 commits the FROZEN encoding of a derived outcome.
func outcomeDigestV2(v VerificationOutcome) (Digest, error) {
	return encodeOutcomeFrozen(normalizeOutcome(v)).frozenHash("outcome")
}

// evidenceDigestV2 commits the legacy FROZEN v2 encoding of resolved
// evidence (no Window / Kinds). Retained for AcceptanceVersionV2/V3 records.
func evidenceDigestV2(e VerifiedEvidence) (Digest, error) {
	return encodeEvidenceFrozenV2(normalizeEvidence(e)).frozenHash("evidence")
}

// evidenceDigestV3 commits the FROZEN v3 encoding of resolved evidence,
// which also binds the resolved Window and the evidence-kind list.
func evidenceDigestV3(e VerifiedEvidence) (Digest, error) {
	return encodeEvidenceFrozenV3(normalizeEvidence(e)).frozenHash("evidence")
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
	// A zero SubjectRef is the same "no subject" shape as nil: canonicalize
	// it away so the frozen encoding (and any JSON round-trip) cannot tell
	// them apart.
	if n.SubjectRef != nil && n.SubjectRef.IsZero() {
		n.SubjectRef = nil
	}
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

// Package verifyapi is the neutral, claim-bound verification contract of the
// Kiwi control plane. It elevates verification from an incidental step of a
// workflow run to a first-class API: a caller declares WHAT must be verified
// (a VerificationObligation binding an immutable candidate, a source state and
// a verification contract) and receives a VerificationOutcome that is valid
// only for that exact quadruple plus the evidence produced.
//
// The package is a pure domain surface. It deliberately carries no product,
// billing, policy-vendor or model-provider concepts: required_checks,
// required_assurance and assurance_profile are opaque strings defined by the
// verification contract, not by this package. Resource facts are neutral
// economics (latency, memory, cache behavior) and never prices.
//
// # Binding rule
//
// A result is valid only for (obligation + exact candidate + exact source
// state + exact contract + evidence). Any change to the candidate digest, the
// source snapshot digest or the verification contract digest is a different
// obligation; the outcome is refused (fail closed) rather than silently
// rebound. The only exception is a verification contract that explicitly
// defines equivalence, which this package does not interpret: callers that
// implement equivalence must submit a new obligation that names the
// equivalent digests.
//
// # Freshness
//
// Every obligation carries a FreshnessPolicy (optional not_before delay,
// hard expiry and/or maximum age). Recording an outcome for an expired or
// stale obligation is refused. The ENTIRE proof execution interval must lie
// inside the policy window: started_at is at or after
// max(issued_at, freshness.not_before), completed_at is at or before
// not_after (when set) and within max_age of issued_at, and started_at <=
// completed_at. Pre-issued work — an execution that began before the
// obligation existed — can never satisfy a later obligation, even when its
// completion timestamp is in range. Freshness is evaluated against the
// registry clock at record time and against the outcome's own timestamps, so
// a backdated or post-expiry completion cannot launder an expired claim.
//
// # Speculative groups
//
// A SpeculativeGroup ties several candidates that were verified against one
// shared base snapshot. Outcomes inside a group expose comparable ResourceFacts
// (same field semantics, same base state) so a caller can pick among candidates
// without re-deriving measurements. Comparability is structural: CompareGroup
// refuses to line up outcomes that do not share the group's base snapshot.
// When a candidate has several recorded attempts, CompareGroup selects one
// canonical attempt deterministically (latest completed_at, ties broken by
// ascending verification_id), so repeated comparisons over the same records
// always return identical rows and the same winner.
//
// # Resource facts: reported vs measured vs attested
//
// ResourceFacts carries the neutral economics of an execution. All of its
// scalar fields are REPORTED facts — caller assertions — and stay that way
// until they are tied to execution evidence (an attested runner measurement
// or equivalent provenance binding). CPU time and memory in particular are
// reported numbers, not verified ones. FactSource / FactSourceOf is the
// audit vocabulary for this distinction (derived | attested | reported).
// The optional Measured subset is substrate-filled: the registry derives
// DurationNS at record time from the outcome's own execution interval
// (completed_at - started_at) and overwrites any caller-supplied value, so a
// dishonest reporter cannot inflate a comparison. Measured.WallTimeNS is
// filled only from attested execution facts — the job started_at/finished_at
// carried by a signature-checked execution attestation and surfaced through
// the AttestationResolver seam — and stays zero when the evidence carries no
// job window. Until runners emit attested CPU/memory/cache measurements,
// those quantities deliberately remain reported.
//
// # Evidence acceptance boundary
//
// Structural binding alone is not proof: a caller can submit Result=pass with
// matching digests and an arbitrary evidence_root. The EvidenceVerifier is
// the acceptance boundary before verifyapi becomes authoritative, and it
// DERIVES authority from authenticated evidence (Model A): Verify(obligation,
// submittedClaim) cryptographically resolves the claim's evidence references
// (signed execution attestations: signatures, subject-digested evidence
// blocks, evidence roots, job status, assurance facts, observed controls,
// bound checks) and returns a server-created DerivedVerifiedOutcome whose
// Result, CompletedChecks, AssuranceProfile, ExecutionIDs, EvidenceRoot and
// Measured resource facts all come from what the signatures prove — never
// from the caller's proposal. The caller's submission is preserved verbatim
// on SubmittedClaim and authorizes nothing; a check only counts as completed
// when structured signed result evidence binds it (attestation facts, a
// test-report suite, an explicit signed check result). A pass requires the
// signed job status success AND full obligation check coverage by those
// derived checks. Only a DerivedVerifiedOutcome may be stored as
// authoritative (Registry.RecordVerifiedOutcome). Unverified submitted
// outcomes can be kept as claims (RecordOutcome) but never satisfy
// QueryOutcome as a proven pass: a claim-only id answers ErrUnverified. The
// concrete adapter (ProvenanceEvidenceVerifier) calls
// internal/provenance.VerifyWith and VerifyExecutionAttestation; the
// FuncEvidenceVerifier seam keeps those imports injectable.
//
// # Acceptance integrity (durable restore)
//
// A durable database row is never authority: the process seal cannot be
// serialized. Acceptance is the durable stand-in — Accept() computes an
// AcceptanceRecord (versioned digests of the exact (obligation, outcome,
// evidence) triple, algorithm, key id, and a MAC under the ACCEPTANCE key,
// which is separate from the runner evidence keys) at persist time, and
// RestoreVerifiedOutcome() re-checks those digests plus the MAC before
// resealing. An unsigned row, a tampered payload, a flipped verified flag or
// a wrong MAC can never produce ProvenPass. The PostgresStore read path goes
// through exactly this check.
//
// # Verifier capabilities
//
// A VerifierCapability advertises what one verifier can check (kind, version,
// claim classes, assurance levels, platforms, evidence types). The Registry
// can register and query capabilities so a caller can discover a fit
// verifier; capabilities are advertising, not enforcement — the binding rule
// and the EvidenceVerifier remain the only acceptance boundary. Class and
// level values are opaque strings defined by the verification contract
// ecosystem.
//
// # Durable store contract
//
// VerificationStore is the persistence-shaped contract over the same domain
// operations (SubmitObligation / RecordOutcome / RecordVerifiedOutcome / Get*
// / QueryOutcome / CompareGroup), with ObligationID as the submit idempotency
// key. MemoryStore is the in-process reference implementation. PostgresStore
// in internal/storage is the PRODUCTION durable implementation — it is
// deliberately not defined here so the verification contract carries no
// database drivers, schema or migrations. Host applications that need
// durability depend on VerificationStore and construct a PostgresStore in the
// storage layer.
//
// # Wire format
//
// JSON is stable and versioned as verifyapi schema v1 (SchemaVersion). Every
// wire document is a flat JSON object whose first-class domain fields match
// the Go struct field names (snake_case) plus a schema_version discriminator.
// Unmarshal refuses unknown schema versions. The codec is the single source of
// wire shape; handlers must not hand-roll JSON.
//
// # HTTP mapping
//
// The in-process Registry is the authoritative surface. An optional, additive
// HTTP facade (Handler / Mount) maps it onto /api/v1/verifications/* without
// touching the control-plane server:
//
//	POST   /api/v1/verifications/obligations       submit obligation
//	GET    /api/v1/verifications/obligations/{id}  fetch obligation
//	GET    /api/v1/verifications/obligations/{id}/outcomes
//	POST   /api/v1/verifications/outcomes          record outcome (bound)
//	GET    /api/v1/verifications/outcomes/{id}     fetch outcome
//	POST   /api/v1/verifications/groups            register speculative group
//	GET    /api/v1/verifications/groups/{id}       fetch group
//	GET    /api/v1/verifications/groups/{id}/outcomes
//	GET    /api/v1/verifications/groups/{id}/comparison
//
// Error mapping: invalid input 400, binding/freshness refusal 409, missing
// 404, duplicate 409, method not allowed 405. Bodies are verifyapi schema v1
// error documents. Mounting the facade is one line at a call site; no server
// internals, auth tiers or stores are modified by this package.
package verifyapi

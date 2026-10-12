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
// Every obligation carries a FreshnessPolicy (hard expiry and/or maximum
// age). Recording an outcome for an expired or stale obligation is refused.
// Freshness is evaluated against the registry clock at record time and
// against the outcome's own timestamps, so a backdated or post-expiry
// completion cannot launder an expired claim.
//
// # Speculative groups
//
// A SpeculativeGroup ties several candidates that were verified against one
// shared base snapshot. Outcomes inside a group expose comparable ResourceFacts
// (same field semantics, same base state) so a caller can pick among candidates
// without re-deriving measurements. Comparability is structural: CompareGroup
// refuses to line up outcomes that do not share the group's base snapshot.
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

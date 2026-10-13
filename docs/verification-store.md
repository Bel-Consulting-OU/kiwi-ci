# The Durable Verification Store

This document describes the production verification substrate: the durable
store contract, the subject and scope source-of-truth rule, and the richer
outcome surfaces that sit on top of the coarse pass/fail/partial vocabulary.

Code references name the stable symbol. Line numbers are a convenience for
the tree at the time of writing.

## 1. Store layout

`verifyapi.VerificationStore` is the durable contract. Two implementations
exist:

| Implementation | Package | Role |
|---|---|---|
| `MemoryStore` | `internal/verifyapi` | in-process reference, unit-test pin |
| `PostgresStore` | `internal/storage/verifystore` | production durable store |

The SQL schema lives in `internal/storage/migrations` (0057+). The store
package owns the read/write contract only; the migrations own the DDL.

## 2. Subject and scope source of truth (P7)

Every row carries two representations: a jsonb payload (the wire-faithful
encoding of the whole struct) and normalized columns (subject plus the
authority scope hierarchy on obligations; the same hierarchy plus the
outcome index dimensions on outcomes).

**The normalized columns are authoritative.** The payload is an encoding,
not the authority.

- The write path (`verifystore.subject_scope.go`) derives columns and
  payload from one Go value and emits them in a single write-all statement.
  A successful insert or upsert upgrade can never leave them diverged.
- The read path restores subject and scope onto the returned struct from
  the columns (`ApplyScope`). A tampered jsonb payload cannot present a
  different authority subject than the row indexes.
- Outcome index columns (`group_id`, `candidate_id`, `started_at`,
  `completed_at`) are denormalized from the claim payload, never from the
  derived verified outcome. Readers such as `CompareGroup` dispatch on the
  claim JSON, so the index must follow the claim.

Consistency predicates `ScopeConsistent` and `ClaimIndexConsistent` report
divergence. Tests pin the write-all invariant
(`subject_scope_test.go`, and the Postgres integration tests under
`internal/storage/verification_subject_scope_it_test.go`).

## 3. Evidence completeness and rich outcomes (P11)

`EvidenceCompleteness` counts the evidence items of one attempt against what
the recipe requires: `Required`, `Present`, `Verified`, `Missing`, `Invalid`.
The counters are computed (`ComputeEvidenceCompleteness`), never asserted.

Rich terminal states (`TerminalState`) say why an attempt ended:

| Terminal state | Coarse projection | Meaning |
|---|---|---|
| `passed` | pass | full coverage, valid evidence |
| `failed` | fail | a required check failed |
| `execution_error` | partial | the run errored before a verdict |
| `policy_denied` | fail | a policy gate refused the outcome |
| `evidence_incomplete` | partial | required evidence is missing |
| `evidence_invalid` | fail | presented evidence failed verification |
| `expired` | fail | the freshness window closed first |
| `cancelled` | partial | cancelled mid-flight |
| `superseded` | partial | a later attempt replaced this one |
| `unsupported` | fail | required capability not implemented |

`TerminalState.ProjectCoarse` is the deterministic projection onto
`Outcome` (pass/fail/partial). Only `passed` projects to `pass`. Outcomes
that are not proven passes carry an `UnverifiedReason` such as
`missing_required_evidence` (`OutcomeStatus`).

## 4. Verification recipes (P12)

A `Recipe` is a versioned, immutable verification demand: name, version,
requirements, assurance floor, evidence minimum, and freshness. A published
`(name, version)` pair never changes; a new rule set is a new version.
`RecipeDigest` is the stable content digest (sorted lists, UTC timestamps,
withdrawal excluded from identity).

Obligations bind a recipe by digest (`VerificationObligation.RecipeDigest`).
The digest participates in the canonical obligation digest, so the same
content under a different recipe is a different obligation. `RecipeRegistry`
publishes versions and refuses mutation of a published pair.

## 5. Proof validity versus policy acceptability (P13)

A `Proof` is an immutable historical statement. Its validity is intrinsic:
either the verification happened and bound those digests, or it did not.
Nothing later changes that.

A `PolicyEvaluation` is the current acceptability of a proof under a policy
context: withdrawn recipe, compromised key, revoked attestation, or a
freshness floor. A valid proof can be unacceptable today without becoming
historically wrong. `EvaluatePolicy` computes the denials; the proof itself
is never modified.

## 6. Neutral candidate comparison (P14)

`CandidateComparison` lines up the verification facts of several candidates:
terminal state, coarse outcome, assurance, wall time, CPU time, peak memory,
artifact size. It is neutral by type shape: no model scores, no utility, no
ranking. A scoring layer applies its own utility on top.

## 7. Epistemic levels (P10)

`EpistemicLevel` generalizes how a fact became known:
`requested` < `configured` < `observed` < `attested` < `derived`. Existing
`FactSource` values map onto the ladder (`EpistemicLevelOf`). New key facts
can be tagged with `Epistemic[T]` so consumers require a minimum rung.

## 8. Portable proof signatures (`internal/portableproof`)

`VerificationProof.Verify` re-checks the bundle under the HMAC acceptance
keyring — the durable store contract between the server and the store. A
proof that leaves that boundary (archived with an artifact, shipped to an
evidence consumer, audited by a third party) must verify without handing out
the sealing secret. `internal/portableproof` adds that asymmetric layer;
the HMAC record is retained untouched inside the proof.

**Signature schema** (`portableproof.SignatureSchemaVersion` = 1):

| Field | Meaning |
| --- | --- |
| `schema_version` | 1; unknown versions are refused |
| `algorithm` | `Ed25519` (the only algorithm) |
| `key_id` | discovery-document identity of the signing key |
| `signed_at` | operator clock at signing (audit only, not freshness) |
| `signature` | base64 raw Ed25519 signature over the exact proof JSON bytes |

`SignedProof` carries the proof as raw JSON: the signature covers the bytes
as transmitted, so any byte-level tamper is a refusal. Verification is
public-key only (`Verify` / `VerifySignedProof` / `VerifyWithDiscovery`) —
the consumer cannot forge, and the layer answers exactly one question: were
these bytes signed by the holder of the private half of this key. It does
not interpret the proof's claims and does not evaluate the HMAC record.

**Public-key discovery document** (`PublicKeyDiscovery`, schema
`DiscoverySchemaVersion` = 1) publishes each `PublicKeyDoc`: `key_id`,
`algorithm`, base64 raw `public_key`, `status` (`active` / `rotated` /
`revoked`), `created_at`, optional `superseded_by_key_id`, and an operator
`note` — the rotation / revocation explanation a consumer reads without a
second channel. `Rotate` moves the predecessor to `rotated` (historical
signatures still verify) and activates the successor; `Revoke` refuses every
signature under the key from that moment. Verification is fail closed:
unknown key id, revoked key, wrong algorithm, malformed key and any mutation
are refusals, never partial trust.

The layer is product-neutral: it speaks about evidence consumers and
external controllers, never about a specific consumer product.

## Related documents

- [evidence-contract.md](evidence-contract.md) covers the signed evidence
  envelope.
- [INVARIANTS.md](INVARIANTS.md) covers cross-surface invariants.

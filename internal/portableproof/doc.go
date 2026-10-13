// Package portableproof is the asymmetric portable-signature layer over
// verifyapi.VerificationProof.
//
// The verifyapi acceptance record is an HMAC sealed under a shared secret:
// it is the durable integrity contract between the store and the server,
// and any party holding the secret can both seal and verify. That is
// correct inside one deployment boundary, but a proof that leaves the
// boundary — shipped to an evidence consumer, archived with an artifact,
// audited by a third party — must be verifiable WITHOUT handing out the
// sealing secret. A consumer who can forge is not a consumer.
//
// This package adds that second, asymmetric signature:
//
//   - the deployment's Ed25519 acceptance-signing identity produces a
//     PortableSignature over the exact JSON encoding of the proof
//     (SignatureSchemaVersion 1, algorithm "Ed25519");
//   - a consumer holds ONLY the public key — typically discovered from a
//     PublicKeyDiscovery document — and verifies the envelope with
//     Verify / VerifyWithDiscovery;
//   - the HMAC AcceptanceRecord inside the proof is retained untouched:
//     portable verification is additive, never a replacement for the
//     internal store contract.
//
// The layer is product-neutral. It speaks about evidence consumers and
// external controllers; it names no vendor, no consumer product and no
// deployment-specific vocabulary.
//
// Rotation and revocation are first-class in the discovery document: a key
// entry carries a status (active / rotated / revoked), an operator note and
// an optional successor pointer, so a consumer can refuse a signature made
// under a key the operator has since retired. Verification is fail closed:
// unknown key id, revoked key, wrong algorithm, malformed signature and any
// byte-level change to the proof are all refusals, never partial trust.
package portableproof

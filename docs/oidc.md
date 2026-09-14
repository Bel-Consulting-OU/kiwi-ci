# OIDC

Kiwi CI's control plane is a minimal OIDC issuer so jobs can obtain
short-lived, audience-scoped identity tokens instead of static cloud
credentials.

## Discovery

- `GET /.well-known/openid-configuration` — issuer, JWKS URI,
  `id_token_signing_alg_values_supported: ["EdDSA"]`,
  `subject_types_supported: ["public"]`,
  `response_types_supported: ["id_token"]`.
- `GET /api/v1/oidc/jwks` — the public Ed25519 key (`kty: OKP`,
  `crv: Ed25519`, `alg: EdDSA`, `kid`).

The issuer is the server's `external_url`, which must be `https://` in
production (loopback `http://127.0.0.1`/`localhost` is accepted for
development).

## Requesting a token

A job requests a token through its runner:

```text
POST /api/v1/jobs/{id}/oidc
{"audience": "sts.amazonaws.com"}
```

The request must present the job's active lease. The server issues an
Ed25519-signed ID token with:

- `iss` — the external URL;
- `aud` — the requested audience;
- `sub` — `repo:<owner/name>:ref:<ref>:job:<key>`;
- `exp` — short expiry.

## Permissions and policy

- The pipeline must declare `permissions.id_token: true` on the job.
- Untrusted jobs are denied OIDC issuance entirely (hard floor).
- The effective policy's `OIDC` field is an audience allowlist; `nil`
  permits any audience (trusted default), an empty non-nil list denies
  all issuance, and a non-nil list permits only listed audiences.
- `permissions.id_token` with no allowed audiences is a policy
  violation at admission.

## Key material

The signing key material is a persisted Ed25519 key ring
(`oidc-keyring.json` in the data directory) so tokens survive restarts.
Each key carries a 32-hex `kid` derived from 16 bytes of `crypto/rand`.

## Rotation

Key rotation is fully implemented:

- active + previous verification keys, each `kid`-indexed;
- `not-before` / `retire-after` timestamps (previous keys stay
  verifiable for 72h after rotation);
- active keys older than 30 days rotate automatically at issuance;
- the trust root is never replaced atomically — previous keys remain in
  the JWKS until retired;
- the JWKS document serves `Cache-Control: public, max-age=300` and an
  `ETag` with `If-None-Match` 304 handling;
- every issuance is audited (`oidc.issued`) with job, audience, and
  `kid` metadata.

Legacy single-key files (`oidc-ed25519.key`) migrate into the ring on
load, keeping their sha256-derived `kid`.

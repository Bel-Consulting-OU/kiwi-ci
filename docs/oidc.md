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

The signing key is a persisted Ed25519 key (`oidc-ed25519.key` in the
data directory) so tokens survive restarts. The `kid` is derived from
the public key.

## TODO: rotation

Key rotation is not implemented. The current model is a single active
key with no previous-verification window:

- `kid`-indexed active and previous verification keys;
- `not-before` / `retire-after` timestamps;
- retire, then verify, then delete, so the trust root is never
  replaced atomically;
- `Cache-Control`/`ETag` on the JWKS document.

Until rotation lands, plan for a short provider-side trust window when
the key must be replaced.

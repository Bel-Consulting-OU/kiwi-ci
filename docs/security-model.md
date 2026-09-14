# Security model

Kiwi CI executes repository-controlled code, so every layer is designed
as a boundary. This document describes the trust model, the capability
policy, and the credentials that hold the system together. Deployment
guidance is in [production-deployment.md](production-deployment.md) and
[runner-security.md](runner-security.md); the adversarial view is in
[threat-model.md](threat-model.md).

## Trust modes

Every run is classified as trusted or untrusted:

- **Trusted**: pushes to the repository's own branches (or API
  submissions authenticated by a principal with trusted-run rights).
- **Untrusted**: pull/merge requests from forks, and any other
  repository-controlled input not backed by a trusted identity.

Untrusted runs read the pipeline definition from the base commit, check
out the fork code separately, and are clamped to a hard capability
floor. Trust is derived server-side; API clients cannot force it.

## Capability policy

Admission compiles an effective capability set as the intersection of
repository policy, organization policy, trust-domain policy, and the
pipeline request. Anything absent is denied
(`internal/policy/capabilities.go`):

| Capability | Meaning |
|---|---|
| `NativeExecution` | `runtime: native` on runner hosts |
| `Container` / `Tart` | container and VM runtimes |
| `Network` | strongest egress allowed (`none` < `services-only` < `internet`) |
| `Secrets` | secret-name allowlist (nil = unrestricted) |
| `OIDC` | allowed token audiences (nil = unrestricted) |
| `Deployments` | targeting protected environments |
| `CacheRead` / `CacheWrite` | cache access |
| `RunnerLabels` | allowed runner label set |
| `GenerateChildGraph` | child graph generation |
| `CrossRepoTrigger` | downstream pipelines in other repositories |

Untrusted pipelines are intersected with a hard floor: no native
execution, no network egress, no secrets, no OIDC, no deployments, and
(server-side) immutable `@sha256:` pinned images and VMs. No policy
source can lift an untrusted pipeline above the floor. `kiwi policy
check` evaluates the same admission locally.

## Leases and job identity

- Each job is leased to exactly one runner for a bounded time
  (default 45 seconds), extended by heartbeats. See
  [ha.md](ha.md).
- A lease has a generation counter. Completion is idempotent through a
  generation-bound receipt, so a retried completion cannot apply twice.
- The raw lease token exists only in runner memory. The control plane
  persists only the HMAC-SHA256 of the token under a server-local key,
  so a stolen database does not yield active capabilities.
- Cancelled or completed jobs lose their lease immediately; dead leases
  are never accepted for mutation endpoints.
- Runners self-cancel when the control plane is unreachable past the
  acknowledged lease deadline, so at most one valid generation of a job
  can execute after its lease expires.

## Runner identity and mTLS

Runners authenticate with bearer tokens or with client certificates from
the runner PKI (`internal/runnerpki`): an Ed25519 CA signs runner CSRs
authorized by a one-time enrollment token, and the certificate carries a
`spiffe://kiwi/runner/<id>` URI. With mTLS, the TLS certificate identity
must match the payload runner ID and the leased runner ID. The private
key never leaves the runner. Runners also negotiate a protocol version
(currently v3); incompatible runners are rejected, not silently
accepted.

## Secrets

- Secrets are declared in the pipeline; values are resolved by the
  server-side broker only for jobs holding an active lease, under the
  effective secret allowlist.
- Delivery uses X25519+HKDF+AES-GCM sealed envelopes opened by the
  runner, optionally with one-time semantics per (name, repository,
  environment). The server does not persist plaintext.
- On the runner, step-level secrets exist only in that step's
  environment map and are masked from logs (raw, URL-encoded, base64,
  JSON-escaped, and shell-quoted forms).
- Job-level secrets resolve once into the job environment; step secrets
  never reach other steps, cache keys, or persisted state.

## OIDC

The control plane is an OIDC issuer (Ed25519, single key) with discovery
at `/.well-known/openid-configuration` and JWKS at
`/api/v1/oidc/jwks`. Tokens are audience-scoped and issued per job under
an active lease. Untrusted jobs cannot request tokens, and audiences are
policy-controlled. Key rotation is not implemented yet; see
[oidc.md](oidc.md).

## AuthN/AuthZ for operators

Admin and API traffic uses hashed bearer tokens
(`internal/auth`): principals carry global roles (`read`, `run`,
`trusted_run`, `approve`, `cancel`, `rerun`, `artifact_read`,
`runner_manage`, `policy_manage`, `admin`) plus per-repository grants.
`run` does not imply `trusted_run`. Audit actor identity comes from the
authenticated principal, never from client-supplied headers.

## Policy enforcement points

1. **Admission** (enqueue): capability intersection, trust floor,
   component resolution, trigger matching.
2. **Lease** (dispatch): label matching, environment concurrency,
   dependency outcomes, queue quotas.
3. **Lease endpoints** (runtime): active-lease checks, declared-secret
   scoping, OIDC audiences, artifact contracts.
4. **Runner** (execution): clean environment, immutable images for
   untrusted jobs, network policy, per-step secret scoping, log masking.

# Threat model

This document enumerates threats against Kiwi CI, the mitigations in
the current codebase, and the residual risk. It is organized by
component using a STRIDE-style classification (spoofing, tampering,
repudiation, information disclosure, denial of service, elevation of
privilege). Status: **Mitigated** (implemented and tested), **Partial**
(implemented with known gaps), **Deferred** (planned, not implemented).

## Runner execution

| Threat | Class | Mitigation | Status |
|---|---|---|---|
| Job inherits host credentials via environment | I | Minimal clean env for distributed jobs; local trusted runs inherit the host env by default (`kiwi run --inherit-env=true`), with `--no-inherit-env` as the opt-out and `--pass-env=FOO,BAR` an explicit allowlist | Mitigated |
| `network: none` regains internet via services | E | Isolated service network created `--internal`; egress policy enforced by backend | Mitigated |
| Unpinned image/VM swapped by mutable tag | T | `require_immutable_images` for untrusted jobs; digest check before any docker invocation | Mitigated |
| Rootless promise not honored by daemon | E | `docker info` verification refuses rootful daemons | Mitigated |
| SSH host spoofing on Tart | S | Host authentication not disabled; workspace mounted and commands run over authenticated channel | Mitigated |
| Oversized output line deadlocks job | D | Streaming splitter drains continuously; truncation markers | Mitigated |
| Windows cancellation kills only the shell | D | Kill-on-close Job Object assigned to every child process | Mitigated |
| Cache/artifact archive escapes workspace | T/E | `safefs` extraction: no symlinks/hardlinks/devices, duplicate/`..`/absolute rejection, size/depth/ratio limits, declared roots only | Mitigated |
| Step output file read through host-side symlink | T/E | Outputs read inside the sandbox via the backend, capped at 1 MiB | Mitigated |
| Native backend executes anything | E | Policy: native denied for untrusted pipelines; trusted-only capability | Mitigated |

## Control plane (server)

| Threat | Class | Mitigation | Status |
|---|---|---|---|
| Forged webhook enqueues runs | S | Signature/token verification before any mutation (HMAC-SHA256 for GitHub/Forgejo, `X-Gitlab-Token` for GitLab) | Mitigated |
| Replayed webhook duplicates runs | S/T | Delivery ID dedupe, persisted; retries return the original run | Mitigated |
| Fork PR reads secrets or runs native | E | Base-commit pipeline fetch; untrusted capability floor (no secrets/OIDC/native/egress) | Mitigated |
| API client forces `trusted: true` | S | Trust derived server-side; DTO field removed | Mitigated |
| Spoofed actor on approve/cancel | S | Actor from authenticated principal; `X-Kiwi-Actor` not trusted | Mitigated |
| Raw lease token stolen from storage | I | Only HMAC-SHA256(token, server key) persisted; raw token never stored | Mitigated |
| Cancelled job keeps mutation rights | E | Active-lease check requires `status=running` + expiry + runner + generation; lease cleared on cancel/complete | Mitigated |
| Completion replay applies twice | T | Generation-bound completion receipts, idempotent transaction | Mitigated |
| Server restart duplicates running jobs | T | Unexpired leases preserved; force-requeue only after expiry | Mitigated |
| Credential leak via redirect | I | Forge clients and ops CLI never follow redirects | Mitigated |
| Request flooding | D | Per-class token buckets (webhooks, next, heartbeat, logs, uploads, enroll, oidc, ...) keyed by principal/runner/IP; bounded bucket map | Mitigated |
| Unauthenticated dashboard/session abuse | S/D | Session cookies HMAC-signed, CSRF tokens on mutating routes, login rate-limited | Mitigated |
| Unbounded YAML parser input | D | 2 MiB source, 1 MiB scalars, depth 100, 1M nodes, alias/merge/tag rejection | Mitigated |
| Giant pipeline expands unboundedly | D | Declared/expanded job, matrix, step, service, secret, env, artifact, output limits | Mitigated |
| Untrusted OIDC token minting | E | Untrusted floor denies; audience allowlists; lease-bound issuance | Mitigated |
| Secret replay outside its job | I | One-time delivery per (name, repo, env); per-step scoping; sealed envelopes | Mitigated |
| Policy files bypassed | E | Capability intersection is the single admission path; untrusted floor cannot be lifted | Mitigated |
| SQL injection / invalid IDs | T | Parameterized queries; 32-hex identifier validation before SQL | Mitigated |
| Stolen bearer tokens | S | Hashed token store; admin/runner separation; mTLS enrollment as the strong path | Partial (bearer mode remains supported) |

## Scheduler and storage

| Threat | Class | Mitigation | Status |
|---|---|---|---|
| Two leaders lease the same job | T | Advisory lock + conditional `UPDATE ... WHERE status='queued'` | Mitigated |
| Lost runner strands a job forever | D | Lease expiry, requeue within `infra_retries`, else fail; dependents recomputed | Mitigated |
| Runner keeps executing after losing contact | T | Runner self-cancels at acknowledged deadline minus margin | Mitigated |
| Audit trail forged or lost | R | Server-side audit events with principal actor; DB-mode append failures logged, never silently dropped | Mitigated |
| Multi-instance divergence | T | Postgres is the source of truth in DB mode; in-memory maps dev-only | Mitigated |
| State snapshot corruption (fs mode) | T | Atomic temp+rename snapshot; append-only logs | Mitigated (dev scope) |
| Schedules fired twice | T | Nominal occurrence claims idempotent by (schedule ID, nominal) across restarts and leaders | Mitigated |

## Secrets

| Threat | Class | Mitigation | Status |
|---|---|---|---|
| Secret visible in logs | I | Compiled multi-form masking (raw, URL, base64, JSON, shell-quoted) at source and sinks | Mitigated |
| Step secret reaches other steps | I | Per-step env maps; fresh cache per step | Mitigated |
| Secret values in cache keys or state | I | Secrets resolved after key computation; never persisted | Mitigated |
| Broker delivers to wrong job | E | Lease-scoped resolution; declared-secret allowlist compiled at enqueue | Mitigated |
| Broker plaintext in transit | I | X25519+HKDF+AES-GCM envelopes to runner ephemeral key | Mitigated |
| Static provider keys on the server | I | Provider clients are configured by the operator; no plaintext persistence | Partial (operator policy) |

## Forge integrations

| Threat | Class | Mitigation | Status |
|---|---|---|---|
| Token sent to wrong host on clone | I | Host-scoped credentials; canonical host allowlist; redirect-free clients | Mitigated |
| App private key exposed in API calls | I | JWT minting server-side; installation tokens cached short-lived | Mitigated |
| Status publication lost on restart | R | Durable outbox with idempotent external IDs | Mitigated |
| Arbitrary pipeline text from fork | E | Base-commit fetch for untrusted PRs | Mitigated |

## OIDC

| Threat | Class | Mitigation | Status |
|---|---|---|---|
| Token minted for wrong audience | E | Audience allowlist per policy; per-job subject | Mitigated |
| Key compromise with no rotation path | T/I | Key ring with 30-day active rotation and 72h previous-verification window | Mitigated |
| Issuer spoofing via lookalike URL | S | Scheme must be `https://` (exact loopback allowed for dev) | Mitigated |

## Residual risks to track

1. **OIDC key rotation** — the key ring keeps a rotated-out signing key
   in the JWKS for a 72-hour previous-verification window, so tokens it
   signed stay verifiable across a rotation; a compromise is still a
   live-key event, but verifiers are not cut off immediately and no
   provider reconfiguration is forced within the window
   (`internal/server/oidc.go`: `oidcPreviousKeyRetireAfter`).
2. **Bearer-token runner mode** — shared runner tokens remain a
   supported configuration; prefer enrollment-based mTLS in multi-tenant
   environments.
3. **Deployment/snapshot records** — persist durably: through
   `DeploymentStore`/`SnapshotStore` in PostgreSQL mode (`deployments`,
   `workspace_snapshots` tables) and through the data-dir state file in
   filesystem mode. They are lost on restart only in the stateless
   in-memory dev mode (no database and no `--data-dir`).
4. **SBOM/Sigstore gates** — implemented as server-side artifact
   contract gates: a declared `sbom` format is validated on upload, and
   a `sigstore` gate is cryptographically verified against configured
   trust roots. A missing or invalid required attestation fails the
   upload (SBOM payload `400`, contract and Sigstore verification
   `422`), and a required Sigstore gate with no configured trust root
   fails closed (`422`) rather than being skipped
   (`internal/server/supplychain_gate.go`).
5. **OpenTelemetry export** — implemented: setting
   `observability.otel_endpoint`/`--otel-endpoint` installs an OTLP/HTTP
   exporter that emits request, forge-intake, enqueue, lease and
   completion spans (`internal/server/tracing.go`). There is no
   OpenTelemetry metrics/log pipeline yet.
6. **Windows Job Object cancellation** — process-group kill covers
   common cases but not all descendants.

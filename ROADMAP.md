# Kiwi CI roadmap to v1

## P0 — correctness and security

- Persistent PostgreSQL store with migrations and idempotent event processing.
- GitHub App, GitLab, Forgejo/Gitea adapters with verified webhook signatures before any mutation.
- mTLS runner enrollment with short-lived certs and runner identity binding.
- Job-level leases with expiry, generation, heartbeat, orphan recovery, and idempotent completion.
- Secret broker with scoped, one-time envelopes; Vault, 1Password, AWS/GCP/Azure secret providers.
- OIDC issuer with per-job subject/audience claims and cloud federation examples.
- Signed cache/artifact manifests, tenant scoping, configurable S3-compatible CAS.
- Reproducible Tart snapshot lifecycle and rootless container backend.
- Strong cancellation tests, retry classification (`command`, `infra`, `timeout`, `lost_runner`).

## P1 — developer experience

- `kiwi init` interactive generator.
- JSON Schema + VS Code completion for pipeline YAML.
- `kiwi explain --why JOB` including every condition and path decision.
- Live TUI with searchable/virtualized logs and collapsible steps.
- Web UI: DAG visualization, critical path, queue time, cache hit rate, runner saturation, log search.
- Pipeline debugger: rerun one failed step against the exact workspace snapshot.
- Reusable, typed, versioned components with immutable digest pinning and a local component registry.
- Native migration importer for GitHub Actions, GitLab CI, CircleCI, and Woodpecker.

## P1 — speed

- Merkle-tree workspace snapshots and remote CAS.
- Automatic lockfile/toolchain cache inference with transparent cache explanations.
- Historical duration-aware scheduling and critical-path prioritization.
- JUnit/test-result history, flaky-test quarantine, deterministic test splitting, retry only failed tests.
- Monorepo impact graph from Git diff + declared package dependencies; skip unaffected jobs safely.
- Speculative prewarming of runner images/VMs and dependency caches.

## P1 — pipeline power

- Job-level heterogeneous runners in one DAG (macOS + Linux + Windows).
- Dynamic pipelines with typed generated graph fragments and pre-execution validation.
- Parent/child and cross-repository pipelines with explicit artifact contracts.
- Manual approvals, protected environments, deployment locks, canary/rollback hooks.
- Concurrency groups and merge queues with superseded-run cancellation.
- Services for container jobs and VM-local service orchestration for macOS.
- Scheduled, manual, API, push, PR/MR, tag, release, merge-queue, and custom events.

## P2 — governance and observability

- Policy-as-code admission layer (OPA/Rego or CEL) for runner, secret, network, image and deploy policies.
- OpenTelemetry traces, metrics and logs from control plane through every runner step.
- Signed SLSA provenance, SBOM attachment, Sigstore keyless signing, verification gates.
- Full audit log and organization/repository RBAC.
- Cost/energy accounting and per-team quotas without hiding queue decisions.
- HA server, distributed scheduler, regional runner pools, graceful upgrades, schema compatibility checks.

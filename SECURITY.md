# Kiwi CI security model

CI executes repository-controlled code, so the runner is a security boundary.

## Rules

1. Never run untrusted pull requests with `runtime: native` on a personal or long-lived Mac.
2. Use `runtime: tart` for untrusted macOS workloads and destroy the cloned VM after each job/run.
3. Never send secret values in the compiled DAG or queue payload.
4. Resolve secrets only after a runner accepts an authorized task.
5. Mask secrets before logs leave the runner. Kiwi also masks at the console sink.
6. Prefer short-lived OIDC credentials to cloud-provider static keys.
7. Pin reusable components/actions by immutable digest or signed release.
8. Treat caches and artifacts as untrusted input. Kiwi validates extraction paths; production deployments should also sign cache manifests and enforce tenant scopes.
9. Give runners least privilege and separate deployment runners from ordinary build runners.
10. For public multi-tenant deployments, require mTLS runner identity, PostgreSQL row-level tenancy, object-store tenant prefixes, and policy enforcement before dispatch.

## Current v0.1 limitations

The included HTTP control plane is a reference implementation, not yet a hardened internet-facing SaaS. It intentionally keeps the protocol small and auditable. Before public exposure, add TLS, persistent storage, forge authentication/webhook verification, RBAC, rate limits, CSRF protection for mutating browser endpoints, audit logs, and signed runner enrollment.

# Runner security

The runner executes repository-controlled code and is therefore the
highest-value target in a Kiwi deployment. This document describes the
isolation the runner applies and how to operate it safely.

## Environment isolation

Remote jobs run in a minimal clean environment built by the runner:
`PATH`, `LANG`, `LC_ALL`, `CI`, `KIWI`. The host environment (HOME,
SSH_AUTH_SOCK, cloud credentials, tokens) never leaks into a remote job.

Two opt-in flags exist for local trusted runs only:

- `kiwi run --inherit-env` — inherit the full host environment;
- `kiwi run --pass-env=FOO,BAR` — allowlist specific host variables.

Distributed runners must never enable environment inheritance.

## Workspaces

- Local runs get one isolated workspace per job (git worktree, APFS
  reflink copy, or plain copy), so parallel matrix jobs cannot observe
  or clobber each other (`internal/workspace`).
- Remote runs get a fresh per-task clone on the runner.
- Working directories are resolved through symlinks and rejected if
  they escape the workspace.

## Backend hardening

### Container

Jobs run in a single long-lived container with:

- `--cap-drop=ALL` and `--security-opt=no-new-privileges`;
- `--init` and workspace bind mount;
- network `bridge`, `host`, or `none` per job;
- `sandbox.rootless` verifies the Docker daemon is actually rootless
  (`docker info`) and refuses otherwise;
- `sandbox.read_only_rootfs` mounts the root filesystem read-only with
  `nosuid,nodev` tmpfs for `/tmp` and `/run`;
- service containers join a dedicated network, which is created
  `--internal` when egress is `none` or `services-only`.

Untrusted jobs must use `@sha256:` pinned images
(`require_immutable_images`); unpinned images are rejected before any
Docker invocation.

### Tart

Tart jobs run in a disposable VM cloned per job and deleted afterwards.
SSH host authentication is not disabled; the workspace is mounted into
the VM and commands run over an authenticated channel. Untrusted jobs
must pin `vm` references by digest, and `sandbox.network: none` fails
closed (the Tart backend refuses jobs that would need networking).

### Native

Native execution runs on the host in its own process group so
cancellation terminates children. It is available only to trusted
pipelines and should be restricted to dedicated runner machines.

## Logs and secrets

- Log lines are masked at the source with compiled multi-form patterns
  (raw, URL-encoded, base64, JSON-escaped, shell-quoted) and again at
  display sinks.
- Step output files (`KIWI_OUTPUT`) are read through the backend inside
  the sandbox, never host-side, and are capped at 1 MiB.
- Long lines are streamed without ever stopping to drain, so a job
  emitting oversized lines cannot deadlock execution.

## Self-cancellation

The runner tracks the acknowledged lease deadline. If the control plane
stops answering heartbeats and the deadline (minus a 2-second safety
margin) passes, the runner cancels the job itself. This preserves the
invariant that at most one valid generation of a job runs after its
lease expires; the control plane requeues the job independently, within
the job's infrastructure retry budget.

## Operating advice

- Run untrusted jobs only through `container` or `tart` backends on
  machines with no valuable host credentials.
- Use a rootless Docker daemon and digest-pinned images for
  container jobs.
- Give each runner a dedicated enrollment: a per-runner certificate via
  the single-use enrollment grant/token flow, and revoke the certificate
  when a runner is decommissioned. The runner BEARER token is a shared
  credential across all runners — it is not a per-runner identity, and a
  bearer-token deployment cannot attribute traffic to one runner or
  revoke one runner without rotating the shared token. Prefer persistent
  mTLS identities in production.
- Keep deployment-capable runners separate from ordinary build runners
  (see [environments.md](environments.md)).
- Drain runners before maintenance: `kiwi runner drain <id>`.

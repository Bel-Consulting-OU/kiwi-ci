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
- The remote runner creates the per-job workspace root with `os.MkdirTemp`
  (`kiwi-run-*`): mode `0700`, owned by the runner's uid/gid. Nothing is
  world-readable or world-writable at rest.
- Working directories are resolved through symlinks and rejected if
  they escape the workspace.

### Container workspace ownership (hardened jobs)

A hardened container job (`sandbox.rootless` or
`sandbox.read_only_rootfs`) must be able to traverse and write the
bind-mounted checkout without the checkout ever becoming world-writable.
The executor decides this purely from the daemon kind
(`planHardenedContainer`):

| daemon   | workload identity | workspace root | ownership                 | host-side provisioning |
|----------|-------------------|----------------|---------------------------|------------------------|
| rootless | `0:0` in the user namespace | unchanged `0700` | stays runner-owned | none: container root already maps to the runner uid; the user namespace is the isolation boundary |
| rootful  | `65534:65534` (`nobody`) | `0711` traverse-only | chowned to `65534:65534` for the container lifetime | `provisionContainerWorkspace` before `docker run` |

Rules that keep this safe:

- The rootful provisioning refuses to touch a tree the runner does not
  own (validated entry by entry before any `chown`; symlinks are
  `lchown`ed, never followed). A partial failure rolls the root mode
  back; a non-root runner gets a clear provisioning error instead of a
  container that cannot read its own workspace.
- Restore runs when the job ends (including failed starts): every entry
  is chowned back to the runner uid/gid and the original root mode
  (`0700`) is reinstated, so artifact capture, snapshots, test reports
  and `os.RemoveAll` all see runner-owned files again. Restore is
  idempotent and its errors are surfaced as cleanup warnings.
- The `0711` root only grants traversal: inner entries are chowned to
  the workload instead of being opened up, and no job ever gets a
  world-writable workspace.
- Rootless daemons never force `--user=65534:65534`: on a user-namespaced
  daemon that uid maps to a subordinate host uid which cannot access the
  runner-owned mount. The workload runs as namespace root and files
  created in the bind mount stay runner-owned on the host.

`internal/runner/rootless_integration_test.go` (gated by
`KIWI_TEST_DOCKER=1`) proves the contract end to end: the job writes a
file through the mount, an artifact uploads from the host-side tree, the
host sees runner ownership and the restored `0700` mode afterwards, and
a rootless daemon reports container root while the host file stays
runner-owned.

## Backend hardening

### Container

Jobs run in a single long-lived container with:

- `--cap-drop=ALL` and `--security-opt=no-new-privileges`;
- `--init` and workspace bind mount (ownership prepared per the
  decision table above);
- network `bridge`, `host`, or `none` per job;
- `sandbox.rootless` verifies the Docker daemon is actually rootless
  (`docker info`) and refuses otherwise; a verified rootless daemon then
  runs the workload as namespace root (`0:0`) so the bind mount stays
  runner-owned on the host;
- `sandbox.read_only_rootfs` mounts the root filesystem read-only with
  `nosuid,nodev` tmpfs for `/tmp` and `/run`; on a rootful daemon the
  workload drops to `65534:65534` and the workspace is provisioned as
  described in "Container workspace ownership";
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

# Woodpecker behavioral equivalence

Kiwi architecture is unchanged. This document is **not** a compatibility
layer, a Woodpecker-shaped API, or a plan to downgrade Kiwi to a foreign CI
model. Kiwi keeps its own pipeline language, compiled jobs, execution
semantics, sandbox policy, and verification substrate.

What this document states is a **capability and outcome contract**:

> Everything Woodpecker can express and run, Kiwi must also express and run —
> in Kiwi's own architecture — and the observable outcomes must be equivalent.

## What equivalence means

For a workflow that can be stated in either system, the two runs are
equivalent when a normalized trace matches on:

| Axis | Compared |
|---|---|
| Trigger | event, branch/tag/path filters, manual/cron |
| Graph | job set, dependency edges, topological order constraints |
| Steps | order inside a job, images, commands, working directories |
| Environment | job/step env after interpolation and matrix expansion |
| Services | names, images, health/lifecycle |
| Gate outcomes | run / skip / condition-gated / continue-on-error / abort |
| Failure propagation | which dependents run, which are skipped or cancelled |
| Workspace effects | checkout shape, submodules, LFS, sparse paths |
| Artifacts & caches | produced names/paths, restore keys |
| Reported status | terminal status posted to the forge |

Differences that are **policy** (Kiwi refuses privileged on untrusted jobs,
bind-mounts, or host network) are not "incompatibilities to paper over". They
are security posture. Those constructs are either:

- first-class and **trust-gated** (privileged, host_path volumes), or
- intentionally absent and refused at admission.

They must never be silently approximated.

## Native capability inventory (Kiwi fields)

These are Kiwi pipeline fields — same architecture as every other job
dimension. The Woodpecker importer maps foreign YAML onto them; it does not
own them.

| Woodpecker concept | Kiwi field | Notes |
|---|---|---|
| sequential steps | `steps[]` + chained `needs` | definition order |
| `depends_on` | `jobs[].needs` | DAG |
| `when.branch` / `branches` | `on.push.branches` / `job.if` | |
| `when.path` | `on.*.paths`, `job.paths` | |
| `when.event` | `on.push`, `on.pull_request`, `on.schedule` | |
| `when.status` / `failure()` | `job.if`, `step.if`, `continue_on_error` | |
| matrix | `job.matrix` | per-job |
| services | `job.services[]` | healthcheck, retries, timeout |
| environment | `job.env`, `step.env`, `spec.env` | |
| secrets | `spec.secrets`, `step.secrets` | broker-scoped |
| registry credentials | `job.registries[]` | secret-backed, job-scoped `DOCKER_CONFIG` |
| step timeout | `step.timeout` | |
| pipeline timeout | `job.timeout`, `defaults.timeout` | |
| retry | `job.retry`, `step.retry` | capped |
| workspace base/path | `job.workspace.base`, `job.workspace.path` | under runner root |
| clone depth | `job.clone.depth` | |
| skip clone | `job.clone.skip` | |
| submodules | `job.clone.submodules` | recursive |
| Git LFS | `job.clone.lfs` | |
| custom clone (sparse) | `job.clone.sparse_paths` | |
| volumes (named) | `job.volumes[]` | job-scoped docker volumes |
| volumes (host) | `job.volumes[].host_path` | **trust-gated** |
| privileged | `job.sandbox.privileged` | **trust-gated** |
| `failure: cancel` | `step.cancel_job_on_failure` | stops remaining steps |
| `failure: ignore` | `step.continue_on_error` | |
| `detach: true` | `step.background` | start and continue |
| labels / placement | `job.placement`, `job.runner` | |
| artifacts | `job.artifacts[]` | |
| caches | `job.cache[]` | |
| network modes | `job.network`, `job.sandbox.network` | |

## Trust-gated constructs

These exist as Kiwi capabilities. Admission and executor enforcement decide
who may use them. Untrusted work (fork PRs, untrusted native) is refused —
never quietly downgraded to a weaker isolation claim.

| Construct | Gate |
|---|---|
| `sandbox.privileged` | policy grant (`Capabilities.Privileged`) + untrusted refused at admission **and** container backend |
| `volumes[].host_path` | policy grant (`Capabilities.HostMounts`) + untrusted refused at admission **and** container backend |
| `network: host` | trusted / policy ceiling |
| native runtime | trusted only (untrusted native is policy-forbidden) |

These are enforced in `internal/policy` (admission) and `internal/executor`
(container backend, defense in depth) — never importer TODOs or silent
drops.

## Equivalence corpus

`compat/woodpecker/` holds paired fixtures. Each fixture directory is one
workflow:

```
compat/woodpecker/<name>/
    .woodpecker.yml     # source workflow
    expected.json       # normalized Kiwi outcome trace (schema below)
```

The machine-checked claim is: importing the source and compiling it in Kiwi
produces exactly `expected.json` — trigger, graph, order, env, skip and fail
states. When a live Woodpecker is available, the same workflow is executed
there and its normalized trace is compared against the same file.

Trace schema: `kiwi.woodpecker-equivalence-trace/v1`.

Corpus suites (expand until every Woodpecker construct is covered):

| Suite | Covers |
|---|---|
| `simple/` | sequential steps |
| `dependencies/` | `depends_on` DAG |
| `conditions/` | `when` / branch / event |
| `secrets/` | secret interpolation |
| `cancellation/` | cancel / abort semantics |
| `services/` | service health and lifecycle |
| `matrices/` | matrix expansion |
| `clone/` | depth, submodules, lfs, skip, sparse |
| `workspace/` | base/path placement |
| `volumes/` | named volumes; host mounts refused when untrusted |
| `failures/` | failure: fail/ignore, continue_on_error |
| `pull-request/` | PR events and fork refusal |
| `tags/` / `cron/` / `manual/` / `deployment/` | remaining triggers |
| `hostile/` / `pathological/` | adversarial inputs |

## What is explicitly out of scope

- Re-implementing Woodpecker's server/agent protocol or DB schema.
- Accepting Woodpecker-only security escapes (privileged untrusted jobs,
  arbitrary host mounts) to claim "100% YAML acceptance".
- A permanent "Woodpecker mode" that forks Kiwi's execution semantics.

Import is a **migration aid**. Long-term, pipelines are written in Kiwi's
language. Equivalence is proven so cutover is safe; the architecture that
runs the work is always Kiwi's.

# Kiwi dogfood — 360° self-validation

This document is the operating contract for Kiwi's dogfood program. After the
execution-assurance fixes (quota truthfulness, effective/observed consistency),
the architecture is frozen: the principal correctness engine becomes continuous
self-validation under hostile conditions.

## Objective

A real Kiwi installation must continuously prove it can:

```text
receive work → authenticate it → admit it → construct the graph → schedule it
→ execute it → survive failures → store its outputs → enforce authority
→ emit truthful evidence → replay/recover it → upgrade itself → operate at scale.
```

`.kiwi/pipeline.yaml` remains **DF0 — Source Integrity**. It is not replaced.

## Three test species

Do not call all three "dogfood" — the suite will otherwise look stronger
than the guarantees it provides.

| Species | What it is | What it proves |
|---|---|---|
| **Model** | `internal/dogfood` in-memory harness/oracle | state-machine invariants, combinatorial races, deterministic faults |
| **Component** | real production packages in-process (store, provenance, executor) | package-level contracts against real implementations |
| **System** | real `server.NewPersistent` + real HTTP API + real `runner.Runner` (loopback listener / goroutines in-process; multi-process topology is the DF2 wave) | HTTP → auth → store → generation → ledger → artifacts as a whole |

`internal/dogfood/harness.go` is the **reference/model** layer. System
dogfood lives in `internal/dogfood/system/` (`system.System / system.Launch`: real
`server.NewPersistent` + HTTP listener + `runner.Runner` / register-next-complete
over the public API). Model scenarios stay valuable as the differential
oracle against that system.

## Three actors

Do not make Kiwi the sole judge of whether Kiwi works.

```text
OUTER ORACLE / DOGFOOD HARNESS
  launches Kiwi, creates test repos/runs, injects failures,
  kills/restarts server and runners, queries public APIs,
  read-only inspects authoritative state, verifies signed evidence,
  observes fake external-effect sinks, checks cleanup/liveness
        │
        ▼
KIWI SYSTEM UNDER TEST
  server → scheduler → runner → executor
        → ledger → DB → cache → artifacts → evidence
        │
        ▼
CONTROLLED DEPENDENCIES
  fake forge · Postgres · S3-compatible storage
  fake OIDC RP · fake deployment target · fake secret broker
  hostile/slow/failing endpoints
```

Rules:

- The harness **never mutates Kiwi's database** to make a scenario pass.
  Direct DB access is a **read-only secondary oracle** only.
- Primary validation goes through the same CLI/API/protocol surfaces real
  customers use.
- A test inside Kiwi cannot prove Kiwi survives being killed. The outer
  harness can.

## Tiers

| Tier | Name | Cadence | Question it answers |
|---|---|---|---|
| DF0 | Source integrity | every PR | Is this commit internally sane enough to launch Kiwi? |
| DF1 | Local product lifecycle | every PR after DF0 | Does a fresh `kiwi up` complete a full lifecycle? |
| DF2 | Distributed topology | every merge to main | Does a real multi-process topology work? |
| DF3 | Adversarial distributed | nightly | Do safety **and** liveness hold under attack? |
| DF4 | Cross-version | nightly + RC | Do the documented compatibility promises hold? |
| DF5 | Production-integrations canary | scheduled, non-PR | Is the real forge/provider path drifting? |
| DF6 | Scale / endurance / recovery | scheduled + RC | Does a fixed workload finish cleanly and return to baseline? |
| DF7 | Release-candidate | RC-blocking | Does the **exact release artifact** pass? |

## Two-generation self-hosting closure

Signature dogfood: an outside trusted runner builds G0; G0 schedules a real
Kiwi build of the same source as G1; G1 builds G2.

Require (not byte-identical binaries unless bit-reproducibility is guaranteed):

- identical source identity
- expected dependency identity
- expected execution semantics
- successful behavioral conformance
- valid attestations
- compatible verifier behavior

Generation limit: harness records `G0/G1/G2` and refuses unintended recursion.

## Evidence dogfood (first-class)

Every signed security fact gets positive **and** negative proof.

### Quota truthfulness

```text
hard quota configured + successfully installed  → workspace_quota_enforced = true
quota requested + hard quota unavailable + fallback measurement → false
quota setup fails before execution → false
no quota requested → false
untrusted job requiring hard quota + quota unavailable → execution rejected
```

Never derive the attested result from configuration alone.

### Effective/observed consistency

Construct contradictory receipts through a hostile test runner
(`internal/dogfood/hostile`). Signing must fail. Verification of a crafted
signed fixture must also fail.

### Tamper matrix

Independently modify commit, runner ID, job ID, attempt, artifact digest,
policy digest, graph fingerprint, execution semantics, assurance facts,
external effects, event frontier. Every mutation must fail verification.

### Secret privacy

Inject canary secrets (`KIWI_DOGFOOD_SECRET_<hex>`). After execution
recursively inspect evidence, logs, snapshots, artifacts (unless explicitly
produced), event payloads, API responses. The canary must not appear where
forbidden.

## Hostile runners

A correct server must not assume every runner behaves correctly. Test-only
modes live in `internal/dogfood/hostile`:

```text
stale-generation · duplicate completion · wrong-runtime receipt
contradictory assurance · artifact hash liar · late logger
never-heartbeat · completion-before-artifact · wrong job · protocol downgrade
```

(`artifact-after-completion` is a planned mode; the implemented closed set is
the ten names above, exercised by `TestNewModeMatrix`.)

The server signature means: *Kiwi validated and accepted this evidence
according to its trust model.* Malformed or self-contradictory runner
statements must be rejected before signing.

## Eight-oracle rule

For important scenarios, success is not "process exited 0". Validate up to
eight independent surfaces (`internal/dogfood.Oracle`):

1. Client result
2. Authoritative state
3. Ledger
4. Runner authority (claim generation/ownership)
5. Artifacts/cache
6. Evidence
7. External effects (fake sink count is authoritative)
8. Recovery (same truth after restart/reconnect)

Critical scenarios fail if these disagree.

## Safety **and** liveness

Every adversarial test answers both:

```text
Did Kiwi prevent the bad thing?
Can Kiwi continue doing the good thing afterward?
```

A system that fails closed by becoming permanently wedged has not passed.

## No hidden retries

Dogfood infrastructure exposes attempt count, retry cause, first-attempt
result, final result. A scenario that succeeds on retry but failed first
attempt is **non-green** unless the retry itself was the behavior under test.

## Random seeds

Race/chaos scheduling may be randomized, but every run records seed, scenario,
commit, server/runner version, OS, executor, DB/storage/execution-semantics
version, policy digest. A failing chaos run must be exactly reproducible.

## Deterministic fault injection

Prefer pause hooks over sleeps:

```text
after-state-mutation-before-ledger
after-object-upload-before-finalize
after-winner-CAS
before-evidence-signature
after-lease-expiration-before-reclaim
```

Hooks pause; they never alter production semantics. Compiled/enabled only for
dogfood.

## Invariants get executable proofs

See `docs/INVARIANTS.md`. Each invariant gets:

```text
unit/property test
+ adversarial integration test
+ at least one system dogfood scenario where practical
```

Examples: single authoritative terminal result; transition/ledger atomicity;
stale lease cannot mutate authority; authorized event recovery; replay cannot
silently introduce effects; dynamic mutation cannot rewrite committed history;
speculation has one committer; terminal states are monotonic; credentials never
exceed execution authority; untrusted execution cannot poison trusted cache.

## Public-surface coverage is measurable

Machine-readable mapping: `public capability → dogfood scenario IDs`
(`docs/DOGFOOD_MATRIX.md`). A new CLI/API/schema feature requires dogfood
coverage or an explicit `dogfood_not_applicable: <reason>` that code review
can challenge. Enforce the mapping in review today; an automated
`surfacecheck` gate for the matrix is planned (the existing surfacecheck
guards cover DF0 pipeline markers, package test presence, and script
inventory).

## Scenario IDs

```text
DF-BOOT-*       bootstrap/local operation
DF-SELF-*       self-host generations
DF-DIST-*       distributed topology
DF-FORGE-*      webhook/forge
DF-AUTH-*       authentication/authorization
DF-DAG-*        graph behavior
DF-SCHED-*      scheduler
DF-LEASE-*      fencing/leases
DF-RUNNER-*     runner behavior
DF-EXEC-*       executor/isolation
DF-ART-*        artifacts
DF-CACHE-*      caching
DF-EVENT-*      ledger/event recovery
DF-SNAP-*       snapshots
DF-REPLAY-*     replay
DF-SPEC-*       speculation
DF-CAP-*        capabilities/OIDC
DF-EFFECT-*     external effects
DF-EVID-*       evidence
DF-CHAOS-*      process/network faults
DF-UPGRADE-*    version transitions
DF-DR-*         backup/recovery
DF-SCALE-*      performance/endurance
DF-CLI-*        CLI
DF-RELEASE-*    packaging
```

IDs appear in scenario implementation, `DOGFOOD_MATRIX.md`, invariant mapping,
CI output, and failure reports.

## Implemented vs planned

The harness, oracle, hostile runner, fakes and the scenario kernel below are
**implemented and green** under `make dogfood-*`. Suites whose live
multi-process topology (real postgres/objectstore, packaged-binary install,
10k-job soak) is not yet online still run their harness-level proofs through
`scripts/dogfood-run.sh`, which **fails closed** on a filter that matches
zero tests.

| Implemented now | Planned next wave |
|---|---|
| DF-BOOT-001, DF-EVID-001..005, DF-LEASE-001/002, DF-QUOTA-001, DF-EFFECT-001/002, DF-SELF-001 (G0/G1/G2 limit), DF-UPGRADE-001 (evidence compat), DF-SCALE-001 (harness workload) — **model species** | live DF2 multi-process topology, DF3 process/network chaos, DF4 N-1 binary matrix, DF5 real-forge canary, DF6 10k-job soak, DF7 packaged-binary install |
| DF-BOOT-001 / DF-EVID-001 / DF-LEASE-001 / DF-QUOTA-001 — **system species** via `TestSys*` in `internal/dogfood/system/` (real `NewPersistent` + HTTP + runner). Fail-closed arms (stale lease generation → 409, untrusted hard-quota gate, untrusted rootless floor) always run. Boot/restart and evidence success arms run an untrusted container job when rootless Docker satisfies the untrusted policy floor, and otherwise run a TRUSTED native job through the product trusted ingress (`TestSysTrustedIngress` signed GitHub webhook, `TestSysTrustedScheduleIngress` trusted schedule) — so they execute on hosts without rootless Docker instead of skipping. Direct API submissions stay untrusted (the product force-clears `Trusted`); the store is never mutated to fake trust. | postgres/objectstore system topology, real-forge webhook canary |
| G0/G1/G2 recursion refusal (`Harness.BeginGeneration`) | full G0→G1→G2 self-build of a release binary |
| `dogfood-result.json` shape (`MarshalResult`, `TestDogfoodResultJSONShape`) | suite-level artifact emission of the result bundle on disk |
| DF0 `.kiwi/pipeline.yaml` + dogfood YAML schema validation | surfacecheck gate over DOGFOOD_MATRIX.md |

## Highest-value initial set

```text
DF-BOOT-001     clean local bootstrap and restart
DF-SELF-001     G0 → G1 self-build
DF-SELF-002     G1 → G2 self-build

DF-DIST-001     server + two real runners + production storage
DF-LEASE-001    stale runner after reassignment
DF-LEASE-002    completion vs lease expiry race

DF-EVENT-001    scoped retention/recovery
DF-EVENT-002    snapshot-to-stream concurrent handoff

DF-ART-001      crash through artifact finalization boundaries
DF-CACHE-001    untrusted-to-trusted cache poisoning attempt

DF-DAG-001      dynamic graph expansion
DF-DAG-002      graph mutation + cancellation + restart

DF-SPEC-001     three speculative candidates / one committer
DF-SPEC-002     server crash during winner selection

DF-EFFECT-001   valid winner external effect exactly once
DF-EFFECT-002   loser/stale runner external effect zero

DF-EVID-001     evidence generation and verification
DF-EVID-002     full evidence tamper matrix
DF-EVID-003     effective/observed mismatch rejection
DF-EVID-004     hard quota truthfulness
DF-EVID-005     secret absence scan

DF-UPGRADE-001  N-1 state → N
DF-UPGRADE-002  supported mixed runner/server versions

DF-DR-001       backup → destruction → restore → replay

DF-SCALE-001    fixed high-volume lifecycle
DF-SCALE-002    runner churn/resource-leak test

DF-RELEASE-001  fresh install from final release artifact
```

## Execution cadence

| Trigger | Suites |
|---|---|
| Pull request | DF0, DF1, critical evidence, critical lease/fencing |
| Main branch | + DF2, self-host G0→G1→G2, artifact/cache/event/replay/speculation |
| Nightly | + DF3 chaos, DF4 compatibility, larger fuzz/property, formal models, storage failures, event retention, backup/restore, perf smoke |
| Scheduled deeper | + fixed-workload endurance, large DAG, high runner churn, real-provider canary, resource-leak detection |
| Release candidate | everything applicable + previous-release upgrade, actual release package install, DR, full evidence tampering, full platform/executor matrix |

## Makefile entry points

```text
make dogfood-fast          # PR gate: DF0 + DF1 + critical evidence + critical lease
make dogfood-local
make dogfood-system        # SYSTEM species: real server/HTTP/runner (TestSys*)
make dogfood-distributed
make dogfood-adversarial
make dogfood-upgrade
make dogfood-scale
make dogfood-release-model   # NOT a release gate
make release-gate           # fails closed until production closure
make dogfood-all
```

CI providers invoke these targets rather than duplicating orchestration, so
GitHub Actions, Woodpecker and Kiwi itself exercise the same implementation.

### Suite contracts are name-complete, not filter-complete

Each target runs through `scripts/dogfood-run.sh`, which takes an explicit
`--require` list of the tests that suite **owns**. The suite is green only
if every required name actually executed — not merely if the `-run` regexp
matched something. Losing `TestDFUPGRADE001` reddens `dogfood-upgrade` even
when another alternative in the same filter still runs.

Two static guards keep the contract honest:

- `TestMakefileRequiresOnlyExistingTests` — every `--require` name must
  match a real `func Test…` (prefix match, same rule as the runner).
- `TestEveryRegistryScenarioHasATest` — every closed-registry scenario ID
  must be `Lookup`'d by at least one test.

Together they make the dogfood matrix a release contract: a documented
scenario cannot silently lose its proof.

## Independent workload

One canonical dogfood workload knows nothing about Faktor, Tangerine, AI
agents, or LLMs (compile, test, fanout, benchmark, artifact,
deploy-to-fake-service). This proves Kiwi remains independently useful. An
optional integration fixture may exercise an external dynamic/agent-style
client at the edge — not in core correctness.

## Use Kiwi's own evidence to certify the dogfood

```text
Kiwi executes Kiwi's dogfood
  → Kiwi emits signed evidence
  → independent harness verifies evidence
  → harness cross-checks it against observed reality
```

Kiwi says `network denied` → the oracle proves network access actually failed.
Kiwi says `one canonical winner` → the oracle proves only one effect reached
the external sink. Kiwi says `artifact SHA256 = X` → the oracle downloads and
independently hashes it.

> Kiwi's record of execution corresponds to what actually happened.

## Graduation condition

A release candidate repeatedly demonstrates:

```text
clean install
+ self-host two generations
+ distributed execution
+ all critical invariants
+ real failure recovery
+ truthful evidence
+ exact authority fencing
+ dynamic graphs
+ speculation
+ replay
+ storage recovery
+ cross-version upgrade
+ fixed scale workload
+ release-package validation
```

with:

```text
0 unexplained invariant violations
0 evidence inconsistencies
0 unauthorized external effects
0 stale-authority successes
0 canonical-state divergences
0 secret leaks
0 unexplained core-suite flakes
```

## Repository layout

```text
.kiwi/
├── pipeline.yaml                 DF0 (existing fast self-check)
└── dogfood/
    ├── local.yaml
    ├── distributed.yaml
    ├── adversarial.yaml
    ├── upgrade.yaml
    ├── scale.yaml
    └── release.yaml

internal/dogfood/                 package dogfood (harness/oracle/fault/…)
├── doc.go harness.go oracle.go topology.go fault.go seed.go result.go namespace.go
├── hostile/                      hostile runner modes
├── fake_forge/ fake_oidc/ fake_deployment/
└── scenarios/                    TestDF* scenario implementations + registry.go + suites.go

scripts/
└── dogfood-run.sh                fail-closed suite runner (no vacuous green)

docs/
├── DOGFOOD.md                    this file
└── DOGFOOD_MATRIX.md             capability ↔ scenario mapping
```

The harness is **internal**. It is not a supported user command.

## Anti-patterns (do not do)

- Put every full-system scenario into `.kiwi/pipeline.yaml`
- Let mocks be happy-path-only (mocks need delay/drop/duplicate/malformed/500 knobs)
- Depend 100% on public providers **or** 100% on mocks
- Silently retry flaky scenarios until green
- Claim dogfood-complete without Gates A–L (see DOGFOOD_MATRIX.md)
- Redesign the execution model, event recovery, lease fencing, replay,
  speculation, or evidence architecture while dogfood is the correctness
  engine — fix only what dogfood proves broken

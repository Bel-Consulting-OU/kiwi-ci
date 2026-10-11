# Dogfood matrix — capability coverage and release gates

Companion to `docs/DOGFOOD.md`. Every substantial Kiwi capability needs at
least one positive product-level dogfood scenario and, where security or
authority is involved, at least one negative scenario.

## 360° capability matrix

| Domain | Required dogfood coverage |
|---|---|
| Bootstrap | clean install, empty state, persistent state, restart, bad permissions, occupied port |
| Authentication | valid token, invalid token, revoked token, wrong scope, existence masking |
| Forge ingress | push, PR, tag where supported, bad signature, duplicate delivery, replayed delivery |
| Admission | valid config, invalid config, unavailable executor, incompatible runner, denied capability |
| DAG | dependency order, fanout, conditionals, dynamic additions, cancellation, retry |
| Scheduling | multiple runners, resource matching, fairness, unavailable capability |
| Leasing | heartbeat, expiry, reclaim, stale runner, stale completion |
| Executors | native, Docker, every supported production executor |
| Networking | normal networking, deny networking, unsupported enforcement |
| Filesystem | isolation, read-only root where supported, workspace limits |
| Resources | CPU/memory/disk controls and truthful fallback behavior |
| Secrets | injection, denial, masking, rotation/revocation, no evidence leakage |
| Logs | stdout, stderr, UTF-8, binary-ish output handling, huge output, reconnect |
| Artifacts | upload, download, hash verification, interrupted upload, duplicate finalization |
| Cache | miss, hit, prefix restore if supported, corruption, trust-domain separation |
| Events | ordering, reconnect, cursors, scopes, retention |
| Snapshot recovery | snapshot + stream handoff, authorization, retention races |
| Checkpoints | save, resume, restart, incompatible checkpoint rejection |
| Replay | normal replay, dynamic graph replay, historical execution-semantics interpretation |
| Speculation | multiple candidates, exactly one authoritative winner |
| Capabilities | issuance, expiry, audience/scope, stale-generation rejection |
| OIDC | correct claims, wrong claims, expiry, stale runner |
| Deployment | authorized effect once, unauthorized effect zero times |
| Evidence | generation, signature, verification, tampering, historical versions |
| Policy | allow, deny, policy update, policy digest in evidence |
| External effects | pure, Kiwi-mediated, opaque external |
| Local storage | SQLite/filesystem mode |
| Production storage | supported production DB/object store topology |
| Restart | graceful and ungraceful server/runner restart |
| Upgrade | N-1 → N, rolling compatibility, failed migration handling |
| Backup | database backup, object backup, clean restore |
| CLI | every supported user command |
| API | every public API family |
| UI | critical user journeys if UI is part of supported product |
| Metrics | values exist and agree with observed work |
| Health | readiness changes correctly during dependency failures |
| Scale | large DAG, many parallel jobs, event volume, artifacts |
| Release | clean install from final package, not source tree |

## Public-surface → scenario mapping

Scenario IDs use the `DF-<FAMILY>-<NNN>` taxonomy. Families currently in
the registry: `BOOT`, `EVID`, `LEASE`, `QUOTA`, `EFFECT`, `SELF`, `UPGRADE`,
`SCALE`. Matrix rows may also name planned families (`LIFE`, `RACE`, `ART`,
`CACHE`, `REPLAY`, `POLICY`, `SNAP`, `CAP`, `CHAOS`, `DIST`, `DR`, `RELEASE`,
`FORGE`, `AUTH`, `DAG`, `SCHED`, `RUNNER`, `EXEC`, `EVENT`, `SPEC`) — those
are roadmap IDs and are not yet executable proofs.


A new public capability must map to dogfood scenario IDs or carry an
explicit exemption. Review enforces this today; an automated surfacecheck
gate over this file is planned. IDs below that are not yet in
`internal/dogfood/scenarios/registry.go` are **planned** rows — the
implemented registry is the source of truth for what runs green.

```yaml
run.create:
  - DF-LIFE-001
  - DF-BOOT-001

run.cancel:
  - DF-LIFE-004
  - DF-RACE-002

run.retry:
  - DF-DAG-001

artifact.publish:
  - DF-ART-001
  - DF-ART-004

artifact.download:
  - DF-ART-002

cache.restore:
  - DF-CACHE-001

cache.publish:
  - DF-CACHE-002

evidence.verify:
  - DF-EVID-001
  - DF-EVID-002

evidence.fetch:
  - DF-EVID-001

replay:
  - DF-REPLAY-001
  - DF-EFFECT-003

jobs.complete:
  - DF-LEASE-002
  - DF-EVID-001

jobs.claim:
  - DF-LEASE-001
  - DF-DIST-001

events.stream:
  - DF-EVENT-001
  - DF-EVENT-002

policy.update:
  - DF-POLICY-001

deploy.authorize:
  - DF-EFFECT-001
  - DF-EFFECT-002

oidc.issue:
  - DF-CAP-001

snapshot.save:
  - DF-SNAP-001

self-host.build:
  - DF-SELF-001
  - DF-SELF-002

release.install:
  - DF-RELEASE-001

# Example exemption (challengeable in review):
# windows.native:
#   dogfood_not_applicable: "Kiwi does not claim Windows support"
```

## Invariant → proof mapping

| Invariant | Unit/property | Adversarial integration | System dogfood |
|---|---|---|---|
| Single authoritative terminal result | completion idempotency tests | concurrent complete/cancel/expiry/retry | DF-LEASE-002, DF-SPEC-001 |
| Transition and ledger atomicity | store atomicity tests | kill around transitions | DF-CHAOS-001 |
| Stale lease cannot mutate authority | generation fencing tests | stale complete/upload after reclaim | DF-LEASE-001 |
| Authorized event recovery | cursor/scope tests | retention between pages | DF-EVENT-001 |
| Replay cannot silently introduce effects | replay effect classification | fake sink count | DF-EFFECT-003, DF-REPLAY-001 |
| Dynamic mutation cannot rewrite history | graph mutation tests | mutate during run + restart | DF-DAG-002 |
| Speculation has one committer | winner CAS tests | near-simultaneous completions | DF-SPEC-001, DF-SPEC-002 |
| Terminal states are monotonic | status transition tests | cancel/complete/retry/timeout races | DF-CHAOS-002 |
| Credentials never exceed execution authority | capability tests | winner/loser/expired/wrong repo | DF-CAP-001, DF-EFFECT-002 |
| Untrusted cannot poison trusted cache | cache trust-domain tests | untrusted write → trusted read | DF-CACHE-001 |
| Quota truthfulness (assurance) | Facts()/ApplyObservedControl matrix | hostile contradictory receipt | DF-EVID-004 |
| Effective/observed consistency | ValidateObservedConsistency matrix | hostile wrong-runtime receipt | DF-EVID-003 |
| No secret leakage | masker tests | canary scan of evidence/logs/snapshots | DF-EVID-005 |
| Artifact finalization atomicity | CAS/staging tests | crash at each boundary | DF-ART-001 |
| Backup restore is usable | restore tests | destroy → restore → replay | DF-DR-001 |

## Security fact dual-proof rule

Every security-sensitive fact needs a positive **and** a control condition:

| Fact | Positive | Negative / control |
|---|---|---|
| NetworkDenied | network request genuinely fails | same workload under allowed networking succeeds |
| ReadOnlyRoot | write to root fs fails | writable root succeeds |
| WorkspaceQuotaEnforced | hard quota install + over-limit fails | fallback accounting claims false; no-quota claims false |
| SecretUnavailable | canary secret not readable | allowed secret is readable |
| DeploymentDenied | sink count stays 0 | authorized winner sink count is 1 |
| CacheTrustSeparated | trusted reader misses untrusted entry | same-domain hit works |

Without the control, the test cannot distinguish enforcement from a broken
endpoint.

## Hostile data set

Dogfood intentionally uses: very long branch names, Unicode, spaces, quotes,
shell metacharacters, unusual file names, deep trees, symlinks, large logs,
zero-byte artifacts, scaled multi-GB streams, malformed UTF-8 where the
interface permits bytes, duplicate keys, invalid YAML, unknown schema fields,
stale schema versions.

## Execution-dogfood result bundle

Every dogfood run emits:

```text
dogfood-result.json
scenario-results/
kiwi-evidence/
server-version.json
runner-versions.json
environment.json
failure-seeds.json
metrics-summary.json
```

Example top-level:

```json
{
  "commit": "...",
  "release_artifact_digest": "...",
  "suite": "DF3",
  "scenarios_total": 15,
  "passed": 15,
  "failed": 0,
  "flaky_retries": 0,
  "invariants_covered": 8,
  "public_surfaces_covered": 12,
  "evidence_verified": true
}
```

## Release closure gates

A release is dogfood-complete only when **all** gates hold.

| Gate | Name | Condition |
|---|---|---|
| A | Source closure | All DF0 checks pass |
| B | Self-host closure | G0 → G1 → G2 works and all evidence verifies |
| C | Public-surface closure | Every supported user-facing capability has mapped dogfood coverage or a justified exemption |
| D | Invariant closure | Every core invariant has automated enforcement and adversarial proof |
| E | Distributed closure | Real separate server/runners/storage complete representative workloads |
| F | Failure closure | Critical crash/lease/recovery/artifact/event scenarios pass |
| G | Evidence closure | All security-sensitive signed facts have truthful positive/negative tests; tampering is rejected |
| H | Upgrade closure | Previous supported release upgrades cleanly to the candidate |
| I | Recovery closure | Backed-up state restores into a fresh deployment and remains usable |
| J | Scale closure | Pinned scale workload completes with no correctness failures or material resource leaks |
| K | Packaging closure | The exact release artifact passes clean-install dogfood |
| L | Zero unexplained flake closure | No core dogfood failure is silently classified as "probably flaky" |

## Architecture freeze rule

While dogfood is the principal correctness engine, do **not**:

- add another architecture layer
- redesign the execution model
- reopen event recovery
- reopen lease fencing
- redesign replay
- redesign speculation
- make evidence more product-specific
- add a grander assurance taxonomy

Fix only what dogfood proves broken.

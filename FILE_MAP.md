# Kiwi CI file map

This source tree contains **57 files**. Every file is listed below.

| File | What it contains |
|---|---|
| `.gitignore` | Ignores binaries, build outputs, local caches/artifacts, macOS metadata and secrets. |
| `ARCHITECTURE.md` | Control-plane/runner/compiler/backend architecture, trust modes, invariants and v1 lease model. |
| `FILE_MAP.md` | Complete inventory of every source/documentation/configuration file and its responsibility. |
| `LICENSE` | Apache-2.0 license for Kiwi CI. |
| `Makefile` | Build/test/vet/format/run/clean developer shortcuts. |
| `README.md` | Project overview, design fixes, Mac quick start, GitHub webhook setup and example pipelines. |
| `ROADMAP.md` | Concrete P0/P1/P2 path to HA production CI: persistence, mTLS, OIDC, CAS, test intelligence, policy, observability and more. |
| `SECURITY.md` | Threat model and deployment rules for trusted/native versus isolated untrusted execution. |
| `cmd/kiwi/main.go` | Single-binary command router for run, validate, explain, doctor, server, runner and version. |
| `examples/kiwi.yaml` | Feature example covering defaults, retries, matrix, cache, artifacts and Tart. |
| `go.mod` | Dependency-free Go module declaration. |
| `internal/app/doctor.go` | Checks host capabilities such as git, bash, Docker, Tart, Xcode and Keychain. |
| `internal/app/local.go` | Local run/validate/explain commands, Git changed-file discovery and result summaries. |
| `internal/app/server_runner.go` | CLI flags and startup wiring for the control plane and remote runner. |
| `internal/app/verify.go` | Downloads an artifact, verifies its DSSE provenance signature against the server JWKS and binds the subject digest. |
| `internal/artifact/artifact.go` | First-class tar.gz artifact capture and traversal-safe extraction. |
| `internal/cache/cache.go` | Content-addressed cache archives, traversal-safe extraction and remote cache mirroring. |
| `internal/cache/cache_test.go` | Cache round-trip regression test. |
| `internal/executor/backend.go` | Execution backend contract, job-lifecycle interface and runtime selection. |
| `internal/executor/container.go` | Hardened Docker backend with dropped capabilities/no-new-privileges defaults. |
| `internal/executor/errors.go` | Typed failure classes: command, infrastructure, timeout and cancellation. |
| `internal/executor/executor.go` | Core DAG scheduler/executor: dependencies, concurrency, path filters, secrets, retries, caches, artifacts, outputs and status propagation. |
| `internal/executor/executor_test.go` | End-to-end DAG dependency and retry behavior test. |
| `internal/executor/native.go` | Native process backend with streaming logs, timeouts and process-group cancellation. |
| `internal/executor/outputs.go` | Step output file (KIWI_OUTPUT) parser used for `steps.*.outputs` interpolation. |
| `internal/executor/process_unix.go` | Unix process-group setup and TERM/KILL helpers. |
| `internal/executor/process_windows.go` | Windows process termination compatibility helpers. |
| `internal/executor/services.go` | Container-job service orchestration: dedicated bridge network, service startup and healthchecks. |
| `internal/executor/tart.go` | Apple-Silicon Tart VM backend: clone disposable VM, mount workspace, SSH script/env, delete VM. |
| `internal/logging/logging.go` | Console/function/multi sinks with timestamped structured step prefixes and masking. |
| `internal/model/model.go` | Shared control-plane types: run/job/runner statuses, artifacts, test reports, log and audit records. |
| `internal/pipeline/condition.go` | Small explicit condition evaluator for success/failure/cancelled/always/event/branch/env. |
| `internal/pipeline/graph.go` | Deterministic matrix expansion, interpolation and compiled dependency graph. |
| `internal/pipeline/parse.go` | Pipeline loading, top-level parse/default/validation flow and artifact retention parsing. |
| `internal/pipeline/pathmatch.go` | Monorepo path filters with *, ** and ? matching. |
| `internal/pipeline/pipeline_test.go` | Parser, matrix, interpolation, cycle, conditions, path-glob and block-scalar tests. |
| `internal/pipeline/spec.go` | Pipeline v1 typed schema: jobs, steps, retry, cache, artifacts, runtime, matrix, services, outputs and concurrency. |
| `internal/pipeline/validate.go` | Static validation: job/step integrity, dependency existence, runtime validation and cycle detection. |
| `internal/pipeline/yaml.go` | Zero-dependency, deliberately restricted YAML subset parser for predictable CI configuration. |
| `internal/policy/policy.go` | Admission policy: untrusted code cannot request secrets or native host execution. |
| `internal/policy/policy_test.go` | Regression tests for trusted/untrusted execution policy. |
| `internal/provenance/provenance.go` | in-toto/SLSA-shaped artifact provenance statement and Ed25519/DSSE signing primitive. |
| `internal/runner/runner.go` | Pull-based runner: capability registration, task polling, secure clone, checkout, execution, downloads, test uploads, logs and completion. |
| `internal/secrets/secrets.go` | Env + macOS Keychain secret providers, provider chaining and longest-first log masking. |
| `internal/secrets/secrets_test.go` | Secret redaction regression test. |
| `internal/server/blobs.go` | Artifact/cache upload/download endpoints with integrity hashes, retention and cleanup. |
| `internal/server/github.go` | Verified GitHub push/PR webhook intake, base-pinned fork pipeline fetch, GitHub Contents API loading. |
| `internal/server/github_status.go` | Commit status publishing from run state back to GitHub. |
| `internal/server/github_test.go` | GitHub's official HMAC test-vector regression test. |
| `internal/server/oidc.go` | Persistent Ed25519 OIDC issuer: discovery, JWKS, per-job audience-scoped ID tokens. |
| `internal/server/server.go` | Minimal control plane: run queue, leases, capability matching, runner auth, logs, statuses and dashboard API. |
| `internal/server/server_test.go` | Runner bearer-auth API test. |
| `internal/server/testintel.go` | Test report intake, per-run listing and flaky-test intelligence endpoint. |
| `internal/server/types.go` | Wire structs for submissions, leased tasks, heartbeats, logs and completions. |
| `internal/server/ui.go` | Dependency-free dark dashboard for recent run status. |
| `internal/storage/fs.go` | Filesystem-backed durable control-plane state: atomic snapshot plus append-only log/audit files. |
| `internal/testintel/junit.go` | JUnit parser and per-job report aggregation for flaky-test tracking and future test splitting. |

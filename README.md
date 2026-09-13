# 🥝 Kiwi CI

Kiwi CI is a local-first CI/CD engine inspired by Woodpecker's small server/agent architecture, but designed around reproducibility, explainability, macOS, and safer execution boundaries.

## What Kiwi fixes

- **No local/CI split:** `kiwi run` executes the same compiled DAG as a remote runner.
- **macOS is first-class:** trusted jobs can run natively; untrusted/reproducible jobs can run in disposable Tart VMs on Apple Silicon.
- **Caching is built in:** content-addressed cache archives keyed by declared inputs/lockfiles.
- **Retries are explicit:** step, job, and default retry policy with exponential backoff.
- **Cancellation is real:** native jobs run in their own process group so cancellation terminates children too.
- **Secrets resolve on the runner:** not in the server-side compiled plan; logs are masked before emission.
- **DAGs are explainable:** `kiwi explain` shows matrix expansion, dependencies, runtime, and commands.
- **Matrices are deterministic:** no silent axis truncation.
- **Artifacts are core:** no plugin required.
- **No mandatory cloud:** one Go binary can be a CLI, server, or runner.
- **Portable backends:** native, Docker, and Tart are behind one interface.
- **Supply-chain-ready:** provenance primitives are included; OIDC and policy enforcement are designed as first-class extensions.

## Quick start on a Mac

```bash
brew install go

git clone <your-kiwi-repo>
cd kiwi-ci
go build -o kiwi ./cmd/kiwi

./kiwi doctor
./kiwi validate -f examples/kiwi.yaml
./kiwi explain -f examples/kiwi.yaml
./kiwi run -f examples/kiwi.yaml
```

For isolated macOS jobs on Apple Silicon:

```bash
brew install openai/tools/tart
tart clone ghcr.io/cirruslabs/macos-tahoe-base:latest tahoe-base
```

Then:

```yaml
jobs:
  xcode:
    runtime: tart
    vm: tahoe-base
    steps:
      - run: xcodebuild -version
```

## Pipeline example

```yaml
version: 1
name: app

defaults:
  timeout: 15m
  retry:
    max: 1
    backoff: 2s

jobs:
  test:
    matrix:
      GO: ["1.23", "1.24"]
    cache:
      - name: deps
        key: "go-${{ matrix.GO }}"
        hash_files: [go.sum]
        paths: [".cache/go"]
    steps:
      - name: test
        run: go test ./...

  build:
    needs: [test]
    steps:
      - run: go build ./...
```

## GitHub webhook mode

Run the control plane with a high-entropy webhook secret and runner/API token:

```bash
export KIWI_RUNNER_TOKEN='runner-and-api-token'
export KIWI_GITHUB_WEBHOOK_SECRET='high-entropy-webhook-secret'
export KIWI_GITHUB_TOKEN='optional-token-for-private-repos'
./kiwi server --listen :8080
```

Configure the GitHub repository webhook to `https://your-kiwi.example/hooks/github`, content type `application/json`, and the same secret. Kiwi verifies `X-Hub-Signature-256` before processing the payload. Pushes are trusted. Fork pull requests are untrusted: Kiwi reads the pipeline definition from the base commit, checks out the fork code separately, forbids secrets, and refuses `runtime: native`; use `container` or `tart` instead.

## Server + Mac runner

Terminal 1:

```bash
export KIWI_RUNNER_TOKEN='change-me'
./kiwi server --listen :8080
```

Terminal 2:

```bash
./kiwi runner --server http://127.0.0.1:8080 --token "$KIWI_RUNNER_TOKEN" --labels macos,arm64,xcode
```

Submit a run through `POST /api/v1/runs` with repository URL, ref, and pipeline YAML. The runner clones the ref and executes the same graph used locally.

## Repository layout

See `ARCHITECTURE.md`. Every non-generated source file is intentionally small enough to audit.

## Status

This repository is a **compiling v0.1 foundation**, not a claim that a few thousand lines can already replace every production feature of GitHub Actions, GitLab CI, Buildkite, or Woodpecker. The architecture intentionally makes the difficult pieces—security boundaries, caching, cancellation, provenance, local parity, and backend isolation—first-class rather than afterthoughts. See `ROADMAP.md` for the path to a production-grade v1.

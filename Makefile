.PHONY: build test test-unit test-race test-integration integration test-adversarial test-shuffle test-stress \
	fuzz coverage coverage-ci coverage-floor coverage-package-floor staticcheck govulncheck cross schema-check surface-check dockerfile-buildargs-check docs-check license-check license-notice repro-build \
	toolchain-check tla2tools fmt lint run clean protect-branch \
	dogfood-fast dogfood-local dogfood-distributed dogfood-adversarial dogfood-upgrade dogfood-scale dogfood-release dogfood-all

VERSION ?= 0.1.0-dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIRTY ?= $(shell test -z "$$(git status --porcelain 2>/dev/null)" && echo false || echo true)
# The module's exact Go toolchain (from go.mod). `go run pkg@version` selects
# the TOOL module's toolchain under GOTOOLCHAIN=auto (for example go1.26 for
# staticcheck), which then cannot compile packages requiring this module's Go
# version. Pinning it keeps tool runs aligned with go.mod and with CI's
# GOTOOLCHAIN=local image regardless of the host's default go binary.
GO_TOOLCHAIN ?= go$(shell awk '/^go /{print $$2}' go.mod)

LDFLAGS = -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Version=$(VERSION) \
          -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Commit=$(COMMIT) \
          -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.BuildDate=$(BUILD_DATE) \
          -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Dirty=$(DIRTY)

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/kiwi ./cmd/kiwi

test: test-unit

test-unit:
	go test ./...

test-race:
	go test -race -shuffle=on ./...

test-integration: integration

# Real-PostgreSQL integration lane: env-gated by KIWI_TEST_POSTGRES_URL (the
# tests skip when it is unset) and selected by -run Integration. Run it
# against a throwaway database; every test creates and drops its own schema.
integration:
	@test -n "$$KIWI_TEST_POSTGRES_URL" || { echo "integration: set KIWI_TEST_POSTGRES_URL (e.g. postgres://postgres:pass@localhost:5432/kiwi?sslmode=disable)"; exit 1; }
	go test -count=1 -timeout=90m -run Integration ./internal/storage ./internal/scheduler ./internal/server ./internal/app

test-adversarial:
	go test -run 'Adversarial|Security|Property|Fault|Symlink|Traversal|Tamper|Reject|Evil|Bomb' -shuffle=on ./...

test-shuffle:
	go test -shuffle=on -count=2 ./...

test-stress:
	go test -run 'Concurrent|Property|Fault|HA|Parity|Adversarial' -count=10 -shuffle=on -timeout=30m ./internal/server ./internal/storage ./internal/scheduler ./internal/executor ./internal/runner

# single-P collapses goroutine interleavings; it found the process-output
# loss race (Wait closing pipes before the drains read them) and stays in CI.
test-single-p:
	GOMAXPROCS=1 go test -count=1 -timeout=30m ./...

# checkptr=2 is maximally strict about unsafe pointer arithmetic (needs -race).
test-checkptr:
	go test -gcflags=all=-d=checkptr=2 -race -count=1 -timeout=40m ./...

# The antagonistic battery run before every release.
test-antagonistic: test-unit test-race test-adversarial test-stress test-single-p test-checkptr

# ---------------------------------------------------------------------------
# Dogfood suite entry points (DF1–DF7). DF0 (source integrity) remains
# .kiwi/pipeline.yaml and is not re-encoded here. CI providers invoke these
# targets rather than duplicating orchestration: the .kiwi/dogfood/*.yaml
# suite definitions only describe tier/cadence/topology and call into this
# Makefile (see docs/DOGFOOD.md "Makefile entry points"). Scenario tests
# live under ./internal/dogfood/... as TestDFBOOT*/TestDFEVID*/TestDFLEASE*/
# TestDFQUOTA*/...; the -run filters below match those names
# the stable contract with that package (scenario IDs in docs/DOGFOOD.md).
# ---------------------------------------------------------------------------
.PHONY: dogfood-fast dogfood-local dogfood-distributed dogfood-adversarial \
	dogfood-upgrade dogfood-scale dogfood-release dogfood-all

# Every dogfood target runs through scripts/dogfood-run.sh, which FAILS
# CLOSED when the -run filter matches zero tests. Vacuous green is a defect,
# not a quiet success. Scenario tests live under ./internal/dogfood/scenarios
# as TestDFBOOT*/TestDFEVID*/TestDFLEASE*/TestDFQUOTA*/TestDFEFFECT*/TestDFSELF*.
#
# Suites whose scenarios are not yet implemented name their planned filter
# anyway: the target goes red until the tests exist. That is the contract.

# PR gate: DF0 (CI runs .kiwi/pipeline.yaml itself) + DF1 critical path
# (boot, evidence, lease, quota). Keep this filter small — it blocks every PR.
dogfood-fast:
	./scripts/dogfood-run.sh 20m 'TestDFBOOT|TestDFEVID|TestDFLEASE|TestDFQUOTA'

# DF1 local product lifecycle (harness-level boot/restart/evidence/lease/
# quota plus the oracle and no-hidden-retry guards).
dogfood-local:
	./scripts/dogfood-run.sh 60m 'TestDFBOOT|TestDFEVID|TestDFLEASE|TestDFQUOTA|TestDFEFFECT|TestDFSELF|TestDFSCALE|TestEightOracle|TestNoHiddenRetries|TestNamespace|TestFaultPoints|TestDogfoodResult|TestScenarioResult'

# DF2 distributed topology: the harness topology checks plus every
# multi-party scenario that does not require a live external process.
# Live multi-process DF2 (real postgres/objectstore/two runners) is the
# next implementation wave — see docs/DOGFOOD.md "Implemented vs planned".
dogfood-distributed:
	./scripts/dogfood-run.sh 90m 'TestDFBOOT|TestDFLEASE|TestDFEVID|TestDFQUOTA|TestDFEFFECT|TestTopology'

# DF3 nightly chaos: lease races, hostile-runner receipts, deterministic
# fault windows. Safety AND liveness (stale rejected, live holder completes).
dogfood-adversarial:
	./scripts/dogfood-run.sh 180m 'TestDFLEASE|TestDFEVID|TestDFQUOTA|TestDFEFFECT|TestEightOracle|TestNoHiddenRetries|TestFaultPoints|TestNewModeMatrix|TestExpectationsAreLayered' ./internal/dogfood/...

# DF4 cross-version: schema/semantics compatibility checks the verifier and
# engine already pin. Live N-1 binary matrix is the next wave.
dogfood-upgrade:
	./scripts/dogfood-run.sh 90m 'TestDFUPGRADE|TestVerifyExecutionAttestationSchema|TestExecutionAttestationAcceptsLegacy' ./internal/dogfood/... ./internal/provenance/

# DF6 fixed-workload soak: harness-level high-volume lifecycle and churn.
# The 10000-job / multi-process constants live in docs/DOGFOOD.md as the
# target workload for the live soak once DF2 is online.
dogfood-scale:
	./scripts/dogfood-run.sh 240m 'TestDFSCALE|TestDogfoodResult|TestScenarioResult|TestNamespace'

# DF7 release-candidate closure: evidence + quota truthfulness + hostile
# rejection + result-bundle seal — the pieces that gate a release today.
# Install-from-artifact and G0→G1→G2 self-build require a packaged binary
# and are the next wave (docs/DOGFOOD.md).
dogfood-release:
	./scripts/dogfood-run.sh 180m 'TestDFEVID|TestDFQUOTA|TestDFEFFECT|TestDFSELF|TestDFBOOT|TestDogfoodResult|TestScenarioResult'

# Full product dogfood (DF1–DF7). dogfood-fast is a strict subset of
# dogfood-local and is not repeated here; DF0 is .kiwi/pipeline.yaml.
dogfood-all: dogfood-local dogfood-distributed dogfood-adversarial dogfood-upgrade dogfood-scale dogfood-release

# staticcheck-all is the CI check: it is exactly the pinned command run by
# .woodpecker/linux-amd64.yml. `staticcheck` runs the same pinned command
# locally so make and CI cannot diverge on the tool version or the -checks set.
staticcheck: staticcheck-all

# staticcheck v0.8.1's pinned x/tools cannot decode Go 1.27.2 compiler export
# data, so the tool is built from tools/ (which pins an explicit x/tools
# override) into dist/ and then run against this module.
STATICCHECK_BIN ?= $(CURDIR)/dist/staticcheck-tool

staticcheck-all: $(STATICCHECK_BIN)
	$(STATICCHECK_BIN) -checks=all,-ST1000,-ST1020,-ST1021,-ST1003 ./...

$(STATICCHECK_BIN): tools/go.mod tools/go.sum tools/tools.go
	@mkdir -p $(CURDIR)/dist
	cd tools && GOTOOLCHAIN=$(GO_TOOLCHAIN) go build -o $(STATICCHECK_BIN) honnef.co/go/tools/cmd/staticcheck

fuzz:
	./scripts/fuzz-smoke.sh 10s

coverage:
	go test -timeout=45m -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

coverage-report:
	./scripts/coverage-report.sh coverage.out

# CI-equivalent coverage chain, mirroring the Woodpecker `coverage` and
# `integration-postgres` lanes exactly: unit profile, PostgreSQL integration
# profile (requires KIWI_TEST_POSTGRES_URL), profile self-test, merge,
# per-package report and the coverage floors (total, then per-package).
#
# The unit-profile run explicitly UNSETS KIWI_TEST_POSTGRES_URL even when the
# caller's environment exports it (the self-hosted pipeline sets it at job
# level for its PostgreSQL service): PostgreSQL-gated tests must land in the
# integration profile with -coverpkg=./..., not silently split across the two
# profiles. `env -u` is also what makes this target reproducible locally with
# a DSN exported. The integration step REQUIRES the variable: without it every
# Integration test skips and the merged floor would pass on a unit-only
# profile while claiming integration coverage.
coverage-ci:
	env -u KIWI_TEST_POSTGRES_URL go test -timeout=45m -coverprofile=coverage.out -covermode=atomic ./...
	@test -n "$$KIWI_TEST_POSTGRES_URL" || { echo "coverage-ci: set KIWI_TEST_POSTGRES_URL (e.g. postgres://postgres:pass@localhost:5432/kiwi?sslmode=disable); the integration profile must run the real-PostgreSQL tests"; exit 1; }
	go test -count=1 -timeout=90m -run Integration -covermode=atomic -coverprofile=integration-coverage.out -coverpkg=./... ./internal/storage ./internal/scheduler ./internal/server ./internal/app
	./scripts/ci-coverage-selftest.sh coverage.out integration-coverage.out
	./scripts/merge-coverage.sh merged-coverage.out coverage.out integration-coverage.out
	./scripts/coverage-report.sh merged-coverage.out
	./scripts/coverage-floor.sh merged-coverage.out
	./scripts/coverage-package-floor.sh merged-coverage.out

# Enforce the total-coverage floor on a profile produced by `make coverage`;
# override the default floor with KC_MIN_COVERAGE=<percent>.
coverage-floor:
	./scripts/coverage-floor.sh coverage.out

# Enforce the per-package statement-coverage floor (default 80%, override
# with KC_MIN_PACKAGE_COVERAGE=<percent>) on a unit profile. Justified
# exceptions live in scripts/coverage-package-baseline.txt; `make coverage-ci`
# applies the same gate to the merged unit+integration profile.
coverage-package-floor:
	./scripts/coverage-package-floor.sh coverage.out

# govulncheck runs the exact pinned command CI runs
# (.woodpecker/linux-amd64.yml govulncheck), including -test so test
# dependencies are scanned.
govulncheck:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -test ./...

cross:
	GOOS=linux GOARCH=amd64 go build -trimpath -o /dev/null ./cmd/kiwi
	GOOS=linux GOARCH=arm64 go build -trimpath -o /dev/null ./cmd/kiwi
	GOOS=darwin GOARCH=arm64 go build -trimpath -o /dev/null ./cmd/kiwi
	GOOS=darwin GOARCH=amd64 go build -trimpath -o /dev/null ./cmd/kiwi
	GOOS=windows GOARCH=amd64 go build -trimpath -o /dev/null ./cmd/kiwi

# Extracts the VERSION/COMMIT validation RUN block from the Dockerfile
# (between its BEGIN/END markers) and executes it natively under sh with
# accept/reject inputs: build-arg validation is testable without a Docker
# daemon. Also wired into schema-check below and the Woodpecker schema step.
dockerfile-buildargs-check:
	./scripts/dockerfile-buildargs-check.sh

# Toolchain contract: README.md must document exactly the `go` version from
# go.mod, and the running `go` must satisfy it. The selftest proves the failure
# paths on doctored temp copies before the live check runs; every Woodpecker
# workflow invokes the script in its first step as well.
toolchain-check:
	./scripts/toolchain-check.sh --selftest
	./scripts/toolchain-check.sh

# Fetch the SHA-256-pinned TLA+ tla2tools.jar used by the formal model check
# (formal/README.md, .github/workflows/formal.yml). The script refuses to
# install an artifact whose digest does not match the pin in the script.
tla2tools:
	./scripts/fetch-tla2tools.sh --selftest
	./scripts/fetch-tla2tools.sh

schema-check: toolchain-check
	go test -run Schema ./internal/pipeline
	go run ./cmd/filemap --check
	./scripts/dockerfile-buildargs-check.sh

# surface-check is the 100%-surface guard: `go test ./internal/surfacecheck/`
# runs the executable inventory of repository surfaces (package test
# presence, fuzz-target drift, script inventory, the self-hosted dogfood
# pipeline's verification matrix, skip/stub hygiene, embed and migration
# accounting) and fails closed on any surface not covered by tests or the
# self-hosted pipeline.
surface-check:
	go test ./internal/surfacecheck/ -count=1

docs-check:
	test -f docs/threat-model.md
	test -f ADVERSARIAL_TEST_MATRIX.md
	test -f SECURITY.md
	test -f CONTRIBUTING.md
	test -f docs/production-deployment.md
	test -f docs/brand/Kiwi_CI_Visual_Identity.pdf
	test -f docs/brand/README.md
	test -f docs/brand/assets/brand-tokens.json
	test -f docs/brand/assets/logo-mark.png
	test -f docs/brand/assets/logo-lockup.png
	test -f docs/brand/assets/logo-lockup-dark.png
	test -f docs/brand/assets/favicon.png
	@# No stale references to abandoned CI systems.
	@! grep -rn "github/workflows/native" README.md docs/ CONTRIBUTING.md .woodpecker/ 2>/dev/null
	@! grep -rn "placeholder address" SECURITY.md 2>/dev/null
	@# Relative Markdown links must resolve.
	./scripts/docs-links-check.sh
	@# The retired single-file Woodpecker layout must not reappear in docs.
	@! grep -rn "\.woodpecker\.yml" README.md docs/ CONTRIBUTING.md .woodpecker/ .github/ 2>/dev/null
	@# The documented example pipelines and config must actually validate.
	go run ./cmd/kiwi validate -f .kiwi/pipeline.yaml
	go run ./cmd/kiwi validate -f examples/kiwi.yaml
	go run ./cmd/kiwi config check --config kiwi.example.toml

license-check:
	@# Classifier fixtures first: the gate itself is testable offline.
	./scripts/license-check.sh --selftest
	@# The scan covers the full build list, so the zips must be present.
	go mod download all
	./scripts/license-check.sh
	grep -q 'Apache License' LICENSE
	grep -q 'http://www.apache.org/licenses/LICENSE-2.0' LICENSE

# Regenerates NOTICE from the dependency scan. Run after any dependency
# change and commit the result; the license CI step fails on NOTICE drift.
license-notice:
	@# The scan covers the full build list, so the zips must be present.
	go mod download all
	./scripts/license-check.sh --notice

repro-build:
	./scripts/repro-build.sh

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint:
	go vet ./...

run:
	go run ./cmd/kiwi run -f examples/kiwi.yaml

clean:
	rm -rf dist coverage.out .kiwi/cache .kiwi/artifacts .kiwi/runs .kiwi/workspaces

# Applies main-branch protection (required PRs, required CI matrix,
# up-to-date branches, admins not exempt). Idempotent; requires repo
# admin; run once manually. See scripts/gh-branch-protection.sh.
protect-branch:
	./scripts/gh-branch-protection.sh

# Reproducible release/snapshot builds: an explicit SOURCE_DATE_EPOCH pins the
# recorded BuildDate (artifacts) while provenance/SBOM timestamps stay
# truthful. In release mode scripts/release.sh derives it from the tagged
# commit when unset. See docs/releases.md.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct HEAD 2>/dev/null)

# RFC3339 BuildDate passed to docker-build: derived here, on the host, from
# SOURCE_DATE_EPOCH (default: HEAD commit date) with a BSD-then-GNU date
# fallback, because the build-stage userland (BusyBox) need not support
# `date -d @epoch`. Override DOCKER_BUILD_DATE for an explicit timestamp;
# SOURCE_DATE_EPOCH still pins the recorded BuildDate (see docs/releases.md).
DOCKER_BUILD_DATE ?= $(shell if [ -n "$(SOURCE_DATE_EPOCH)" ]; then date -u -r "$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; fi)

.PHONY: release release-snapshot release-formula-test release-snapshot-signing-test docker-build

release:
	./scripts/release.sh $(TAG)

# Branch/dirty development build: records the short SHA with a -snapshot
# version suffix, requires no signing key, and never touches Formula/kiwi.rb.
release-snapshot:
	./scripts/release.sh --snapshot

# Proves Formula/kiwi.rb renders correctly from Formula/kiwi.rb.tmpl across
# two sequential releases (v1 then v2), with no pre-existing placeholders.
release-formula-test:
	./scripts/release-formula-test.sh

# Proves snapshot builds are never signed even when KIWI_RELEASE_SIGNING_KEY
# is exported: release-tool must receive no -key and no key temp file may be
# materialized, while a release-mode control with the same environment must
# pass -key pointing at a mode-600 temp file.
release-snapshot-signing-test:
	./scripts/release-snapshot-signing-test.sh

docker-build:
	docker build --build-arg BUILD_DATE=$(DOCKER_BUILD_DATE) \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		-t ghcr.io/bel-consulting-ou/kiwi-ci:$(VERSION) .

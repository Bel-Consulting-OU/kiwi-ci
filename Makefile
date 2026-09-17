.PHONY: build test test-unit test-race test-integration integration test-adversarial test-shuffle test-stress \
	fuzz coverage coverage-ci coverage-floor staticcheck govulncheck cross schema-check docs-check license-check repro-build \
	fmt lint run clean protect-branch

VERSION ?= 0.1.0-dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIRTY ?= $(shell test -z "$$(git status --porcelain 2>/dev/null)" && echo false || echo true)
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
	go test -count=1 -timeout=20m -run Integration ./internal/storage ./internal/scheduler ./internal/server

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

staticcheck-all:
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 -checks=all,-ST1000,-ST1020,-ST1021,-ST1003 ./...

fuzz:
	./scripts/fuzz-smoke.sh 10s

coverage:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

coverage-report:
	./scripts/coverage-report.sh coverage.out

# CI-equivalent coverage chain, mirroring the Woodpecker `coverage` and
# `integration-postgres` lanes exactly: unit profile, PostgreSQL integration
# profile (requires KIWI_TEST_POSTGRES_URL), profile self-test, merge,
# per-package report and the coverage floor.
coverage-ci:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go test -count=1 -timeout=20m -run Integration -covermode=atomic -coverprofile=integration-coverage.out -coverpkg=./... ./internal/storage ./internal/scheduler ./internal/server
	./scripts/ci-coverage-selftest.sh coverage.out integration-coverage.out
	./scripts/merge-coverage.sh merged-coverage.out coverage.out integration-coverage.out
	./scripts/coverage-report.sh merged-coverage.out
	./scripts/coverage-floor.sh merged-coverage.out

# Enforce the total-coverage floor on a profile produced by `make coverage`;
# override the default floor with KC_MIN_COVERAGE=<percent>.
coverage-floor:
	./scripts/coverage-floor.sh coverage.out

staticcheck:
	staticcheck ./...

govulncheck:
	govulncheck ./...

cross:
	GOOS=linux GOARCH=amd64 go build -trimpath -o /dev/null ./cmd/kiwi
	GOOS=linux GOARCH=arm64 go build -trimpath -o /dev/null ./cmd/kiwi
	GOOS=darwin GOARCH=arm64 go build -trimpath -o /dev/null ./cmd/kiwi
	GOOS=darwin GOARCH=amd64 go build -trimpath -o /dev/null ./cmd/kiwi
	GOOS=windows GOARCH=amd64 go build -trimpath -o /dev/null ./cmd/kiwi

schema-check:
	go test -run Schema ./internal/pipeline
	go run ./cmd/filemap --check

docs-check:
	test -f docs/threat-model.md
	test -f ADVERSARIAL_TEST_MATRIX.md
	test -f SECURITY.md
	test -f CONTRIBUTING.md

license-check:
	grep -q 'Apache License' LICENSE
	grep -q 'http://www.apache.org/licenses/LICENSE-2.0' LICENSE

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

.PHONY: release docker-build

release:
	./scripts/release.sh $(TAG)

docker-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		-t ghcr.io/bel-consulting-ou/kiwi-ci:$(VERSION) .

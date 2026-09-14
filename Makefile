.PHONY: build test test-unit test-race test-integration test-adversarial test-shuffle test-stress \
	fuzz coverage staticcheck govulncheck cross schema-check docs-check license-check repro-build \
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

test-integration:
	go test -tags=integration ./...

test-adversarial:
	go test -run 'Adversarial|Security|Property|Fault|Symlink|Traversal|Tamper|Reject|Evil|Bomb' -shuffle=on ./...

test-shuffle:
	go test -shuffle=on -count=2 ./...

test-stress:
	go test -count=20 -run 'Property|Fault|Concurrent' ./internal/scheduler ./internal/storage ./internal/server

fuzz:
	./scripts/fuzz-smoke.sh 10s

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

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

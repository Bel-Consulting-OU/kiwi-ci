# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage.
#
# Pinned by digest (multi-arch OCI index) on 2026-09-17:
#   golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125
# Re-resolve before bumping the Go minor: docker buildx imagetools inspect golang:1.27-alpine
# ---------------------------------------------------------------------------
FROM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
# BUILD_DATE is the RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ) recorded as
# version.BuildDate. The Makefile's docker-build computes it on the host from
# SOURCE_DATE_EPOCH, so the build-stage userland never has to convert an
# epoch. A caller-supplied value is validated below before it reaches
# -ldflags: anything outside the exact RFC3339 UTC shape (whitespace, extra
# linker flags, other characters) fails the build instead of being
# whitespace-split by cmd/go.
ARG BUILD_DATE
# SOURCE_DATE_EPOCH pins the recorded BuildDate so the artifact bytes are
# reproducible, and is the fallback when BUILD_DATE is not supplied. The
# epoch is converted with the Go toolchain already in this stage because
# BusyBox date(1) need not support GNU `-d @epoch` or BSD `-r`. Provenance and
# SBOM timestamps are unaffected and stay truthful. When neither is set, the
# build timestamp is "now".
ARG SOURCE_DATE_EPOCH

WORKDIR /src

# Module cache is a separate layer so source-only changes rebuild fast.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN set -eux; \
    if [ -n "${BUILD_DATE}" ]; then \
      case "${BUILD_DATE}" in \
        *[!0-9TZ:.-]*) printf 'error: BUILD_DATE must be an RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ), got %s\n' "${BUILD_DATE}" >&2; exit 1 ;; \
      esac; \
      if ! printf '%s' "${BUILD_DATE}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; then \
        printf 'error: BUILD_DATE must be an RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ), got %s\n' "${BUILD_DATE}" >&2; \
        exit 1; \
      fi; \
    fi; \
    if [ -z "${BUILD_DATE}" ] && [ -n "${SOURCE_DATE_EPOCH}" ]; then \
      printf 'package main\nimport ("fmt"; "os"; "strconv"; "time")\nfunc main() { n, err := strconv.ParseInt(os.Args[1], 10, 64); if err != nil { os.Exit(1) }; fmt.Print(time.Unix(n, 0).UTC().Format(time.RFC3339)) }\n' >/tmp/epochdate.go; \
      BUILD_DATE="$(go run /tmp/epochdate.go "${SOURCE_DATE_EPOCH}")"; \
      rm -f /tmp/epochdate.go; \
    fi; \
    if [ -z "${BUILD_DATE}" ]; then \
      BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
    fi; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
    -ldflags "-s -w \
      -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Version=${VERSION} \
      -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Commit=${COMMIT} \
      -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.BuildDate=${BUILD_DATE} \
      -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Dirty=false" \
    -o /out/kiwi ./cmd/kiwi

# ---------------------------------------------------------------------------
# Runtime stage.
#
# Pinned by digest (multi-arch OCI index) on 2026-09-14:
#   gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
# Re-resolve before bumping: docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
#
# distroless has no shell and no package manager, so a Dockerfile HEALTHCHECK
# instruction is not possible; orchestrators must probe the HTTP endpoints
# instead: GET /readiness (ready to serve; checks the store in DB mode) and
# GET /liveness (process up). The image runs as the nonroot uid 65532.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG COMMIT=unknown

USER 65532:65532

LABEL org.opencontainers.image.title="Kiwi CI" \
      org.opencontainers.image.description="Single-binary CI/CD engine: CLI, control plane, and runner" \
      org.opencontainers.image.url="https://github.com/Bel-Consulting-OU/kiwi-ci" \
      org.opencontainers.image.source="https://github.com/Bel-Consulting-OU/kiwi-ci" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

COPY --from=build /out/kiwi /kiwi

EXPOSE 8080

# Production mode enforces its startup contract (--database-url, distinct
# admin/runner tokens, https:// --external-url, --tls-cert/--tls-key); supply
# those in your orchestrator manifest by overriding the CMD. See
# docs/production-deployment.md.
ENTRYPOINT ["/kiwi"]
CMD ["server", "--mode=production"]

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

WORKDIR /src

# Module cache is a separate layer so source-only changes rebuild fast.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
    -ldflags "-s -w \
      -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Version=${VERSION} \
      -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Commit=${COMMIT} \
      -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
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

# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage.
#
# Pin this image by digest before cutting a release, e.g.
#   docker buildx imagetools inspect golang:1.23-alpine
# then replace the tag with golang:1.23-alpine@sha256:<digest>.
# ---------------------------------------------------------------------------
FROM golang:1.23-alpine AS build

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
# Pin this image by digest before cutting a release, e.g.
#   docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
# then replace the tag with gcr.io/distroless/static-debian12@sha256:<digest>.
#
# distroless has no shell and no package manager, so a Dockerfile HEALTHCHECK
# instruction is not possible; orchestrators must probe the HTTP endpoints
# instead: GET /readiness (ready to serve; checks the store in DB mode) and
# GET /liveness (process up). The image runs as the nonroot uid 65532.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

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

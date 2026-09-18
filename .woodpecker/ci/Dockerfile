# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Dedicated CI test image for .woodpecker/docker-workspace.yml.
#
# Why it exists: the docker-workspace lane must have a Docker CLI, which the
# golang:1.27 image does not guarantee, and the lane must not depend on an
# image published to a registry. The workflow's first step therefore builds
# this file on the agent's Docker daemon:
#
#   docker build -f .woodpecker/ci/Dockerfile -t kiwi-ci-test:go1.27 .
#
# and the test step runs in that local image (pull: false).
#
# Pins (never replace a digest with a floating tag):
#   - Go 1.27: golang:1.27@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea
#     This is the digest already used by .woodpecker/*.yml. The Docker Hub
#     amd64 manifest for it carries ENV GOLANG_VERSION=1.27.1 (verified from
#     the image config on 2026-09-18).
#   - Docker CLI: docker:cli@sha256:018edbc908e08fcc9dbf029c812c34251e9b4719e6f71ca0e5eae2a987d014ca
#     Multi-arch OCI index resolved from Docker Hub on 2026-09-18 (Docker CLI
#     29.8.1). Re-resolve with `docker buildx imagetools inspect docker:cli`
#     whenever the pin is bumped.
# ---------------------------------------------------------------------------
FROM docker:cli@sha256:018edbc908e08fcc9dbf029c812c34251e9b4719e6f71ca0e5eae2a987d014ca AS dockercli

FROM golang:1.27@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea

# git: VCS access for the Go tooling; ca-certificates: TLS for module
# downloads; make/gcc/libc6-dev: the repo's native build tools (Makefile
# targets, cgo and race builds). The Debian golang image ships these already,
# but installing them explicitly keeps the contract in this file instead of
# relying on an implicit base-image detail, and the go/git/make/gcc probes
# fail the build if a future base omits one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git make gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/* \
 && go version | grep -Eq '^go version go1\.27([.][0-9]+)? ' \
 && command -v git >/dev/null && command -v make >/dev/null && command -v gcc >/dev/null

# Docker CLI plus its CLI plugins (BuildKit) from the pinned upstream image,
# so `docker info` and `docker build` behave like a normal Docker CLI install.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins /usr/local/libexec/docker/cli-plugins
RUN docker --version

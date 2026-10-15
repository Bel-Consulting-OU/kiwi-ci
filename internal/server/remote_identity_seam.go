package server

import (
	"context"
	"os"
	"strings"
)

// gatewayError wraps a forge/transport failure (resolve revision, fetch
// lock) so ingress can surface it as a retryable 502 instead of an opaque
// 500. It is a client-visible outage signal, not a server defect.
type gatewayError struct{ err error }

func (g *gatewayError) Error() string {
	if g == nil || g.err == nil {
		return "gateway error"
	}
	return g.err.Error()
}

func (g *gatewayError) Unwrap() error { return g.err }

// runningUnderTest reports whether this binary is a `go test` binary. Used
// so unit tests that construct a Server with github.com coordinates never
// hit a real forge API. Production binaries are unaffected.
func runningUnderTest() bool {
	name := os.Args[0]
	return strings.HasSuffix(name, ".test") || strings.Contains(name, ".test")
}

// StubRemoteIdentityForTest disables network-backed revision resolution and
// lock fetch. Production leaves the seams nil and uses the exact forge
// adapter; tests call this (or rely on auto-stub) so unit tests never reach
// a real forge.
func (s *Server) StubRemoteIdentityForTest() {
	s.RevisionResolver = func(_ context.Context, _, _, ref string) (string, error) {
		sha := make([]byte, 40)
		for i := range sha {
			sha[i] = 'a'
		}
		if ref != "" && ref != "HEAD" {
			sha[0] = ref[len(ref)-1]
		}
		return string(sha), nil
	}
	s.ImageLockFetcher = func(_ context.Context, _, _, _ string) (string, error) {
		return "", nil
	}
	s.DownstreamImageLockFetcher = func(_ context.Context, _, _ string) (string, error) {
		return "", nil
	}
}

// maybeAutoStubRemoteIdentity applies the test stub when the binary is a
// test and no forge API base is configured (a configured base means the test
// owns the forge and wants real adapter behavior).
func (s *Server) maybeAutoStubRemoteIdentity() {
	if !runningUnderTest() {
		return
	}
	if s.gitHubAPIBase != "" || s.gitLabAPIBase != "" || s.forgejoAPIBase != "" {
		return
	}
	s.StubRemoteIdentityForTest()
}

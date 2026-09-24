package giturl

// F4-E regressions: loopback detection must parse the host, never a "127."
// prefix, and the http clone-URL rule must reject a lookalike.

import "testing"

func TestIsLoopbackHostExact(t *testing.T) {
	loopback := []string{"localhost", "LOCALHOST", "127.0.0.1", "127.255.255.254", "::1"}
	for _, h := range loopback {
		if !IsLoopbackHost(h) {
			t.Fatalf("IsLoopbackHost(%q) = false, want true", h)
		}
	}
	notLoopback := []string{
		"", "0.0.0.0", "127.evil.example", "localhost.evil.example",
		"localhostfoo", "127.0.0.1.attacker.test", "10.0.0.1", "[::1]",
	}
	for _, h := range notLoopback {
		if IsLoopbackHost(h) {
			t.Fatalf("IsLoopbackHost(%q) = true, want false", h)
		}
	}
}

func TestParseCloneURLHTTPLoopbackLookalikeRejected(t *testing.T) {
	if _, _, _, err := ParseCloneURL("http://127.evil.example/acme/repo"); err == nil {
		t.Fatal("http clone URL for 127.evil.example accepted as loopback")
	}
	if _, _, _, err := ParseCloneURL("http://localhost.evil.example/acme/repo"); err == nil {
		t.Fatal("http clone URL for localhost.evil.example accepted as loopback")
	}
	host, path, scheme, err := ParseCloneURL("http://127.0.0.1/acme/repo")
	if err != nil || host != "127.0.0.1" || path != "acme/repo" || scheme != "http" {
		t.Fatalf("genuine loopback http clone URL rejected: %q %q %q %v", host, path, scheme, err)
	}
}

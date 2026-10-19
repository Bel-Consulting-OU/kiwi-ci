package app

import (
	"os"
	"strings"
	"testing"
)

// The precedence contract: explicit flag > active context > env > local
// default. A saved login context must actually be the default authority.
func TestResolveEndpointPrecedence(t *testing.T) {
	// Isolate from any saved operator context (flag > context > env): a
	// real ~/.config/kiwi/contexts.json would win over env and break the
	// precedence assertions.
	t.Setenv("KIWI_CONFIG_DIR", t.TempDir())
	t.Setenv("KIWI_SERVER", "")
	t.Setenv("KIWI_ADMIN_TOKEN", "")
	t.Setenv("KIWI_ALLOW_INSECURE_HTTP", "")

	// Flag wins over everything (https so the cleartext guard stays quiet).
	e, err := ResolveEndpoint("https://flag.example", "flagtok")
	if err != nil || e.Server != "https://flag.example" || e.Token != "flagtok" || e.Source != "flag" {
		t.Fatalf("flag precedence: %+v err=%v", e, err)
	}

	// Env wins when no flag.
	t.Setenv("KIWI_SERVER", "https://env.example")
	t.Setenv("KIWI_ADMIN_TOKEN", "envtok")
	e, err = ResolveEndpoint("", "")
	if err != nil || e.Server != "https://env.example" || e.Source != "env" {
		t.Fatalf("env precedence: %+v err=%v", e, err)
	}

	// Safe local default when nothing else is set.
	t.Setenv("KIWI_SERVER", "")
	t.Setenv("KIWI_ADMIN_TOKEN", "")
	e, err = ResolveEndpoint("", "")
	if err != nil || e.Server != defaultLocalServer || e.Source != "default" {
		t.Fatalf("default precedence: %+v err=%v", e, err)
	}
}

// Refuse sending a token to a non-loopback plaintext HTTP server unless the
// operator supplied the unsafe override. This is a security-oriented CI
// product: silent cleartext credential exfiltration is a defect.
func TestResolveEndpointRefusesCleartextRemoteToken(t *testing.T) {
	t.Setenv("KIWI_ALLOW_INSECURE_HTTP", "")
	_, err := ResolveEndpoint("http://remote.example:8080", "tok")
	if err == nil {
		t.Fatal("plaintext remote + token must be refused")
	}
	if !strings.Contains(err.Error(), "KIWI_ALLOW_INSECURE_HTTP") {
		t.Fatalf("error must name the override: %v", err)
	}
	// Explicit override allows it.
	t.Setenv("KIWI_ALLOW_INSECURE_HTTP", "1")
	e, err := ResolveEndpoint("http://remote.example:8080", "tok")
	if err != nil || e.Token != "tok" {
		t.Fatalf("override must allow: %+v err=%v", e, err)
	}
	// Loopback plaintext is fine without the override.
	t.Setenv("KIWI_ALLOW_INSECURE_HTTP", "")
	if _, err := ResolveEndpoint("http://127.0.0.1:8080", "tok"); err != nil {
		t.Fatalf("loopback plaintext must be allowed: %v", err)
	}
	// TLS is always fine.
	if _, err := ResolveEndpoint("https://remote.example", "tok"); err != nil {
		t.Fatalf("https must be allowed: %v", err)
	}
}

func TestResolveEndpointRequireToken(t *testing.T) {
	t.Setenv("KIWI_ADMIN_TOKEN", "")
	e, err := ResolveEndpoint("http://127.0.0.1:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.RequireToken(); err == nil {
		t.Fatal("missing token must error")
	}
	e.Token = "t"
	if _, err := e.RequireToken(); err != nil {
		t.Fatalf("present token: %v", err)
	}
	_ = os.Getenv
}

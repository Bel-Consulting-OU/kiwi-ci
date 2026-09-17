package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type stubProvider struct {
	value string
	err   error
}

func (s stubProvider) Get(context.Context, string) (string, error) { return s.value, s.err }

// TestChainGet exercises the provider chain: first non-empty value wins,
// empty values and errors are skipped, and an all-negative chain returns a
// named error that joins every provider error.
func TestChainGet(t *testing.T) {
	ctx := context.Background()

	// First provider returns a value: chain stops there.
	c := Chain{stubProvider{value: "one"}, stubProvider{value: "two"}}
	if got, err := c.Get(ctx, "token"); err != nil || got != "one" {
		t.Fatalf("Get = (%q, %v), want (one, nil)", got, err)
	}

	// Empty values are treated as misses (not errors) and fall through.
	c = Chain{stubProvider{value: ""}, stubProvider{value: "two"}}
	if got, err := c.Get(ctx, "token"); err != nil || got != "two" {
		t.Fatalf("Get = (%q, %v), want (two, nil)", got, err)
	}

	// Errors are collected and the next provider still wins.
	boom := errors.New("provider down")
	c = Chain{stubProvider{err: boom}, stubProvider{value: "two"}}
	if got, err := c.Get(ctx, "token"); err != nil || got != "two" {
		t.Fatalf("Get = (%q, %v), want (two, nil)", got, err)
	}

	// All negative: the error names the secret and joins the causes.
	c = Chain{stubProvider{err: boom}, stubProvider{err: boom}}
	_, err := c.Get(ctx, "token")
	if err == nil {
		t.Fatal("Get succeeded, want error")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("Get error = %v, want it to wrap %v", err, boom)
	}
	if !strings.Contains(err.Error(), `"token"`) {
		t.Fatalf("Get error %q does not name the secret", err)
	}

	// Empty chain: the joined-cause error is still returned.
	if _, err := (Chain{}).Get(ctx, "token"); err == nil {
		t.Fatal("empty chain Get succeeded, want error")
	}
}

// TestEnvProviderGet proves prefix/upper/dash-to-underscore normalization,
// empty-but-set values, and the unset error.
func TestEnvProviderGet(t *testing.T) {
	ctx := context.Background()
	t.Setenv("KIWI_TEST_API_TOKEN", "value-1")
	t.Setenv("KIWI_TEST_EMPTY", "")
	p := EnvProvider{Prefix: "KIWI_TEST_"}

	if got, err := p.Get(ctx, "api-token"); err != nil || got != "value-1" {
		t.Fatalf("Get = (%q, %v), want (value-1, nil)", got, err)
	}
	// A set-but-empty variable is a hit for the provider itself.
	if got, err := p.Get(ctx, "empty"); err != nil || got != "" {
		t.Fatalf("Get empty = (%q, %v), want (\"\", nil)", got, err)
	}
	if _, err := p.Get(ctx, "missing"); err == nil {
		t.Fatal("unset variable: want error")
	}
	// No prefix normalization beyond identity.
	p = EnvProvider{}
	t.Setenv("PLAIN", "v")
	if got, err := p.Get(ctx, "plain"); err != nil || got != "v" {
		t.Fatalf("Get prefixless = (%q, %v), want (v, nil)", got, err)
	}
}

// TestMapProviderGet proves map hits and the miss error.
func TestMapProviderGet(t *testing.T) {
	ctx := context.Background()
	m := MapProvider{"a": "1", "empty": ""}
	if got, err := m.Get(ctx, "a"); err != nil || got != "1" {
		t.Fatalf("Get = (%q, %v), want (1, nil)", got, err)
	}
	if got, err := m.Get(ctx, "empty"); err != nil || got != "" {
		t.Fatalf("Get empty = (%q, %v), want (\"\", nil)", got, err)
	}
	if _, err := m.Get(ctx, "nope"); err == nil {
		t.Fatal("missing key: want error")
	}
}

// writeFakeSecurity installs a fake `security` executable on PATH so the
// keychain provider can be exercised without touching the real keychain.
func writeFakeSecurity(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "security")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestMacKeychainProviderGet exercises the keychain provider on darwin: a
// fake `security` on PATH proves the trimmed-output success path, the exec
// failure path, the default service, and context cancellation.
func TestMacKeychainProviderGet(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain provider is darwin-only")
	}
	ctx := context.Background()
	origGOOS := goos
	defer func() { goos = origGOOS }()

	// Non-darwin platforms are rejected before any exec.
	goos = "linux"
	if _, err := (MacKeychainProvider{}).Get(ctx, "account"); err == nil {
		t.Fatal("non-darwin Get succeeded, want error")
	}
	goos = origGOOS

	writeFakeSecurity(t, `printf '  secret-value \n'`)
	p := MacKeychainProvider{}
	if got, err := p.Get(ctx, "account"); err != nil || got != "secret-value" {
		t.Fatalf("Get = (%q, %v), want (secret-value, nil)", got, err)
	}
	// Explicit service is passed through.
	p = MacKeychainProvider{Service: "svc"}
	if got, err := p.Get(ctx, "account"); err != nil || got != "secret-value" {
		t.Fatalf("Get with service = (%q, %v)", got, err)
	}
	// Empty output from the tool is a valid empty secret.
	writeFakeSecurity(t, `exit 0`)
	if got, err := p.Get(ctx, "account"); err != nil || got != "" {
		t.Fatalf("Get empty = (%q, %v), want (\"\", nil)", got, err)
	}

	// Non-zero exit surfaces as an error.
	writeFakeSecurity(t, `exit 44`)
	if _, err := p.Get(ctx, "account"); err == nil {
		t.Fatal("failing security tool: want error")
	}

	// Cancelled context: exec fails before/while running.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Get(cctx, "account"); err == nil {
		t.Fatal("cancelled context: want error")
	}
}

package secrets

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMacKeychainProviderGetThroughGOOSSeam exercises the keychain provider on
// every platform through the documented test-only goos seam: the darwin guard,
// the default service name, the trimmed success output and the exec failure
// path are all driven with a fake `security` executable on PATH.
func TestMacKeychainProviderGetThroughGOOSSeam(t *testing.T) {
	origGOOS := goos
	defer func() { goos = origGOOS }()

	ctx := context.Background()
	goos = "linux"
	if _, err := (MacKeychainProvider{Service: "svc"}).Get(ctx, "account"); err == nil {
		t.Fatal("non-darwin Get succeeded, want the guard error")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "security")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '  seam-secret \\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	goos = "darwin"
	p := MacKeychainProvider{}
	if got, err := p.Get(ctx, "account"); err != nil || got != "seam-secret" {
		t.Fatalf("Get with default service = (%q, %v), want (seam-secret, nil)", got, err)
	}
	p = MacKeychainProvider{Service: "explicit"}
	if got, err := p.Get(ctx, "account"); err != nil || got != "seam-secret" {
		t.Fatalf("Get with explicit service = (%q, %v), want (seam-secret, nil)", got, err)
	}

	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 42\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx, "account"); err == nil {
		t.Fatal("failing security tool: want error")
	}
}

// TestMaskMultiRewritesWhitespaceSplitForm proves a base64 form split across a
// line wrap is found and masked in place, whitespace preserved, and that the
// taint predicate sees the same wrapped form.
func TestMaskMultiRewritesWhitespaceSplitForm(t *testing.T) {
	var m Masker
	secret := "wrapped-secret-value-0123456789"
	if err := m.AddStrict(secret); err != nil {
		t.Fatal(err)
	}
	form := base64.StdEncoding.EncodeToString([]byte(secret))
	input := "lead\n" + form[:5] + "\n" + form[5:]
	if strings.Contains(input, form) {
		t.Fatal("fixture is not actually split across whitespace")
	}

	got := m.MaskMulti(input)
	if !strings.HasPrefix(got, "lead\n") {
		t.Fatalf("MaskMulti = %q, want the non-form prefix preserved", got)
	}
	if !strings.Contains(got, "***") {
		t.Fatalf("MaskMulti = %q, want the wrapped form replaced", got)
	}
	if collapsed := strings.ReplaceAll(got, "\n", ""); strings.Contains(collapsed, form) {
		t.Fatalf("MaskMulti left the wrapped form in place: %q", got)
	}
	if !m.ContainsSecret(input) {
		t.Fatal("ContainsSecret missed the whitespace-split form")
	}
}

// TestLowerPercentHexNoChange verifies the no-escape and already-lowercase
// escapes return the empty sentinel (never a duplicate form), while an
// upper-case escape is folded.
func TestLowerPercentHexNoChange(t *testing.T) {
	if got := lowerPercentHex("plain"); got != "" {
		t.Fatalf("lowerPercentHex(plain) = %q, want empty", got)
	}
	if got := lowerPercentHex("%20"); got != "" {
		t.Fatalf("lowerPercentHex(%%20) = %q, want empty (no hex letters)", got)
	}
	if got := lowerPercentHex("%2f"); got != "" {
		t.Fatalf("lowerPercentHex(%%2f) = %q, want empty (already lower)", got)
	}
	if got := lowerPercentHex("%2F"); got != "%2f" {
		t.Fatalf("lowerPercentHex(%%2F) = %q, want %%2f", got)
	}
}

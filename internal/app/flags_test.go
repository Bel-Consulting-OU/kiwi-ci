package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// TestParseFlagsAndPositionals pins the flag/positional split that lets the
// documented `COMMAND RUN [--flags]` order work: value-taking flags consume
// their value, boolean flags do not, --flag=value works, and unknown flags
// still fail.
func TestParseFlagsAndPositionals(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	srv := fs.String("server", "", "server")
	follow := fs.Bool("follow", false, "follow")
	rest, err := parseFlagsAndPositionals(fs, []string{"run1", "--server", "http://x", "--follow"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rest) != 1 || rest[0] != "run1" {
		t.Fatalf("positionals = %v, want [run1]", rest)
	}
	if *srv != "http://x" || !*follow {
		t.Fatalf("flags = %q,%v", *srv, *follow)
	}

	fs2 := flag.NewFlagSet("t2", flag.ContinueOnError)
	srv2 := fs2.String("server", "", "server")
	rest, err = parseFlagsAndPositionals(fs2, []string{"--server=http://y", "run2", "--", "--looks-like-a-flag"})
	if err != nil {
		t.Fatalf("parse2: %v", err)
	}
	if *srv2 != "http://y" {
		t.Fatalf("server = %q", *srv2)
	}
	if len(rest) != 2 || rest[0] != "run2" || rest[1] != "--looks-like-a-flag" {
		t.Fatalf("positionals after -- = %v", rest)
	}

	fs3 := flag.NewFlagSet("t3", flag.ContinueOnError)
	if _, err := parseFlagsAndPositionals(fs3, []string{"run", "--nope"}); err == nil {
		t.Fatal("unknown flag must fail")
	}
}

func TestParseDownstreamAllowlist(t *testing.T) {
	got, err := parseDownstreamAllowlist([]string{
		"acme/child=o/r, other/repo",
		"acme/open=",
		"acme/other=o/r",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"acme/child": {"o/r", "other/repo"},
		"acme/open":  {},
		"acme/other": {"o/r"},
	}
	if len(got) != len(want) {
		t.Fatalf("allowlist = %v, want %v", got, want)
	}
	for target, srcs := range want {
		if len(got[target]) != len(srcs) {
			t.Fatalf("allowlist[%q] = %v, want %v", target, got[target], srcs)
		}
		for i, s := range srcs {
			if got[target][i] != s {
				t.Fatalf("allowlist[%q] = %v, want %v", target, got[target], srcs)
			}
		}
	}
	if _, err := parseDownstreamAllowlist([]string{"missing-equals"}); err == nil {
		t.Fatal("entry without = accepted")
	}
	if _, err := parseDownstreamAllowlist([]string{"=sources"}); err == nil {
		t.Fatal("empty target accepted")
	}
	if got, err := parseDownstreamAllowlist(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty input = %v, %v", got, err)
	}
}

func TestParseDownstreamTrustedIngress(t *testing.T) {
	got, err := parseDownstreamTrustedIngress([]string{"acme/child=true", "acme/other=false"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["acme/child"] || got["acme/other"] {
		t.Fatalf("ingress = %v", got)
	}
	if _, err := parseDownstreamTrustedIngress([]string{"acme/child=maybe"}); err == nil {
		t.Fatal("non-boolean value accepted")
	}
	if _, err := parseDownstreamTrustedIngress([]string{"no-equals"}); err == nil {
		t.Fatal("entry without = accepted")
	}
}

func TestParseSigstoreKeysAndLoader(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(t.TempDir(), "sig.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := parseSigstoreKeys([]string{"ci=" + pemPath})
	if err != nil {
		t.Fatal(err)
	}
	if got := keys["ci"]; !got.Equal(pub) {
		t.Fatalf("loaded key %x does not match %x", got, pub)
	}
	// PEM contents are accepted verbatim (not treated as a path).
	contents := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	keys, err = parseSigstoreKeys([]string{"ci=" + contents})
	if err != nil {
		t.Fatalf("PEM contents rejected: %v", err)
	}
	if got := keys["ci"]; !got.Equal(pub) {
		t.Fatalf("PEM-contents key %x does not match %x", got, pub)
	}
	// Raw 32-byte files are accepted.
	rawPath := filepath.Join(t.TempDir(), "raw.key")
	if err := os.WriteFile(rawPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err = parseSigstoreKeys([]string{"raw=" + rawPath})
	if err != nil {
		t.Fatalf("raw key file rejected: %v", err)
	}
	if got := keys["raw"]; !got.Equal(pub) {
		t.Fatalf("raw key %x does not match %x", got, pub)
	}
	// Malformed entries are rejected.
	if _, err := parseSigstoreKeys([]string{"no-equals"}); err == nil {
		t.Fatal("entry without = accepted")
	}
	if _, err := parseSigstoreKeys([]string{"=path"}); err == nil {
		t.Fatal("empty id accepted")
	}
	if _, err := parseSigstoreKeys([]string{"ci=" + filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := loadEd25519PublicKey("-----BEGIN PUBLIC KEY-----\nZ29vZg==\n-----END PUBLIC KEY-----\n"); err == nil {
		t.Fatal("non-Ed25519 PEM accepted")
	}
}

func TestRepeatFlagKeepsCommas(t *testing.T) {
	var f repeatFlag
	for _, v := range []string{"target=src1,src2", "other=src3"} {
		if err := f.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	got := f.values()
	if len(got) != 2 || got[0] != "target=src1,src2" || got[1] != "other=src3" {
		t.Fatalf("repeatFlag values = %v", got)
	}
	if err := f.Set("   "); err != nil {
		t.Fatal(err)
	}
	if len(f.values()) != 2 {
		t.Fatal("blank entry must not be appended")
	}
}

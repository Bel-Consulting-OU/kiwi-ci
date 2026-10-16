package candidate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBin(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func shaOf(t *testing.T, p string) string {
	t.Helper()
	s, err := SHA256File(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A selected candidate that fails its pinned digest is a HARD error — never
// a silent fallback to a source build. Release certification must not
// quietly test different bytes than it certified.
func TestResolveRejectsDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := writeBin(t, dir, "kiwi", "frozen-bytes")
	t.Setenv(EnvBin, bin)
	t.Setenv(EnvSHA256, strings.Repeat("0", 64))
	t.Setenv(EnvFreeze, "")
	if _, _, err := Resolve(filepath.Join(dir, "out")); err == nil {
		t.Fatal("digest mismatch must fail closed")
	}
}

// A matching pin installs the exact bytes and reports the digest.
func TestResolveInstallsMatchingCandidate(t *testing.T) {
	dir := t.TempDir()
	bin := writeBin(t, dir, "kiwi", "frozen-bytes-v1")
	sum := shaOf(t, bin)
	dest := filepath.Join(dir, "installed", "kiwi")
	t.Setenv(EnvBin, bin)
	t.Setenv(EnvSHA256, sum)
	t.Setenv(EnvFreeze, "")
	got, frozen, err := Resolve(dest)
	if err != nil || !frozen {
		t.Fatalf("resolve = %q frozen=%v err=%v", got, frozen, err)
	}
	if got != sum {
		t.Fatalf("digest = %q, want %q", got, sum)
	}
	raw, err := os.ReadFile(dest)
	if err != nil || string(raw) != "frozen-bytes-v1" {
		t.Fatalf("installed bytes = %q err=%v", raw, err)
	}
}

// No candidate selected: development mode, caller builds from source.
func TestResolveNoCandidateIsDev(t *testing.T) {
	t.Setenv(EnvBin, "")
	_, frozen, err := Resolve(filepath.Join(t.TempDir(), "x"))
	if err != nil || frozen {
		t.Fatalf("dev resolve = frozen=%v err=%v", frozen, err)
	}
}

// Release mode refuses a candidate whose digest was never independently
// pinned: hashing the file we were handed is self-authentication.
func TestExpectedDigestRequiresIndependentPin(t *testing.T) {
	dir := t.TempDir()
	bin := writeBin(t, dir, "kiwi", "bytes")
	t.Setenv(EnvBin, bin)
	t.Setenv(EnvSHA256, "")
	t.Setenv(EnvFreeze, "")
	// expectedDigest returns "" (no pin) — Resolve still installs, but
	// fetch-n-minus-one.sh is the layer that refuses self-auth under
	// REQUIRE_RELEASED. This test pins the "no pin available" signal.
	want, err := expectedDigest(bin)
	if err != nil || want != "" {
		t.Fatalf("expectedDigest with no pin = %q err=%v, want empty", want, err)
	}
}

// The FREEZE manifest's SHA256SUMS is independent metadata: a matching
// platform entry must be accepted as the pin.
func TestExpectedDigestFromFreezeSums(t *testing.T) {
	dir := t.TempDir()
	bin := writeBin(t, dir, "kiwi-linux-amd64", "platform-bytes")
	sum := shaOf(t, bin)
	freeze := filepath.Join(dir, "FREEZE")
	if err := os.WriteFile(freeze, []byte("version=0.0.0\ncommit="+strings.Repeat("a", 40)+"\nfreeze_sha256="+strings.Repeat("b", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sum+"  kiwi-linux-amd64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvBin, bin)
	t.Setenv(EnvSHA256, "")
	t.Setenv(EnvFreeze, freeze)
	t.Setenv(EnvPlatform, "kiwi-linux-amd64")
	got, frozen, err := Resolve(filepath.Join(dir, "out"))
	if err != nil || !frozen {
		t.Fatalf("resolve = frozen=%v err=%v", frozen, err)
	}
	if got != sum {
		t.Fatalf("digest = %q, want %q", got, sum)
	}
}

// A FREEZE SHA256SUMS without the requested platform is a hard error.
func TestExpectedDigestMissingPlatform(t *testing.T) {
	dir := t.TempDir()
	bin := writeBin(t, dir, "kiwi", "bytes")
	freeze := filepath.Join(dir, "FREEZE")
	if err := os.WriteFile(freeze, []byte("version=0.0.0\ncommit="+strings.Repeat("a", 40)+"\nfreeze_sha256="+strings.Repeat("b", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Repeat("c", 64)+"  kiwi-other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvBin, bin)
	t.Setenv(EnvSHA256, "")
	t.Setenv(EnvFreeze, freeze)
	t.Setenv(EnvPlatform, "kiwi-linux-amd64")
	if _, _, err := Resolve(filepath.Join(dir, "out")); err == nil {
		t.Fatal("missing platform entry must fail closed")
	}
}

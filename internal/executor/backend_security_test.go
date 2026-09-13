package executor

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/kiwici/kiwi/internal/pipeline"
)

// TestServiceNetworkInternalFlag asserts the pure args builder adds --internal
// exactly when isolation is requested (no docker daemon required).
func TestServiceNetworkInternalFlag(t *testing.T) {
	args := serviceNetworkArgs(true)
	if !contains(args, "--internal") {
		t.Fatalf("isolated network args missing --internal: %v", args)
	}
	for _, want := range []string{"create", "--driver", "bridge"} {
		if !contains(args, want) {
			t.Fatalf("network args missing %q: %v", want, args)
		}
	}
	args = serviceNetworkArgs(false)
	if contains(args, "--internal") {
		t.Fatalf("non-isolated network args must not include --internal: %v", args)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestImmutableImageRejected verifies the digest check fires before any
// docker invocation: even with no docker installed the error names the
// missing digest, not the missing binary.
func TestImmutableImageRejected(t *testing.T) {
	b := &ContainerBackend{Image: "golang:1.23", RequireImmutableImages: true}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil {
		t.Fatal("expected immutable-image rejection")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("error does not explain the digest requirement: %v", err)
	}
	if strings.Contains(err.Error(), "docker not found") {
		t.Fatalf("digest check ran after docker lookup: %v", err)
	}
}

// TestTartNetworkRefused verifies tart jobs that require network isolation
// fail closed before any tart invocation.
func TestTartNetworkRefused(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("tart backend is macOS-only")
	}
	for _, mode := range []string{"none", "services-only"} {
		b := &TartBackend{VM: "ghcr.io/cirruslabs/macos-sonoma-base:latest", Network: mode}
		err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
		if err == nil {
			t.Fatalf("expected tart to refuse network mode %q", mode)
		}
		if !strings.Contains(err.Error(), "tart runtime does not support network isolation") {
			t.Fatalf("unexpected error for mode %q: %v", mode, err)
		}
		if !strings.Contains(err.Error(), mode) {
			t.Fatalf("error does not name the requested policy %q: %v", mode, err)
		}
		if strings.Contains(err.Error(), "tart not found") {
			t.Fatalf("network check ran after tart lookup: %v", err)
		}
	}
}

// TestTartImmutableRefRejected verifies unpinned VM references are rejected
// before any tart invocation.
func TestTartImmutableRefRejected(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("tart backend is macOS-only")
	}
	b := &TartBackend{VM: "ghcr.io/cirruslabs/macos-sonoma-base:latest", RequireImmutableImages: true}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil {
		t.Fatal("expected immutable VM rejection")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("error does not explain the digest requirement: %v", err)
	}
	if strings.Contains(err.Error(), "tart not found") {
		t.Fatalf("digest check ran after tart lookup: %v", err)
	}
}

// TestTartKeyGeneration verifies the ephemeral keypair helper produces an
// OpenSSH-compatible key file and public key without any external binary
// (crypto/ed25519 fallback path).
func TestTartKeyGeneration(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/id_ed25519"
	if err := writeGoGeneratedKey(keyPath); err != nil {
		t.Fatal(err)
	}
	priv, err := readFileNoFollow(keyPath, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(priv), "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("private key is not PEM: %q", priv)
	}
	pub, err := readFileNoFollow(keyPath+".pub", 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pub), "ssh-ed25519 ") {
		t.Fatalf("public key is not OpenSSH format: %q", pub)
	}
}

// TestValidateNetworkAndSandbox verifies the new pipeline validation rules:
// job.network allowlist and sandbox.network enum bounds.
func TestValidateNetworkAndSandbox(t *testing.T) {
	base := "version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n"
	validNetworks := []string{"", "bridge", "host", "none"}
	for _, n := range validNetworks {
		networkLine := ""
		if n != "" {
			networkLine = "    network: " + n + "\n"
		}
		if _, err := pipeline.Parse([]byte(base + networkLine)); err != nil {
			t.Fatalf("network %q should be valid: %v", n, err)
		}
	}
	if _, err := pipeline.Parse([]byte(base + "    network: vpn\n")); err == nil {
		t.Fatal("expected validation error for network \"vpn\"")
	}
	s, err := pipeline.Parse([]byte(base + `    sandbox:
      network: 2
      rootless: true
      read_only_rootfs: true
`))
	if err != nil {
		t.Fatal(err)
	}
	sb := s.Jobs["a"].Sandbox
	if sb.Network != pipeline.NetworkPolicyServicesOnly {
		t.Fatalf("network policy = %d, want %d", sb.Network, pipeline.NetworkPolicyServicesOnly)
	}
	if !sb.Rootless || !sb.ReadOnlyRootFS {
		t.Fatalf("sandbox flags not decoded: %+v", sb)
	}
	if _, err := pipeline.Parse([]byte(base + "    sandbox:\n      network: 99\n")); err == nil {
		t.Fatal("expected validation error for sandbox.network 99")
	}
	if _, err := pipeline.Parse([]byte(base + "    sandbox:\n      network: -1\n")); err == nil {
		t.Fatal("expected validation error for sandbox.network -1")
	}
}

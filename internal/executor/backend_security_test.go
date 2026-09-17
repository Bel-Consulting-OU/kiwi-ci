package executor

import (
	"context"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
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

// TestTartSSHArgsAreHardened asserts every ssh argument set the tart backend
// constructs carries the hardened, job-scoped posture — StrictHostKeyChecking
// accept-new pinned to the per-job known_hosts file, IdentitiesOnly=yes, and
// -i with the ephemeral per-job key — and that no insecure host-verification
// options (StrictHostKeyChecking=no, UserKnownHostsFile=/dev/null) appear
// anywhere in the constructed args.
func TestTartSSHArgsAreHardened(t *testing.T) {
	b := &TartBackend{sshDir: "/tmp/kiwi-ssh-42", ip: "192.0.2.1"}
	args := b.hardenedSSHArgs("admin@"+b.ip, "true")
	if !contains(args, "StrictHostKeyChecking=accept-new") {
		t.Fatalf("missing accept-new host-key posture: %v", args)
	}
	if !contains(args, "UserKnownHostsFile="+b.knownHostsFile()) {
		t.Fatalf("missing per-job known_hosts file: %v", args)
	}
	if !contains(args, "IdentitiesOnly=yes") {
		t.Fatalf("missing IdentitiesOnly=yes: %v", args)
	}
	if !contains(args, "-i") {
		t.Fatalf("missing -i flag: %v", args)
	}
	if !contains(args, b.keyFile()) {
		t.Fatalf("missing ephemeral key path: %v", args)
	}
	joined := strings.Join(args, " ")
	for _, insecure := range []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "/dev/null"} {
		if strings.Contains(joined, insecure) {
			t.Fatalf("insecure ssh option %q present in %v", insecure, args)
		}
	}
}

// TestTartSSHAuthFailureIsHardError simulates ssh exiting 255 (the ssh(1)
// authentication/host-key failure code) with a fake ssh script that records
// every invocation, and asserts the tart backend fails hard: exactly one ssh
// invocation, no retry, and no insecure options in the args the fake ssh
// received.
func TestTartSSHAuthFailureIsHardError(t *testing.T) {
	testutil.UnixShell(t)
	if runtime.GOOS == "windows" {
		t.Skip("fake ssh script is a POSIX shell script")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "invocations")
	fake := filepath.Join(dir, "ssh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + shellQuote(record) + "\necho 'Permission denied (publickey).' >&2\nexit 255\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &TartBackend{ssh: fake, ip: "192.0.2.1", sshDir: dir}
	consume := func(r io.Reader) error {
		_, err := io.ReadAll(r)
		return err
	}
	err := b.sshRun(context.Background(), nil, "true", consume, consume)
	if err == nil {
		t.Fatal("expected hard error on ssh exit 255")
	}
	if !strings.Contains(err.Error(), "255") {
		t.Fatalf("error does not surface the ssh exit code: %v", err)
	}
	lines, rerr := os.ReadFile(record)
	if rerr != nil {
		t.Fatal(rerr)
	}
	invocations := strings.Split(strings.TrimSpace(string(lines)), "\n")
	if len(invocations) != 1 || invocations[0] == "" {
		t.Fatalf("ssh invocations = %q, want exactly one", lines)
	}
	argsLine := invocations[0]
	if !strings.Contains(argsLine, "IdentitiesOnly=yes") || !strings.Contains(argsLine, "-i "+b.keyFile()) {
		t.Fatalf("invocation is missing hardened identity options: %s", argsLine)
	}
	for _, insecure := range []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "/dev/null"} {
		if strings.Contains(argsLine, insecure) {
			t.Fatalf("insecure ssh option %q present in invocation: %s", insecure, argsLine)
		}
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

package runner

import (
	"strings"
	"testing"
)

func TestValidatePrewarmRefs(t *testing.T) {
	valid := []string{
		"docker.io/library/alpine@sha256:abc123",
		"ghcr.io/acme/app@sha256:def456",
		"tart:ghcr.io/acme/vm@sha256:111222",
	}
	if err := validatePrewarmRefs(valid); err != nil {
		t.Fatalf("digest-pinned refs rejected: %v", err)
	}
	invalid := []string{
		"alpine:latest",
		"ghcr.io/acme/app",
		"ghcr.io/acme/app@latest",
	}
	for _, ref := range invalid {
		if err := validatePrewarmRefs([]string{ref}); err == nil {
			t.Fatalf("non-digest ref %q accepted", ref)
		} else if !strings.Contains(err.Error(), "not pinned by digest") {
			t.Fatalf("ref %q: unexpected error %v", ref, err)
		}
	}
	if err := validatePrewarmRefs([]string{""}); err == nil || !strings.Contains(err.Error(), "empty image reference") {
		t.Fatalf("empty ref: unexpected error %v", err)
	}
}

func TestPrewarmRemovals(t *testing.T) {
	prev := prewarmState{Version: 1, Items: []prewarmItem{
		{Ref: "img/a@sha256:1", Kind: "docker"},
		{Ref: "img/b@sha256:2", Kind: "docker"},
		{Ref: "img/c@sha256:3", Kind: "tart"},
	}}
	remove, keep := prewarmRemovals(prev, []string{"img/a@sha256:1"})
	if len(remove) != 2 || len(keep) != 1 || keep[0].Ref != "img/a@sha256:1" {
		t.Fatalf("remove=%v keep=%v", remove, keep)
	}
}

func TestCapPrewarmItems(t *testing.T) {
	items := make([]prewarmItem, 0, 12)
	for _, ref := range []string{"z@sha256:1", "a@sha256:2", "m@sha256:3", "b@sha256:4"} {
		items = append(items, prewarmItem{Ref: ref, Kind: "docker"})
	}
	capped := capPrewarmItems(items, 2)
	if len(capped) != 2 {
		t.Fatalf("capped length = %d, want 2", len(capped))
	}
	if capped[0].Ref != "a@sha256:2" || capped[1].Ref != "b@sha256:4" {
		t.Fatalf("capped set not deterministic: %v", capped)
	}
}

func TestParsePrewarmRef(t *testing.T) {
	digest := strings.Repeat("a", 64)
	docker, err := parsePrewarmRef("ghcr.io/acme/app@sha256:" + digest)
	if err != nil {
		t.Fatalf("docker ref: %v", err)
	}
	if docker.Kind != "docker" || docker.Ref != "ghcr.io/acme/app@sha256:"+digest {
		t.Fatalf("docker ref parsed wrong: %+v", docker)
	}

	tart, err := parsePrewarmRef("tart://ghcr.io/cirruslabs/macos-sonoma-base@sha256:" + digest)
	if err != nil {
		t.Fatalf("tart ref: %v", err)
	}
	if tart.Kind != "tart" {
		t.Fatalf("kind = %q, want tart", tart.Kind)
	}
	if tart.Image != "ghcr.io/cirruslabs/macos-sonoma-base" {
		t.Fatalf("image = %q", tart.Image)
	}
	if tart.Digest != "sha256:"+digest {
		t.Fatalf("digest = %q", tart.Digest)
	}
	if !strings.HasPrefix(tart.VMName, prewarmVMNamePrefix) {
		t.Fatalf("VM name %q lacks prefix %q", tart.VMName, prewarmVMNamePrefix)
	}

	if _, err := parsePrewarmRef(""); err == nil {
		t.Fatal("empty ref accepted")
	}
	if _, err := parsePrewarmRef("tart://ghcr.io/acme/vm"); err == nil {
		t.Fatal("tart ref without digest accepted")
	}
	if _, err := parsePrewarmRef("tart://ghcr.io/acme/vm@sha256:short"); err == nil {
		t.Fatal("tart ref with short digest accepted")
	}
	if _, err := parsePrewarmRef("tart://@sha256:" + digest); err == nil {
		t.Fatal("tart ref without image accepted")
	}
}

func TestPrewarmVMNameDeterministic(t *testing.T) {
	a := prewarmVMName("ghcr.io/cirruslabs/macos-sonoma-base")
	b := prewarmVMName("ghcr.io/cirruslabs/macos-sonoma-base")
	if a != b {
		t.Fatalf("VM name not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, prewarmVMNamePrefix) {
		t.Fatalf("VM name %q lacks prefix", a)
	}
	if strings.ContainsAny(a, "/:@") {
		t.Fatalf("VM name %q contains invalid characters", a)
	}
}

func TestValidatePrewarmRefsTartForms(t *testing.T) {
	digest := strings.Repeat("b", 64)
	valid := []string{
		"docker.io/library/alpine@sha256:abc123",
		"tart://ghcr.io/acme/vm@sha256:" + digest,
		"tart:ghcr.io/acme/vm@sha256:111222",
	}
	if err := validatePrewarmRefs(valid); err != nil {
		t.Fatalf("valid refs rejected: %v", err)
	}
	if err := validatePrewarmRefs([]string{"tart://ghcr.io/acme/vm@sha256:tooshort"}); err == nil {
		t.Fatal("invalid tart digest accepted")
	}
}

func TestParseTartList(t *testing.T) {
	fixture := []byte(`[
  {"name": "kiwi-prewarm-ghcr-io-cirruslabs-macos-sonoma-base", "source": "ghcr.io/cirruslabs/macos-sonoma-base@sha256:` + strings.Repeat("c", 64) + `", "size": 456},
  {"name": "my-dev-vm", "source": "ghcr.io/cirruslabs/macos-sonoma-base@sha256:` + strings.Repeat("d", 64) + `", "size": 123}
]`)
	vms, err := parseTartList(fixture)
	if err != nil {
		t.Fatalf("parseTartList: %v", err)
	}
	if len(vms) != 2 {
		t.Fatalf("parsed %d VMs, want 2", len(vms))
	}
	if vms[0].Name != "kiwi-prewarm-ghcr-io-cirruslabs-macos-sonoma-base" {
		t.Fatalf("first VM name = %q", vms[0].Name)
	}
	if _, err := parseTartList([]byte("not json")); err == nil {
		t.Fatal("malformed tart list accepted")
	}
}

func TestTartStaleVMs(t *testing.T) {
	keepDigest := "sha256:" + strings.Repeat("c", 64)
	staleDigest := "sha256:" + strings.Repeat("d", 64)
	vms := []tartVM{
		{Name: "kiwi-prewarm-stale", Source: "ghcr.io/acme/old@sha256:" + strings.Repeat("e", 64)},
		{Name: "kiwi-prewarm-keep", Source: "ghcr.io/acme/app@" + keepDigest},
		{Name: "kiwi-prewarm-nodigest", Source: "ghcr.io/acme/app:latest"},
		{Name: "unrelated-vm", Source: "ghcr.io/acme/app@" + staleDigest},
	}
	got := tartStaleVMs(vms, map[string]bool{keepDigest: true})
	want := []string{"kiwi-prewarm-nodigest", "kiwi-prewarm-stale"}
	if len(got) != len(want) {
		t.Fatalf("stale VMs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stale VMs = %v, want %v (deterministic order)", got, want)
		}
	}
	if got := tartStaleVMs(vms, map[string]bool{}); len(got) != 3 {
		t.Fatalf("empty wanted set must mark all prewarmed VMs stale, got %v", got)
	}
}

func TestTartSourceDigest(t *testing.T) {
	if got := tartSourceDigest("ghcr.io/acme/app@sha256:" + strings.Repeat("f", 64)); got != "sha256:"+strings.Repeat("f", 64) {
		t.Fatalf("source digest = %q", got)
	}
	if got := tartSourceDigest("ghcr.io/acme/app:latest"); got != "" {
		t.Fatalf("tagged source must have no digest, got %q", got)
	}
}

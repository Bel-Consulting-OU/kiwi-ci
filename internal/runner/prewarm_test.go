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

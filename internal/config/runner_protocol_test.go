package config

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMinRunnerProtocolDefault pins the fail-closed default: an unset
// server.min_runner_protocol takes the current wire-semantic protocol, so a
// legacy runner (absent protocol_version) is refused unless an operator
// deliberately lowers the floor for an upgrade window.
func TestMinRunnerProtocolDefault(t *testing.T) {
	cfg := Default()
	if cfg.Server.MinRunnerProtocol != model.RunnerProtocolVersion {
		t.Fatalf("default min_runner_protocol = %d, want %d", cfg.Server.MinRunnerProtocol, model.RunnerProtocolVersion)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}
	if cfg.Server.MinRunnerProtocol != model.RunnerProtocolVersion {
		t.Fatalf("Validate changed the default to %d", cfg.Server.MinRunnerProtocol)
	}
}

// TestMinRunnerProtocolValidation covers the accepted and refused ranges:
// unset/0 falls back to the default (the zero-value Config must keep
// validating), 1 is the explicit upgrade-window floor, negatives and values
// above the running binary's protocol are rejected.
func TestMinRunnerProtocolValidation(t *testing.T) {
	zero := &Config{}
	if err := zero.Validate(); err != nil {
		t.Fatalf("zero-value config must validate with defaults: %v", err)
	}
	if zero.Server.MinRunnerProtocol != model.RunnerProtocolVersion {
		t.Fatalf("zero-value config min = %d, want the default %d", zero.Server.MinRunnerProtocol, model.RunnerProtocolVersion)
	}
	window := Default()
	window.Server.MinRunnerProtocol = 1
	if err := window.Validate(); err != nil {
		t.Fatalf("upgrade-window floor 1 must validate: %v", err)
	}
	negative := Default()
	negative.Server.MinRunnerProtocol = -1
	if err := negative.Validate(); err == nil || !strings.Contains(err.Error(), "min_runner_protocol") {
		t.Fatalf("negative floor = %v, want a min_runner_protocol error", err)
	}
	future := Default()
	future.Server.MinRunnerProtocol = model.RunnerProtocolVersion + 1
	if err := future.Validate(); err == nil || !strings.Contains(err.Error(), "min_runner_protocol") {
		t.Fatalf("future floor = %v, want a min_runner_protocol error", err)
	}
}

// TestMinRunnerProtocolTOMLRoundTrip proves the config key is part of the
// strict schema and that an explicit upgrade-window value survives loading.
func TestMinRunnerProtocolTOMLRoundTrip(t *testing.T) {
	cfg, err := Load(writeTemp(t, "[server]\nmin_runner_protocol = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MinRunnerProtocol != 1 {
		t.Fatalf("loaded min_runner_protocol = %d, want 1", cfg.Server.MinRunnerProtocol)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loaded upgrade-window config must validate: %v", err)
	}
	if _, err := Load(writeTemp(t, "[server]\nmin_protocol = 1\n")); err == nil {
		t.Fatal("misspelled key must be refused by the strict schema")
	}
}

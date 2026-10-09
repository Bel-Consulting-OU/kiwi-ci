package config

import (
	"strings"
	"testing"
)

// TestEventsRetentionConfig pins server.events_retention parsing and
// validation: the default is 7 days, "0" is accepted (retention disabled),
// and a malformed or negative duration is refused at startup.
func TestEventsRetentionConfig(t *testing.T) {
	if got := Default().Server.EventsRetention; got != "168h" {
		t.Fatalf("default events_retention = %q, want 168h", got)
	}
	if Default().Server.EventsRetentionPrune {
		t.Fatal("events_retention_prune must default to false (two-phase activation)")
	}

	cfg, err := Load(writeTemp(t, "[server]\nevents_retention = \"0\"\n"))
	if err != nil {
		t.Fatalf("load events_retention=0: %v", err)
	}
	if cfg.Server.EventsRetention != "0" {
		t.Fatalf("events_retention = %q, want 0", cfg.Server.EventsRetention)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("events_retention=0 must validate: %v", err)
	}

	cfg, err = Load(writeTemp(t, "[server]\nevents_retention = \"48h\"\n"))
	if err != nil {
		t.Fatalf("load events_retention=48h: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("events_retention=48h must validate: %v", err)
	}

	for _, raw := range []string{"-1h", "not-a-duration"} {
		bad := Default()
		bad.Server.EventsRetention = raw
		err := bad.Validate()
		if err == nil || !strings.Contains(err.Error(), "events_retention") {
			t.Fatalf("events_retention=%q validation = %v, want an events_retention error", raw, err)
		}
	}
}

// TestEventsRetentionPruneConfig pins the two-phase gate: the flag parses,
// enabling it with a positive/default window validates, and enabling it
// while retention is explicitly disabled is refused (there is nothing to
// prune).
func TestEventsRetentionPruneConfig(t *testing.T) {
	cfg, err := Load(writeTemp(t, "[server]\nevents_retention = \"48h\"\nevents_retention_prune = true\n"))
	if err != nil {
		t.Fatalf("load events_retention_prune: %v", err)
	}
	if !cfg.Server.EventsRetentionPrune {
		t.Fatal("events_retention_prune did not parse as true")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("prune with a window must validate: %v", err)
	}

	bad := Default()
	bad.Server.EventsRetention = "0"
	bad.Server.EventsRetentionPrune = true
	err = bad.Validate()
	if err == nil || !strings.Contains(err.Error(), "events_retention") {
		t.Fatalf("prune with events_retention=0 validation = %v, want an events_retention error", err)
	}
}

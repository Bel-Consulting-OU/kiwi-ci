package app

import (
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestApplyEventsRetentionWiring pins the server.events_retention translation:
// the config default keeps the 7-day server default, "0" is the explicit
// disable sentinel (negative, meaning "never prune") and a positive duration
// is the age window.
func TestApplyEventsRetentionWiring(t *testing.T) {
	srv := server.New("r")
	applyQuotaConfig(srv, config.Default())
	if srv.EventsRetention != 168*time.Hour {
		t.Fatalf("default events retention = %v, want 168h", srv.EventsRetention)
	}

	cfg := config.Default()
	cfg.Server.EventsRetention = "0"
	srv = server.New("r")
	applyQuotaConfig(srv, cfg)
	if srv.EventsRetention != -1 {
		t.Fatalf("events_retention=0 wired to %v, want the disabled sentinel -1", srv.EventsRetention)
	}

	cfg.Server.EventsRetention = "24h"
	srv = server.New("r")
	applyQuotaConfig(srv, cfg)
	if srv.EventsRetention != 24*time.Hour {
		t.Fatalf("events_retention=24h wired to %v", srv.EventsRetention)
	}

	// An empty value (a hand-built config) keeps the server's built-in
	// default rather than disabling retention.
	cfg.Server.EventsRetention = ""
	srv = server.New("r")
	applyQuotaConfig(srv, cfg)
	if srv.EventsRetention != 168*time.Hour {
		t.Fatalf("empty events_retention wired to %v, want the built-in default", srv.EventsRetention)
	}

	// The two-phase prune gate is wired independently of the window.
	if srv.EventsRetentionPrune {
		t.Fatal("events_retention_prune default wired to true, want false")
	}
	cfg.Server.EventsRetention = "24h"
	cfg.Server.EventsRetentionPrune = true
	srv = server.New("r")
	applyQuotaConfig(srv, cfg)
	if srv.EventsRetention != 24*time.Hour || !srv.EventsRetentionPrune {
		t.Fatalf("wired retention/prune = %v/%v, want 24h/true", srv.EventsRetention, srv.EventsRetentionPrune)
	}
}

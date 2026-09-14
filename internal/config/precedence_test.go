package config

import (
	"flag"
	"testing"
)

func TestPrecedence(t *testing.T) {
	// Config file > defaults.
	cfg, err := Load(writeTemp(t, "[server]\nlisten = \":7070\"\nmode = \"dev\"\n[auth]\nadmin_token = \"file-admin\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Env > config file.
	t.Setenv("KIWI_SERVER_LISTEN", ":8081")
	// CLI > env.
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.String("listen", "", "")
	fs.String("admin-token", "", "")
	fs.String("runner-token", "", "")
	fs.String("mode", "", "")
	if err := fs.Parse([]string{"-listen", ":9090", "-mode", "production"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":9090" {
		t.Errorf("CLI did not win: listen = %q, want :9090", cfg.Server.Listen)
	}
	if cfg.Server.Mode != "production" {
		t.Errorf("CLI mode = %q, want production", cfg.Server.Mode)
	}
	if cfg.Auth.AdminToken != "file-admin" {
		t.Errorf("config file value lost: admin = %q, want file-admin", cfg.Auth.AdminToken)
	}
}

func TestPrecedenceEnvBeatsFile(t *testing.T) {
	cfg, err := Load(writeTemp(t, "[server]\nlisten = \":7070\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KIWI_SERVER_LISTEN", ":8081")
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":8081" {
		t.Errorf("env did not beat file: listen = %q", cfg.Server.Listen)
	}
}

func TestRateLimitClassesAndMiddleware(t *testing.T) {
	cfg := Default()
	if m := cfg.RateLimitMiddleware(); m != nil {
		t.Fatal("default config must disable rate limiting, got middleware")
	}
	cfg.RateLimit.PerSecond = 10
	cfg.RateLimit.Burst = 7
	cfg.RateLimit.LogsPerSecond = 25
	classes := cfg.RateLimitClasses()
	if classes["default"] != 10 || classes["logs"] != 25 || classes["next"] != 10 {
		t.Errorf("classes = %v", classes)
	}
	if cfg.RateLimitBurst() != 7 {
		t.Errorf("burst = %d, want 7", cfg.RateLimitBurst())
	}
	if m := cfg.RateLimitMiddleware(); m == nil {
		t.Fatal("enabled rate limit config produced nil middleware")
	}
}

func TestOverrideRateLimitFlags(t *testing.T) {
	cfg := Default()
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.Float64("rate-limit-per-second", 0, "")
	fs.Int("rate-limit-burst", 0, "")
	if err := fs.Parse([]string{"-rate-limit-per-second", "3.5", "-rate-limit-burst", "12"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimit.PerSecond != 3.5 || cfg.RateLimit.Burst != 12 {
		t.Errorf("rate limit flags not applied: %+v", cfg.RateLimit)
	}
	if m := cfg.RateLimitMiddleware(); m == nil {
		t.Fatal("flag-configured rate limit produced nil middleware")
	}
}

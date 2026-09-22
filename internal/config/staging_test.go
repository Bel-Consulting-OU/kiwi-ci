package config

import (
	"flag"
	"strings"
	"testing"
)

func TestStagingTOMLRoundTrip(t *testing.T) {
	p := writeTemp(t, `
[staging]
dir = "/var/lib/kiwi/staging"
max_bytes = 34359738368
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Staging.Dir != "/var/lib/kiwi/staging" || cfg.Staging.MaxBytes != 34359738368 {
		t.Fatalf("staging section = %+v", cfg.Staging)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("configured staging section should validate: %v", err)
	}
	// No staging section keeps the unset (dev) default.
	cfg, err = Load(writeTemp(t, "[server]\nmode = \"dev\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Staging.Dir != "" || cfg.Staging.MaxBytes != 0 {
		t.Fatalf("unset staging = %+v, want zero", cfg.Staging)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unset staging should validate in dev: %v", err)
	}
}

func TestStagingValidationAllOrNothing(t *testing.T) {
	cases := map[string]struct {
		st        StagingConfig
		wantError string
	}{
		"both set":    {StagingConfig{Dir: "/var/lib/kiwi/staging", MaxBytes: 1 << 30}, ""},
		"neither set": {StagingConfig{}, ""},
		"dir only":    {StagingConfig{Dir: "/var/lib/kiwi/staging"}, "staging.max_bytes"},
		"bytes only":  {StagingConfig{MaxBytes: 1 << 30}, "staging.dir"},
		"zero bytes":  {StagingConfig{Dir: "/tmp/staging", MaxBytes: 0}, "staging.max_bytes"},
		"negative":    {StagingConfig{Dir: "/tmp/staging", MaxBytes: -5}, "staging.max_bytes"},
		"blank dir":   {StagingConfig{Dir: "   ", MaxBytes: 1 << 30}, "staging.dir"},
		"blank+bytes": {StagingConfig{Dir: "   ", MaxBytes: 0}, ""},
		"tiny budget": {StagingConfig{Dir: "/tmp/staging", MaxBytes: 1}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			cfg.Staging = tc.st
			err := cfg.Validate()
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("Validate(%+v) = %v, want nil", tc.st, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Validate(%+v) = %v, want error mentioning %q", tc.st, err, tc.wantError)
			}
		})
	}
}

func TestStagingEnvOverride(t *testing.T) {
	t.Setenv("KIWI_STAGING_DIR", "/env/staging")
	t.Setenv("KIWI_STAGING_MAX_BYTES", "987654321")
	cfg := Default()
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if cfg.Staging.Dir != "/env/staging" || cfg.Staging.MaxBytes != 987654321 {
		t.Fatalf("env staging = %+v", cfg.Staging)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("env-configured staging should validate: %v", err)
	}
	// A malformed numeric override fails startup instead of silently
	// falling back.
	t.Setenv("KIWI_STAGING_MAX_BYTES", "not-a-number")
	if err := Default().ApplyEnv(); err == nil || !strings.Contains(err.Error(), "KIWI_STAGING_MAX_BYTES") {
		t.Fatalf("malformed KIWI_STAGING_MAX_BYTES = %v, want a parse error", err)
	}
}

func TestStagingFlagOverride(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("staging-dir", "", "")
	fs.String("staging-max-bytes", "", "")
	if err := fs.Parse([]string{"--staging-dir", "/flag/staging", "--staging-max-bytes", "4096"}); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatalf("OverrideFromFlags: %v", err)
	}
	if cfg.Staging.Dir != "/flag/staging" || cfg.Staging.MaxBytes != 4096 {
		t.Fatalf("flag staging = %+v", cfg.Staging)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("flag-configured staging should validate: %v", err)
	}
	// A malformed flag value is a startup error.
	fs = flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("staging-max-bytes", "", "")
	if err := fs.Parse([]string{"--staging-max-bytes", "huge"}); err != nil {
		t.Fatal(err)
	}
	if err := Default().OverrideFromFlags(fs); err == nil || !strings.Contains(err.Error(), "--staging-max-bytes") {
		t.Fatalf("malformed --staging-max-bytes = %v, want a parse error", err)
	}
}

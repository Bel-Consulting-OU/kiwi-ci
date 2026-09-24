package config

import (
	"flag"
	"strings"
	"testing"
)

// TestValidateRetentionAndScheduleBounds covers the schedule/retention bound
// checks and the external-URL validation call in Validate.
func TestValidateRetentionAndScheduleBounds(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"max schedules below -1", func(c *Config) { c.Server.MaxSchedules = -2 }, "max_schedules"},
		{"max retained runs below -1", func(c *Config) { c.Server.MaxRetainedRuns = -2 }, "max_retained_runs"},
		{"unparseable run retention", func(c *Config) { c.Server.RunRetention = "not-a-duration" }, "run_retention"},
		{"negative run retention", func(c *Config) { c.Server.RunRetention = "-1h" }, "run_retention"},
		{"non-loopback http external url", func(c *Config) { c.Server.ExternalURL = "http://ci.example.com" }, "external"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Database.URL = "postgres://db"
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// TestValidateForgeBaseURLRejectsInvalidScheme covers the base-URL loop error
// and the redaction path.
func TestValidateForgeBaseURLRejectsInvalidScheme(t *testing.T) {
	cfg := Default()
	cfg.Database.URL = "postgres://db"
	cfg.GitLab.BaseURL = "ftp://user:secret@host/path"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted an ftp forge base URL")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaked credentials: %v", err)
	}
}

// TestRedactURLBranches pins every redaction arm.
func TestRedactURLBranches(t *testing.T) {
	cases := map[string]string{
		"":                  "(empty)",
		"http://u:p@host/x": "http://host",
		"//host/x":          "host",
		"mailto:user":       "mailto",
		"bad url":           "(unparseable)",
	}
	for in, want := range cases {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestValidateExternalURLParseError covers the malformed-URL arm.
func TestValidateExternalURLParseError(t *testing.T) {
	if _, err := ValidateExternalURL("http://[::1", "dev"); err == nil {
		t.Fatal("malformed external URL accepted")
	}
	if _, err := ValidateExternalURL("", "dev"); err == nil {
		t.Fatal("empty external URL accepted")
	}
	if _, err := ValidateExternalURL("https:opaque", "dev"); err == nil {
		t.Fatal("opaque external URL accepted")
	}
}

// TestOverrideUntrustedCeilingParseErrors covers the four untrusted ceiling
// flag parse-error arms.
func TestOverrideUntrustedCeilingParseErrors(t *testing.T) {
	for _, name := range []string{
		"untrusted-cpu-ceiling", "untrusted-memory-ceiling",
		"untrusted-disk-ceiling", "untrusted-pids-ceiling",
	} {
		t.Run(name, func(t *testing.T) {
			fs := flag.NewFlagSet("bad", flag.ContinueOnError)
			fs.String(name, "", "")
			if err := fs.Parse([]string{"-" + name, "not-a-number"}); err != nil {
				t.Fatal(err)
			}
			if err := Default().OverrideFromFlags(fs); err == nil {
				t.Fatalf("OverrideFromFlags(%s=not-a-number) = nil, want a parse error", name)
			}
		})
	}
}

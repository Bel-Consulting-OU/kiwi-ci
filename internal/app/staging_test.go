package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// validProductionStaging returns a productionConfig that passes the static
// production contract with a configured staging bound; tests then break one
// field to prove each requirement.
func validProductionStaging() productionConfig {
	return productionConfig{
		Mode:            "production",
		DatabaseURL:     "postgres://kiwi:secret@db:5432/kiwi",
		RunnerToken:     "runner",
		AdminToken:      "admin",
		ExternalURL:     "https://ci.example.com",
		TLSCert:         "/etc/kiwi/server.crt",
		TLSKey:          "/etc/kiwi/server.key",
		StagingDir:      "/var/lib/kiwi/staging",
		StagingMaxBytes: 32 << 30,
	}
}

// TestValidateProductionConfigRequiresStagingBound: production mode must
// REFUSE to start when large-upload staging has no configured bound.
func TestValidateProductionConfigRequiresStagingBound(t *testing.T) {
	if err := validateProductionConfig(validProductionStaging()); err != nil {
		t.Fatalf("fully configured production config rejected: %v", err)
	}
	for name, mutate := range map[string]func(*productionConfig){
		"missing dir":    func(c *productionConfig) { c.StagingDir = "" },
		"blank dir":      func(c *productionConfig) { c.StagingDir = "   " },
		"missing budget": func(c *productionConfig) { c.StagingMaxBytes = 0 },
		"negative budget": func(c *productionConfig) {
			c.StagingMaxBytes = -1
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validProductionStaging()
			mutate(&cfg)
			err := validateProductionConfig(cfg)
			if err == nil {
				t.Fatal("production config without a staging bound was accepted")
			}
			if !strings.Contains(err.Error(), "staging") {
				t.Fatalf("refusal %q does not name the missing staging bound", err)
			}
		})
	}
	// Dev mode keeps the server's bounded default and needs no explicit
	// staging configuration.
	dev := validProductionStaging()
	dev.Mode = "dev"
	dev.StagingDir, dev.StagingMaxBytes = "", 0
	if err := validateProductionConfig(dev); err != nil {
		t.Fatalf("dev config with unconfigured staging rejected: %v", err)
	}
}

// TestServerProductionRefusesMissingStagingBoundAtStartup proves the
// refusal is wired into the real startup path: with no staging section (and
// no flags), Server() rejects production before any network work.
func TestServerProductionRefusesMissingStagingBoundAtStartup(t *testing.T) {
	err := Server(context.Background(), []string{
		"--mode", "production",
		"--database-url", "postgres://postgres@127.0.0.1:1/postgres?sslmode=disable",
		"--external-url", "https://ci.example.com",
		"--tls-cert", "c.pem", "--tls-key", "k.pem",
		"--admin-token", "admin", "--runner-token", "runner",
	})
	if err == nil {
		t.Fatal("production Server without a staging bound started")
	}
	if !strings.Contains(err.Error(), "staging") || !strings.Contains(err.Error(), "--staging-dir") {
		t.Fatalf("production refusal = %q, want it to name the staging flags", err)
	}
}

// TestServerProductionRefusesUnusableStagingDirectoryAtStartup: a configured
// but unusable bound fails startup when the budget is constructed, before the
// database connection is attempted.
func TestServerProductionRefusesUnusableStagingDirectoryAtStartup(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Server(context.Background(), []string{
		"--mode", "production",
		"--database-url", "postgres://postgres@127.0.0.1:1/postgres?sslmode=disable",
		"--external-url", "https://ci.example.com",
		"--tls-cert", "c.pem", "--tls-key", "k.pem",
		"--admin-token", "admin", "--runner-token", "runner",
		"--staging-dir", filepath.Join(file, "staging"), "--staging-max-bytes", "1048576",
	})
	if err == nil {
		t.Fatal("production Server with an unusable staging directory started")
	}
	if !strings.Contains(err.Error(), "staging") {
		t.Fatalf("unusable staging refusal = %q, want a staging error", err)
	}
}

// TestBuildStagingBudgetPrunesAndRefusesUnusable: an unconfigured section
// leaves the server default in place, a configured one is constructed and
// startup-pruned, and an unusable configured bound fails startup.
func TestBuildStagingBudgetPrunesAndRefusesUnusable(t *testing.T) {
	b, pruned, err := buildStagingBudget(context.Background(), config.StagingConfig{})
	if err != nil || b != nil || pruned != 0 {
		t.Fatalf("unconfigured budget = (%v, %d, %v), want (nil, 0, nil)", b, pruned, err)
	}

	dir := t.TempDir()
	abandoned := filepath.Join(dir, staging.FilePrefix+"crash-leftover")
	if err := os.WriteFile(abandoned, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(abandoned, old, old); err != nil {
		t.Fatal(err)
	}
	b, pruned, err = buildStagingBudget(context.Background(), config.StagingConfig{Dir: dir, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("buildStagingBudget: %v", err)
	}
	if b == nil || b.Dir() != dir || b.MaxBytes() != 1<<20 {
		t.Fatalf("budget = %+v", b)
	}
	if pruned != 1 {
		t.Fatalf("startup prune removed %d files, want 1", pruned)
	}
	if _, err := os.Stat(abandoned); !os.IsNotExist(err) {
		t.Fatalf("abandoned spool file survived startup prune: %v", err)
	}

	// An unusable bound (the parent is a regular file) must fail startup.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildStagingBudget(context.Background(), config.StagingConfig{Dir: filepath.Join(file, "staging"), MaxBytes: 1 << 20}); err == nil {
		t.Fatal("unusable configured staging directory was accepted")
	} else if !strings.Contains(err.Error(), "staging") {
		t.Fatalf("unusable staging error %q does not name staging", err)
	}
	// A partial configuration is caught by config.Validate in the real
	// startup path; the helper itself must not silently accept it either.
	if _, _, err := buildStagingBudget(context.Background(), config.StagingConfig{Dir: dir}); err == nil {
		t.Fatal("partial staging configuration (dir without max_bytes) was accepted")
	}
}

package config

import (
	"flag"
	"math"
	"os"
	"strings"
	"testing"
)

// TestUntrustedCeilingDefaults pins the built-in ceiling values that the
// server has always applied to untrusted jobs: changing them here changes
// what every deployment without an explicit override enforces.
func TestUntrustedCeilingDefaults(t *testing.T) {
	q := Default().Quota
	if q.UntrustedCPUCeiling != 2 || q.UntrustedMemoryCeiling != 4<<30 ||
		q.UntrustedDiskCeiling != 10<<30 || q.UntrustedPIDsCeiling != 256 {
		t.Fatalf("ceiling defaults = %v/%v/%v/%v, want 2/4GiB/10GiB/256",
			q.UntrustedCPUCeiling, q.UntrustedMemoryCeiling, q.UntrustedDiskCeiling, q.UntrustedPIDsCeiling)
	}
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
}

// TestUntrustedCeilingTOMLRoundTrip loads the four quota keys from kiwi.toml
// and proves the values survive the file parse exactly, while absent keys
// keep the built-in defaults (the documented bottom of the precedence
// chain).
func TestUntrustedCeilingTOMLRoundTrip(t *testing.T) {
	p := writeTemp(t, `
[quota]
untrusted_cpu_ceiling = 1.5
untrusted_memory_ceiling = 8589934592
untrusted_disk_ceiling = 21474836480
untrusted_pids_ceiling = 1024
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	q := cfg.Quota
	if q.UntrustedCPUCeiling != 1.5 || q.UntrustedMemoryCeiling != 8<<30 ||
		q.UntrustedDiskCeiling != 20<<30 || q.UntrustedPIDsCeiling != 1024 {
		t.Fatalf("loaded ceilings = %v/%v/%v/%v, want 1.5/8GiB/20GiB/1024",
			q.UntrustedCPUCeiling, q.UntrustedMemoryCeiling, q.UntrustedDiskCeiling, q.UntrustedPIDsCeiling)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loaded config rejected: %v", err)
	}

	// Round-trip the effective config through a flag set exactly as the
	// server does: explicitly set flags win, unset flags keep the file.
	fs := flag.NewFlagSet("ceilings", flag.ContinueOnError)
	for _, name := range []string{"untrusted-cpu-ceiling", "untrusted-memory-ceiling", "untrusted-disk-ceiling", "untrusted-pids-ceiling"} {
		fs.String(name, "", "")
	}
	if err := fs.Parse([]string{"-untrusted-memory-ceiling", "17179869184", "-untrusted-pids-ceiling", "2048"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatalf("OverrideFromFlags: %v", err)
	}
	q = cfg.Quota
	if q.UntrustedCPUCeiling != 1.5 || q.UntrustedDiskCeiling != 20<<30 {
		t.Fatalf("unset flags clobbered file values: %+v", q)
	}
	if q.UntrustedMemoryCeiling != 16<<30 || q.UntrustedPIDsCeiling != 2048 {
		t.Fatalf("flags did not win: %+v", q)
	}
}

// TestUntrustedCeilingAbsentKeysKeepDefaults proves a quota section that
// only configures the classic keys leaves the ceiling defaults intact.
func TestUntrustedCeilingAbsentKeysKeepDefaults(t *testing.T) {
	p := writeTemp(t, `
[quota]
repo_concurrency = 4
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Quota.UntrustedCPUCeiling != 2 || cfg.Quota.UntrustedMemoryCeiling != 4<<30 ||
		cfg.Quota.UntrustedDiskCeiling != 10<<30 || cfg.Quota.UntrustedPIDsCeiling != 256 {
		t.Fatalf("absent ceiling keys lost the defaults: %+v", cfg.Quota)
	}
}

// TestUntrustedCeilingEnvOverrideAndPrecedence pins the KIWI_QUOTA_* env
// names and their position in the precedence chain: env beats the file, and
// an explicitly set flag beats env.
func TestUntrustedCeilingEnvOverrideAndPrecedence(t *testing.T) {
	env := map[string]string{
		"KIWI_QUOTA_UNTRUSTED_CPU_CEILING":    "3",
		"KIWI_QUOTA_UNTRUSTED_MEMORY_CEILING": "17179869184",
		"KIWI_QUOTA_UNTRUSTED_DISK_CEILING":   "32212254720",
		"KIWI_QUOTA_UNTRUSTED_PIDS_CEILING":   "512",
	}
	for k, v := range env {
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		for k := range env {
			os.Unsetenv(k)
		}
	})
	p := writeTemp(t, "[quota]\nuntrusted_cpu_ceiling = 1.0\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	q := cfg.Quota
	if q.UntrustedCPUCeiling != 3 || q.UntrustedMemoryCeiling != 16<<30 ||
		q.UntrustedDiskCeiling != 30<<30 || q.UntrustedPIDsCeiling != 512 {
		t.Fatalf("env ceilings = %+v", q)
	}
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	_ = fs.String("untrusted-cpu-ceiling", "", "")
	if err := fs.Parse([]string{"-untrusted-cpu-ceiling", "1.25"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatal(err)
	}
	if cfg.Quota.UntrustedCPUCeiling != 1.25 {
		t.Fatalf("flag did not beat env: %v", cfg.Quota.UntrustedCPUCeiling)
	}
}

// TestUntrustedCeilingValidation rejects ceiling values that cannot be
// enforced honestly (negative, NaN/Inf, overflowing byte/pid counts) while
// accepting zero (dimension disabled).
func TestUntrustedCeilingValidation(t *testing.T) {
	bad := []struct {
		name   string
		mutate func(*QuotaConfig)
		want   string
	}{
		{"negative cpu", func(q *QuotaConfig) { q.UntrustedCPUCeiling = -1 }, "quota.untrusted_cpu_ceiling"},
		{"negative memory", func(q *QuotaConfig) { q.UntrustedMemoryCeiling = -1 }, "quota.untrusted_memory_ceiling"},
		{"negative disk", func(q *QuotaConfig) { q.UntrustedDiskCeiling = -1 }, "quota.untrusted_disk_ceiling"},
		{"negative pids", func(q *QuotaConfig) { q.UntrustedPIDsCeiling = -1 }, "quota.untrusted_pids_ceiling"},
		{"nan cpu", func(q *QuotaConfig) { q.UntrustedCPUCeiling = math.NaN() }, "finite"},
		{"inf memory", func(q *QuotaConfig) { q.UntrustedMemoryCeiling = math.Inf(1) }, "finite"},
		{"memory overflows int64", func(q *QuotaConfig) { q.UntrustedMemoryCeiling = math.MaxInt64 }, "quota.untrusted_memory_ceiling"},
		{"disk overflows int64", func(q *QuotaConfig) { q.UntrustedDiskCeiling = float64(math.MaxInt64) }, "quota.untrusted_disk_ceiling"},
		{"pids overflows int", func(q *QuotaConfig) { q.UntrustedPIDsCeiling = math.MaxInt32 + 1 }, "quota.untrusted_pids_ceiling"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg.Quota)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted the config, want an error naming %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
	zero := Default()
	zero.Quota = QuotaConfig{}
	if err := zero.Validate(); err != nil {
		t.Fatalf("all-zero ceilings must be legal (they disable every dimension): %v", err)
	}
}

// TestUntrustedCeilingEnvParseErrors proves a malformed override fails
// startup instead of silently keeping a different ceiling.
func TestUntrustedCeilingEnvParseErrors(t *testing.T) {
	for _, name := range []string{
		"KIWI_QUOTA_UNTRUSTED_CPU_CEILING",
		"KIWI_QUOTA_UNTRUSTED_MEMORY_CEILING",
		"KIWI_QUOTA_UNTRUSTED_DISK_CEILING",
		"KIWI_QUOTA_UNTRUSTED_PIDS_CEILING",
	} {
		t.Run(name, func(t *testing.T) {
			os.Setenv(name, "lots")
			t.Cleanup(func() { os.Unsetenv(name) })
			err := Default().ApplyEnv()
			if err == nil {
				t.Fatalf("%s accepted a non-numeric value", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("error %q does not name %s", err, name)
			}
		})
	}
}

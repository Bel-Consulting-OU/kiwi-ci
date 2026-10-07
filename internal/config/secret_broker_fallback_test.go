package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSecretBrokerConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kiwi.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSecretBrokerFallbackOnLoad pins the TOML list parsing: an absent key
// stays nil (the default policy applies), an explicit list is preserved, an
// empty list means no class may fall through, and malformed lists are
// refused at load time.
func TestSecretBrokerFallbackOnLoad(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		cfg, err := Load(writeSecretBrokerConfig(t, `
[secret_broker]
broker = "vault"
vault_addr = "https://vault.example"
fallback_on = ["not_found", "unavailable"]
`))
		if err != nil {
			t.Fatal(err)
		}
		got := cfg.SecretBroker.FallbackOn
		if len(got) != 2 || got[0] != "not_found" || got[1] != "unavailable" {
			t.Fatalf("fallback_on = %v", got)
		}
	})

	t.Run("absent", func(t *testing.T) {
		cfg, err := Load(writeSecretBrokerConfig(t, `
[secret_broker]
broker = "vault"
vault_addr = "https://vault.example"
`))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SecretBroker.FallbackOn != nil {
			t.Fatalf("absent fallback_on = %v, want nil (default policy)", cfg.SecretBroker.FallbackOn)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		cfg, err := Load(writeSecretBrokerConfig(t, `
[secret_broker]
broker = "vault"
vault_addr = "https://vault.example"
fallback_on = []
`))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SecretBroker.FallbackOn == nil || len(cfg.SecretBroker.FallbackOn) != 0 {
			t.Fatalf("empty fallback_on = %#v, want a non-nil empty list", cfg.SecretBroker.FallbackOn)
		}
	})

	t.Run("literal strings and trailing comma", func(t *testing.T) {
		cfg, err := Load(writeSecretBrokerConfig(t, `
[secret_broker]
broker = "vault"
vault_addr = "https://vault.example"
fallback_on = ['not_found',]
`))
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.SecretBroker.FallbackOn) != 1 || cfg.SecretBroker.FallbackOn[0] != "not_found" {
			t.Fatalf("fallback_on = %v", cfg.SecretBroker.FallbackOn)
		}
	})

	for label, raw := range map[string]string{
		"unterminated":  `fallback_on = ["not_found"`,
		"unquoted":      `fallback_on = [not_found]`,
		"non-string":    `fallback_on = [1]`,
		"empty element": `fallback_on = ["not_found",, "unavailable"]`,
	} {
		t.Run("malformed "+label, func(t *testing.T) {
			_, err := Load(writeSecretBrokerConfig(t, `
[secret_broker]
broker = "vault"
vault_addr = "https://vault.example"
`+raw))
			if err == nil {
				t.Fatalf("malformed fallback_on %q accepted", raw)
			}
		})
	}
}

// TestSecretBrokerFallbackOnValidation pins the fail-closed policy contract
// in BOTH modes: only not_found and unavailable are accepted; authorization,
// policy and malformed-response classes (and unknowns) are startup errors.
func TestSecretBrokerFallbackOnValidation(t *testing.T) {
	cases := []struct {
		label   string
		entries []string
		wantErr bool
	}{
		{"absent", nil, false},
		{"not_found", []string{"not_found"}, false},
		{"unavailable", []string{"unavailable"}, false},
		{"both", []string{"not_found", "unavailable"}, false},
		{"empty", []string{}, false},
		{"forbidden", []string{"forbidden"}, true},
		{"unauthorized", []string{"unauthorized"}, true},
		{"malformed", []string{"malformed"}, true},
		{"unknown", []string{"whatever"}, true},
		{"mixed valid and forbidden", []string{"not_found", "forbidden"}, true},
		{"blank", []string{"  "}, true},
	}
	for _, mode := range []string{"dev", "production"} {
		t.Run(mode, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.label, func(t *testing.T) {
					cfg := Default()
					cfg.Server.Mode = mode
					if mode == "production" {
						cfg.Server.ExternalURL = "https://ci.example.com"
					}
					cfg.SecretBroker.Broker = "vault"
					cfg.SecretBroker.VaultAddr = "https://vault.example"
					cfg.SecretBroker.FallbackOn = tc.entries
					err := cfg.Validate()
					if tc.wantErr {
						if err == nil {
							t.Fatalf("fallback_on %v accepted in %s mode", tc.entries, mode)
						}
						if !strings.Contains(err.Error(), "fallback_on") {
							t.Fatalf("error does not name fallback_on: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatalf("fallback_on %v rejected in %s mode: %v", tc.entries, mode, err)
					}
				})
			}
		})
	}

	t.Run("rejected even with no broker configured", func(t *testing.T) {
		cfg := Default()
		cfg.SecretBroker.Broker = ""
		cfg.SecretBroker.FallbackOn = []string{"forbidden"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("forbidden fallback class accepted with no broker configured")
		}
	})
}

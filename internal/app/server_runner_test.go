package app

import "testing"

func TestValidateProductionConfig(t *testing.T) {
	valid := productionConfig{
		Mode:        "production",
		DatabaseURL: "postgres://db",
		RunnerToken: "runner",
		AdminToken:  "admin",
		ExternalURL: "https://ci.example.com",
		TLSCert:     "cert.pem",
		TLSKey:      "key.pem",
	}
	if err := validateProductionConfig(valid); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*productionConfig)
		want   string
	}{
		{"missing database url", func(c *productionConfig) { c.DatabaseURL = "" }, "--database-url"},
		{"shared tokens", func(c *productionConfig) { c.AdminToken = c.RunnerToken }, "--allow-shared-token"},
		{"empty admin token", func(c *productionConfig) { c.AdminToken = "" }, "--allow-shared-token"},
		{"missing external url", func(c *productionConfig) { c.ExternalURL = "" }, "--external-url"},
		{"missing tls cert", func(c *productionConfig) { c.TLSCert = "" }, "--tls-cert"},
		{"missing tls key", func(c *productionConfig) { c.TLSKey = "" }, "--tls-key"},
		{"unknown mode", func(c *productionConfig) { c.Mode = "staging" }, "--mode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := valid
			c.mutate(&cfg)
			err := validateProductionConfig(cfg)
			if err == nil {
				t.Fatalf("config accepted, want error mentioning %s", c.want)
			}
			if !containsStr(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}

	// Shared credentials are acceptable with the explicit acknowledgment.
	shared := valid
	shared.AdminToken = shared.RunnerToken
	shared.AllowSharedToken = true
	if err := validateProductionConfig(shared); err != nil {
		t.Errorf("--allow-shared-token config rejected: %v", err)
	}

	// Dev mode has no requirements beyond the mode value.
	if err := validateProductionConfig(productionConfig{Mode: "dev"}); err != nil {
		t.Errorf("empty dev config rejected: %v", err)
	}
	if err := validateProductionConfig(productionConfig{}); err != nil {
		t.Errorf("empty mode (defaults to dev) rejected: %v", err)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

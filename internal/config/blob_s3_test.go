package config

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
)

// TestValidateS3Coherence pins the S3 endpoint/bucket/style policy: the
// structural rules are exactly the transport's shared validator
// (blob.ValidateS3Config), and production layers the plaintext refusal on top
// with an explicit, documented override.
func TestValidateS3Coherence(t *testing.T) {
	base := func() *Config {
		cfg := Default()
		cfg.Server.ExternalURL = "https://ci.example.com"
		cfg.Blob.Backend = "s3"
		cfg.Blob.S3Endpoint = "https://s3.example.com"
		cfg.Blob.S3Bucket = "kiwi-artifacts"
		cfg.Blob.S3Region = "eu-central-1"
		return cfg
	}
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantOK  bool
		wantMsg string
	}{
		{"https default accepted", func(*Config) {}, true, ""},
		{"dev plaintext accepted", func(c *Config) { c.Blob.S3Endpoint = "http://localhost:9000" }, true, ""},
		{"production plaintext refused", func(c *Config) {
			c.Server.Mode = "production"
			c.Blob.S3Endpoint = "http://minio.internal:9000"
		}, false, "s3_allow_plaintext"},
		{"production padded plaintext refused", func(c *Config) {
			c.Server.Mode = "production"
			c.Blob.S3Endpoint = "  http://minio.internal:9000  "
		}, false, "s3_allow_plaintext"},
		{"production plaintext override", func(c *Config) {
			c.Server.Mode = "production"
			c.Blob.S3Endpoint = "http://minio.internal:9000"
			c.Blob.S3AllowPlaintext = true
		}, true, ""},
		{"path-style IP accepted", func(c *Config) {
			c.Blob.S3Endpoint = "http://127.0.0.1:9000"
			c.Blob.S3PathStyle = true
		}, true, ""},
		{"virtual-host IP refused", func(c *Config) { c.Blob.S3Endpoint = "http://127.0.0.1:9000" }, false, "s3_path_style"},
		{"virtual-host path prefix refused", func(c *Config) { c.Blob.S3Endpoint = "https://gw.example/s3" }, false, "s3_path_style"},
		{"path-style prefix accepted", func(c *Config) {
			c.Blob.S3Endpoint = "https://gw.example/s3"
			c.Blob.S3PathStyle = true
		}, true, ""},
		{"host-less endpoint refused", func(c *Config) { c.Blob.S3Endpoint = "https://" }, false, "host"},
		{"scheme-less endpoint refused", func(c *Config) { c.Blob.S3Endpoint = "s3.example.com" }, false, "http://"},
		{"bucket slash refused", func(c *Config) { c.Blob.S3Bucket = "a/b" }, false, "bucket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantOK != (err == nil) {
				t.Fatalf("Validate() err=%v, wantOK=%v", err, tc.wantOK)
			}
			if err != nil && tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error %q does not mention %q", err, tc.wantMsg)
			}
		})
	}

	// The structural acceptance set is the transport validator's: for every
	// non-plaintext-production case the two agree exactly.
	for _, tc := range []struct {
		endpoint string
		bucket   string
		path     bool
	}{
		{"https://s3.example.com", "kiwi-artifacts", false},
		{"http://127.0.0.1:9000", "kiwi-artifacts", false},
		{"http://127.0.0.1:9000", "kiwi-artifacts", true},
		{"https://gw.example/s3", "kiwi-artifacts", false},
		{"https://gw.example/s3", "kiwi-artifacts", true},
		{"https://", "kiwi-artifacts", true},
	} {
		want := blob.ValidateS3Config(tc.endpoint, tc.bucket, tc.path)
		cfg := base()
		cfg.Blob.S3Endpoint = tc.endpoint
		cfg.Blob.S3Bucket = tc.bucket
		cfg.Blob.S3PathStyle = tc.path
		got := cfg.Validate()
		if (got == nil) != (want == nil) {
			t.Errorf("config.Validate(%q, %q, path=%v) = %v, transport validator = %v", tc.endpoint, tc.bucket, tc.path, got, want)
		}
	}
}

package config

import (
	"strings"
	"testing"
)

// HA blob topology is a production contract: node-local fs CAS under shared
// PostgreSQL metadata loses artifacts across replicas. Production must
// refuse that topology until the operator names single_replica or shared fs.

func baseProdConfig() *Config {
	cfg := Default()
	cfg.Server.Mode = "production"
	cfg.Server.ExternalURL = "https://ci.example.com"
	cfg.Quota.TeamQueueDepth = 100
	// The dangerous topology is PostgreSQL metadata + node-local fs CAS.
	cfg.Database.URL = "postgres://user@localhost/kiwi"
	cfg.Blob.Backend = "fs"
	cfg.Blob.Path = "/var/lib/kiwi/blobs"
	return cfg
}

func TestHARefusesUnacknowledgedLocalBlobFS(t *testing.T) {
	c := baseProdConfig()
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "blob.shared") {
		t.Fatalf("unacknowledged fs blob in production = %v, want blob.shared/single_replica refusal", err)
	}

	// Single-replica acknowledgement admits local fs.
	c = baseProdConfig()
	c.Server.SingleReplica = true
	if err := c.Validate(); err != nil {
		t.Fatalf("single_replica + fs = %v, want success", err)
	}

	// Shared-fs acknowledgement admits multi-replica fs.
	c = baseProdConfig()
	c.Blob.Shared = true
	if err := c.Validate(); err != nil {
		t.Fatalf("shared fs = %v, want success", err)
	}

	// Both set is contradictory.
	c = baseProdConfig()
	c.Server.SingleReplica = true
	c.Blob.Shared = true
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("both acknowledgements = %v, want mutually exclusive", err)
	}

	// s3 needs neither acknowledgement.
	c = baseProdConfig()
	c.Blob = BlobConfig{
		Backend:     "s3",
		S3Endpoint:  "https://s3.example.com",
		S3Bucket:    "kiwi-blobs",
		S3Region:    "eu-west-1",
		S3PathStyle: true,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("s3 without acknowledgement = %v, want success", err)
	}

	// Production without PostgreSQL is a single-process store: no
	// multi-replica CAS hazard, so no acknowledgement is demanded.
	c = baseProdConfig()
	c.Database.URL = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("production fs without postgres = %v, want success", err)
	}
}

func TestHABlobTopologyAllowsDevWithoutAcknowledgement(t *testing.T) {
	c := baseProdConfig()
	c.Server.Mode = "dev"
	c.Server.ExternalURL = ""
	c.Database.URL = ""
	c.Staging = StagingConfig{}
	if err := c.Validate(); err != nil {
		t.Fatalf("dev + local fs = %v, want success (no HA contract in dev)", err)
	}
}

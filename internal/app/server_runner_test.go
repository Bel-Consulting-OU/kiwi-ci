package app

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// Compile-time adoption checks: once *server.Server implements the drain
// and blob seams, the --drain-on-sigterm flag and the blob backend wiring
// activate automatically. A signature change on the server side breaks
// these assertions, surfacing the drift immediately.
var (
	_ drainableServer = (*server.Server)(nil)
	_ blobStoreSetter = (*server.Server)(nil)
)

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

// fakeDrainServer is a drainableServer test double.
type fakeDrainServer struct {
	active  atomic.Int64
	drained bool
	reason  string
}

func (f *fakeDrainServer) BeginDrain(reason string) { f.drained = true; f.reason = reason }
func (f *fakeDrainServer) ActiveJobs() int          { return int(f.active.Load()) }
func (f *fakeDrainServer) setActive(n int)          { f.active.Store(int64(n)) }

func TestWaitForDrainIdle(t *testing.T) {
	s := &fakeDrainServer{}
	if !waitForDrain(s, 2*time.Second) {
		t.Fatal("idle server must drain immediately")
	}
}

func TestWaitForDrainCompletesWhenJobsFinish(t *testing.T) {
	s := &fakeDrainServer{}
	s.setActive(2)
	go func() {
		time.Sleep(150 * time.Millisecond)
		s.setActive(0)
	}()
	if !waitForDrain(s, 2*time.Second) {
		t.Fatal("drain must complete once active jobs reach zero")
	}
}

func TestWaitForDrainTimesOut(t *testing.T) {
	s := &fakeDrainServer{}
	s.setActive(1)
	if waitForDrain(s, 100*time.Millisecond) {
		t.Fatal("drain with active jobs must time out")
	}
}

func TestBuildBlobStoreS3(t *testing.T) {
	cfg := config.BlobConfig{
		Backend:     "s3",
		S3Endpoint:  "http://s3.local",
		S3Bucket:    "kiwi-artifacts",
		S3Region:    "us-east-1",
		S3AccessKey: "ak",
		S3SecretKey: "sk",
	}
	store := buildBlobStore(cfg, "")
	s3, ok := store.(*blob.S3)
	if !ok {
		t.Fatalf("s3 backend produced %T, want *blob.S3", store)
	}
	if s3.Bucket != "kiwi-artifacts" || s3.Region != "us-east-1" || s3.Endpoint != "http://s3.local" {
		t.Fatalf("s3 config not carried: %+v", s3)
	}
}

func TestBuildBlobStoreFSFromDataDir(t *testing.T) {
	store := buildBlobStore(config.BlobConfig{Backend: "fs"}, "/var/lib/kiwi")
	fs, ok := store.(*blob.FS)
	if !ok {
		t.Fatalf("fs backend produced %T, want *blob.FS", store)
	}
	if fs.Root != "/var/lib/kiwi/blobs" {
		t.Fatalf("fs root = %q, want /var/lib/kiwi/blobs", fs.Root)
	}
}

func TestBuildBlobStoreFSPathPrecedence(t *testing.T) {
	store := buildBlobStore(config.BlobConfig{Backend: "fs", Path: "/custom/blobs"}, "/var/lib/kiwi")
	fs := store.(*blob.FS)
	if fs.Root != "/custom/blobs" {
		t.Fatalf("fs root = %q, want explicit blob.path", fs.Root)
	}
}

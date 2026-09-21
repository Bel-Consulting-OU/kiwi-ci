package app

import (
	"crypto/tls"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
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

// tlsConfigBuilder is the compile-checkable adoption seam for the server's
// listener TLS configuration: the app wires Server.TLSConfig into the
// http.Server so runner client certificates are verified at the handshake.
type tlsConfigBuilder interface {
	TLSConfig(certFile, keyFile string) (*tls.Config, error)
}

var _ tlsConfigBuilder = (*server.Server)(nil)

// clusterKeyAdopter is the compile-checkable adoption seam for the server's
// shared cluster key store (NewPersistentWithCluster).
var _ server.ClusterKeyStore = (*server.FSClusterKeyStore)(nil)

func TestApplyRunnerTLSConfig(t *testing.T) {
	ca, err := runnerpki.NewCA("test-runner-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("runner CA populates pool and requirement", func(t *testing.T) {
		s := server.New("runner-token")
		s.RunnerCA = ca
		applyRunnerTLSConfig(s, true)
		if s.RunnerClientCAPool == nil {
			t.Fatal("RunnerClientCAPool not populated")
		}
		if !s.RequireRunnerClientCerts {
			t.Fatal("RequireRunnerClientCerts = false, want true")
		}
	})
	t.Run("optional client certs", func(t *testing.T) {
		s := server.New("runner-token")
		s.RunnerCA = ca
		applyRunnerTLSConfig(s, false)
		if s.RunnerClientCAPool == nil || s.RequireRunnerClientCerts {
			t.Fatalf("verify-if-given not honored: pool=%v require=%t", s.RunnerClientCAPool, s.RequireRunnerClientCerts)
		}
	})
	t.Run("no runner CA leaves bearer mode untouched", func(t *testing.T) {
		s := server.New("runner-token")
		applyRunnerTLSConfig(s, true)
		if s.RunnerClientCAPool != nil || s.RequireRunnerClientCerts {
			t.Fatalf("bearer-token server got runner cert settings: pool=%v require=%t", s.RunnerClientCAPool, s.RequireRunnerClientCerts)
		}
	})
}

func TestValidateProductionConfig(t *testing.T) {
	valid := productionConfig{
		Mode:                   "production",
		DatabaseURL:            "postgres://db",
		RunnerToken:            "runner",
		AdminToken:             "admin",
		ExternalURL:            "https://ci.example.com",
		TLSCert:                "cert.pem",
		TLSKey:                 "key.pem",
		RunnerMTLSEnforced:     true,
		RunnerTokensConfigured: false,
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
		{"shared token without per-runner credentials", func(c *productionConfig) { c.RunnerMTLSEnforced = false }, "shared runner token is dev-only"},
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

func TestValidateProductionRunnerCredentialMatrix(t *testing.T) {
	base := productionConfig{
		Mode:        "production",
		DatabaseURL: "postgres://db",
		AdminToken:  "admin",
		ExternalURL: "https://ci.example.com",
		TLSCert:     "cert.pem",
		TLSKey:      "key.pem",
	}
	// Runner token + enforced mTLS: fine.
	withMTLS := base
	withMTLS.RunnerToken = "runner"
	withMTLS.RunnerMTLSEnforced = true
	if err := validateProductionConfig(withMTLS); err != nil {
		t.Fatalf("runner token + enforced mTLS rejected: %v", err)
	}
	// Admin token + enforced runner mTLS (no bearer): fine.
	mtlsOnly := base
	mtlsOnly.RunnerMTLSEnforced = true
	if err := validateProductionConfig(mtlsOnly); err != nil {
		t.Fatalf("admin token + enforced runner mTLS rejected: %v", err)
	}
	// Admin token + per-runner bearer tokens: fine without mTLS.
	withTokens := base
	withTokens.RunnerTokensConfigured = true
	if err := validateProductionConfig(withTokens); err != nil {
		t.Fatalf("admin token + per-runner tokens rejected: %v", err)
	}
	// Admin token + shared runner token + no mTLS + no per-runner tokens:
	// the shared token is dev-only and production refuses to start.
	shared := base
	shared.RunnerToken = "runner"
	if err := validateProductionConfig(shared); err == nil || !containsStr(err.Error(), "shared runner token is dev-only") {
		t.Fatalf("shared runner token without per-runner credentials: %v", err)
	}
	// Admin token + no runner credential at all: fail closed at startup.
	if err := validateProductionConfig(base); err == nil {
		t.Fatal("admin token without runner credential accepted, want startup error")
	}
	// Runner token without an admin token stays subject to the existing
	// shared-credential rule, not the runner-credential rule.
	noAdmin := base
	noAdmin.AdminToken = ""
	noAdmin.RunnerToken = "runner"
	noAdmin.RunnerTokensConfigured = true
	if err := validateProductionConfig(noAdmin); err == nil || !containsStr(err.Error(), "--allow-shared-token") {
		t.Fatalf("runner-only production config: %v", err)
	}
	// Empty admin + mTLS enforced still hits the admin credential rule.
	noAdminMTLS := base
	noAdminMTLS.AdminToken = ""
	noAdminMTLS.RunnerMTLSEnforced = true
	if err := validateProductionConfig(noAdminMTLS); err == nil || !containsStr(err.Error(), "--allow-shared-token") {
		t.Fatalf("mTLS-only production config: %v", err)
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
		S3Endpoint:  "http://127.0.0.1:9000",
		S3Bucket:    "kiwi-artifacts",
		S3Region:    "us-east-1",
		S3PathStyle: true,
		S3AccessKey: "ak",
		S3SecretKey: "sk",
	}
	store := buildBlobStore(cfg, "")
	s3, ok := store.(*blob.S3)
	if !ok {
		t.Fatalf("s3 backend produced %T, want *blob.S3", store)
	}
	if s3.Bucket != "kiwi-artifacts" || s3.Region != "us-east-1" || s3.Endpoint != "http://127.0.0.1:9000" || !s3.PathStyle {
		t.Fatalf("s3 config not carried: %+v", s3)
	}
	if err := s3.Validate(); err != nil {
		t.Fatalf("wired s3 store invalid: %v", err)
	}
}

func TestBuildBlobStoreFSFromDataDir(t *testing.T) {
	store := buildBlobStore(config.BlobConfig{Backend: "fs"}, "/var/lib/kiwi")
	fs, ok := store.(*blob.FS)
	if !ok {
		t.Fatalf("fs backend produced %T, want *blob.FS", store)
	}
	want := filepath.FromSlash("/var/lib/kiwi/blobs")
	if fs.Root != want {
		t.Fatalf("fs root = %q, want %q", fs.Root, want)
	}
}

func TestBuildBlobStoreFSPathPrecedence(t *testing.T) {
	store := buildBlobStore(config.BlobConfig{Backend: "fs", Path: "/custom/blobs"}, "/var/lib/kiwi")
	fs := store.(*blob.FS)
	if fs.Root != "/custom/blobs" {
		t.Fatalf("fs root = %q, want explicit blob.path", fs.Root)
	}
}

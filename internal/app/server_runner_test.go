package app

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
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

	// --runner-token alone is NOT rejected statically: the per-runner
	// decision is post-DB, because per-runner bearer credentials may
	// already be provisioned in runner_bearer_tokens (D3-D).
	runnerTokenOnly := valid
	runnerTokenOnly.AdminToken = "admin"
	if err := validateProductionConfig(runnerTokenOnly); err != nil {
		t.Fatalf("production config with only --runner-token rejected statically: %v", err)
	}
	// A production config with no runner credential at all is likewise a
	// post-DB decision (the shared token is disabled, but DB rows decide).
	noRunnerCredential := valid
	noRunnerCredential.RunnerToken = ""
	if err := validateProductionConfig(noRunnerCredential); err != nil {
		t.Fatalf("production config without a runner credential rejected statically: %v", err)
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

// runnerTokenStoreFake implements storage.RunnerTokenStore for the post-DB
// production credential check; the embedded Store is never called.
type runnerTokenStoreFake struct {
	storage.Store
	has bool
	err error
}

func (f runnerTokenStoreFake) UpsertRunnerToken(context.Context, string, string) error { return nil }
func (f runnerTokenStoreFake) RunnerIDForToken(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (f runnerTokenStoreFake) HasRunnerTokens(context.Context) (bool, error) { return f.has, f.err }

func TestValidateProductionRunnerCredentials(t *testing.T) {
	ctx := context.Background()
	// Enforced runner mTLS needs no bearer credentials and never probes the
	// store (a broken store must not fail an mTLS-only deployment).
	if err := validateProductionRunnerCredentials(ctx, runnerTokenStoreFake{err: errors.New("db down")}, true, nil); err != nil {
		t.Fatalf("enforced mTLS rejected: %v", err)
	}
	// Per-runner bearer credentials from --runner-tokens-file pass before
	// they are provisioned.
	if err := validateProductionRunnerCredentials(ctx, runnerTokenStoreFake{}, false, map[string]string{"runner-1": "digest"}); err != nil {
		t.Fatalf("file per-runner tokens rejected: %v", err)
	}
	// Per-runner rows already provisioned in runner_bearer_tokens pass.
	if err := validateProductionRunnerCredentials(ctx, runnerTokenStoreFake{has: true}, false, nil); err != nil {
		t.Fatalf("provisioned per-runner tokens rejected: %v", err)
	}
	// Neither mechanism: fail closed post-DB with a message naming the
	// supported mechanisms and the shared token's dev-only status.
	err := validateProductionRunnerCredentials(ctx, runnerTokenStoreFake{}, false, nil)
	if err == nil || !containsStr(err.Error(), "production requires runner mTLS or per-runner credentials") {
		t.Fatalf("no runner mechanism = %v", err)
	}
	if !containsStr(err.Error(), "dev/bootstrap-only") {
		t.Fatalf("error does not state the shared token policy: %v", err)
	}
	// A store error while probing fails closed.
	err = validateProductionRunnerCredentials(ctx, runnerTokenStoreFake{err: errors.New("db down")}, false, nil)
	if err == nil || !containsStr(err.Error(), "check per-runner credentials") {
		t.Fatalf("store error = %v, want a wrapped probe failure", err)
	}
	// A store without the RunnerTokenStore surface can never prove
	// per-runner credentials exist: refused.
	err = validateProductionRunnerCredentials(ctx, storeOnly{}, false, nil)
	if err == nil {
		t.Fatal("store without the token surface accepted")
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

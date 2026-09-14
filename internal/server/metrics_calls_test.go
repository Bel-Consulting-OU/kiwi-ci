package server

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

func TestMetricsCallSitesIncrement(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Metrics.Reset()

	// Artifact upload records artifact bytes and CAS latency.
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload-data", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	if v := counterValue(s, "kiwi_artifact_bytes_total"); v != 12 {
		t.Fatalf("artifact bytes = %v, want 12", v)
	}
	// Secret delivery counter via a trusted leased job with a broker.
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	j.Trusted = true
	j.DeclaredSecrets = []string{"TOKEN"}
	s.jobs[task.Job.ID] = j
	s.mu.Unlock()
	s.SecretBroker = staticBroker{"TOKEN": "s3cret"}
	secretBody := `{"runner_id":` + jsonString(runnerID) + `,"lease_token":` + jsonString(task.LeaseToken) + `,"lease_generation":` + itoa(task.LeaseGeneration) + `,"name":"TOKEN","ephemeral_public":` + jsonString(ephemeralPubForTest(t)) + `}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/secrets", "token", secretBody); w.Code != http.StatusOK {
		t.Fatalf("secrets = %d: %s", w.Code, w.Body.String())
	}
	if v := counterValue(s, "kiwi_secret_deliveries_total"); v != 1 {
		t.Fatalf("secret deliveries = %v, want 1", v)
	}
	// Cache endpoints record hits/misses/bytes via the job-lease routes;
	// the namespace is derived from the leased job.
	key := strings.Repeat("a", 64)
	s.mu.Lock()
	cj := s.jobs[task.Job.ID]
	s.mu.Unlock()
	repo, trust := cacheNamespace(cj)
	if err := writeCacheBlob(s.store.Root, cacheFileKey(repo, trust, key), []byte("cached-data")); err != nil {
		t.Fatal(err)
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+task.Job.ID+"/cache/"+key, "token", "", hdrs); w.Code != http.StatusOK {
		t.Fatalf("cache get = %d: %s", w.Code, w.Body.String())
	}
	if v := counterValue(s, "kiwi_cache_hits_total"); v != 1 {
		t.Fatalf("cache hits = %v, want 1", v)
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+task.Job.ID+"/cache/"+strings.Repeat("b", 64), "token", "", hdrs); w.Code != http.StatusNotFound {
		t.Fatalf("cache miss = %d", w.Code)
	}
	if v := counterValue(s, "kiwi_cache_misses_total"); v != 1 {
		t.Fatalf("cache misses = %v, want 1", v)
	}
	if v := counterValue(s, "kiwi_cache_bytes_total"); v == 0 {
		t.Fatal("cache bytes not recorded")
	}
	// Queue latency and job duration histograms: complete the job.
	complete := `{"runner_id":` + jsonString(runnerID) + `,"lease_token":` + jsonString(task.LeaseToken) + `,"lease_generation":` + itoa(task.LeaseGeneration) + `,"status":"success"}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", complete); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d", w.Code)
	}
	if v := histogramCount(s, "kiwi_queue_latency_seconds"); v != 1 {
		t.Fatalf("queue latency samples = %v, want 1", v)
	}
	if v := histogramCount(s, "kiwi_job_duration_seconds"); v != 1 {
		t.Fatalf("job duration samples = %v, want 1", v)
	}
}

func TestMetricsResetZeroesCounters(t *testing.T) {
	m := NewMetrics()
	m.Add("kiwi_cache_hits_total", 5, nil)
	m.Reset()
	if v := counterValue(&Server{Metrics: m}, "kiwi_cache_hits_total"); v != 0 {
		t.Fatalf("counter after reset = %v", v)
	}
}

// counterValue reads a counter from the metrics registry.
func counterValue(s *Server, name string) float64 {
	s.Metrics.mu.Lock()
	defer s.Metrics.mu.Unlock()
	vec := s.Metrics.counters[name]
	total := 0.0
	for _, v := range vec {
		total += v
	}
	return total
}

// histogramCount returns the total observations in a histogram.
func histogramCount(s *Server, name string) uint64 {
	s.Metrics.mu.Lock()
	defer s.Metrics.mu.Unlock()
	var count uint64
	for _, h := range s.Metrics.histograms[name] {
		count += h.count
	}
	return count
}

// staticBroker is a fixed map secret broker for metrics tests.
type staticBroker map[string]string

func (b staticBroker) Resolve(ctx context.Context, name string, scope secretbroker.SecretScope) (string, error) {
	v, ok := b[name]
	if !ok {
		return "", fmt.Errorf("secret %q not found", name)
	}
	return v, nil
}

// ephemeralPubForTest generates a fresh X25519 public key for the secret
// endpoint.
func ephemeralPubForTest(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// writeCacheBlob seeds a cache entry on disk.
func writeCacheBlob(root, key string, data []byte) error {
	dir := filepath.Join(root, "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, key+".tar.gz"), data, 0o600); err != nil {
		return err
	}
	return nil
}

var _ = model.StatusSuccess

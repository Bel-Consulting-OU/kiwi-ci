package pipeline

import (
	"fmt"
	"strings"
	"testing"
)

// cacheDefsDoc builds a minimal valid pipeline whose job declares n cache
// entries.
func cacheDefsDoc(n int) string {
	var b strings.Builder
	b.WriteString("version: 1\njobs:\n  build:\n    cache:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "      - key: k%d\n        paths: [.cache]\n", i)
	}
	b.WriteString("    steps:\n      - run: r\n")
	return b.String()
}

// TestValidateLimitsCacheDefsCeiling pins the absolute per-job cache
// declaration cap: it exists alongside the step/service/artifact limits so a
// single run cannot fan out unbounded cache archive work.
func TestValidateLimitsCacheDefsCeiling(t *testing.T) {
	spec, err := Parse([]byte(cacheDefsDoc(maxCacheDefsPerJob)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLimits(spec); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	// Parse itself runs ValidateLimits, so build the over-limit spec by
	// extending the valid one and pin ValidateLimits directly.
	job := spec.Jobs["build"]
	job.Cache = append(job.Cache, Cache{Key: "extra", Paths: []string{".cache"}})
	spec.Jobs["build"] = job
	if err := ValidateLimits(spec); err == nil || !strings.Contains(err.Error(), "cache entries") {
		t.Fatalf("over the limit = %v, want a cache-entries error", err)
	}
}

// TestValidateCacheQuotaUntrusted pins the trust-dependent ceiling: trusted
// pipelines keep the absolute cap while untrusted ones are held to the
// stricter per-job bound (each entry can pin durable shared storage).
func TestValidateCacheQuotaUntrusted(t *testing.T) {
	trusted, err := Parse([]byte(cacheDefsDoc(MaxUntrustedCacheDefsPerJob + 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCacheQuota(trusted, false); err != nil {
		t.Fatalf("trusted quota: %v", err)
	}
	if err := ValidateCacheQuota(trusted, true); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("untrusted quota = %v, want a refusal naming untrusted jobs", err)
	}
	atLimit, err := Parse([]byte(cacheDefsDoc(MaxUntrustedCacheDefsPerJob)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCacheQuota(atLimit, true); err != nil {
		t.Fatalf("untrusted at the limit: %v", err)
	}
	// The per-job form used by the executor and generated-fragment admission.
	if err := ValidateCacheCount("j", atLimit.Jobs["build"].Cache, true); err != nil {
		t.Fatalf("ValidateCacheCount at limit: %v", err)
	}
	if err := ValidateCacheCount("j", trusted.Jobs["build"].Cache, true); err == nil {
		t.Fatal("ValidateCacheCount allowed an over-limit untrusted job")
	}
}

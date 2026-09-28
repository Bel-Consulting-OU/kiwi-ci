package server

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func cacheCeilingDoc(n int) string {
	var b strings.Builder
	b.WriteString("version: 1\njobs:\n  build:\n    cache:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "      - key: k%d\n        paths: [.cache]\n", i)
	}
	b.WriteString("    steps:\n      - run: r\n")
	return b.String()
}

// TestAdmitUntrustedCacheQuota pins the admission choke point: an untrusted
// spec over the per-job cache-definition ceiling is refused with the typed
// admission reason before any signing/persistence, while trusted specs and
// at-limit untrusted specs pass.
func TestAdmitUntrustedCacheQuota(t *testing.T) {
	s := &Server{}
	over, err := pipeline.Parse([]byte(cacheCeilingDoc(pipeline.MaxUntrustedCacheDefsPerJob + 1)))
	if err != nil {
		t.Fatal(err)
	}
	err = s.admitUntrustedCacheQuota(over, false)
	var ae *admissionError
	if !errors.As(err, &ae) {
		t.Fatalf("over-limit untrusted admit = %v, want *admissionError", err)
	}
	if ae.Reason != "untrusted_cache_ceiling_exceeded" || ae.Status != 400 {
		t.Fatalf("admission error = %+v", ae)
	}
	if err := s.admitUntrustedCacheQuota(over, true); err != nil {
		t.Fatalf("trusted spec refused: %v", err)
	}
	atLimit, err := pipeline.Parse([]byte(cacheCeilingDoc(pipeline.MaxUntrustedCacheDefsPerJob)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.admitUntrustedCacheQuota(atLimit, false); err != nil {
		t.Fatalf("at-limit untrusted spec refused: %v", err)
	}
}

// TestApplyUntrustedResourceCeilingsEnforcesCacheCount pins the compiled-job
// form used for generated fragments, which bypass enqueueID.
func TestApplyUntrustedResourceCeilingsEnforcesCacheCount(t *testing.T) {
	s := &Server{}
	cj := pipeline.CompiledJob{BaseID: "j"}
	for i := 0; i < pipeline.MaxUntrustedCacheDefsPerJob+1; i++ {
		cj.Job.Cache = append(cj.Job.Cache, pipeline.Cache{Key: fmt.Sprintf("k%d", i)})
	}
	if _, err := s.applyUntrustedResourceCeilings(cj, true); err != nil {
		t.Fatalf("trusted compiled job refused: %v", err)
	}
	_, err := s.applyUntrustedResourceCeilings(cj, false)
	var ae *admissionError
	if !errors.As(err, &ae) || ae.Reason != "untrusted_cache_ceiling_exceeded" {
		t.Fatalf("compiled-job ceiling = %v, want the cache admission error", err)
	}
}

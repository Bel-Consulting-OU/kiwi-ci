package pipeline

// Coverage for the trust-aware service-count ceiling now shared by runner
// admission and the executor: ValidateServiceCount is the per-job form the
// executor calls immediately before starting any service container, and
// ValidateServiceQuota is the spec-level form. Both must enforce the
// untrusted ceiling (MaxUntrustedServicesPerJob) and the trusted ceiling
// (maxServicesPerJob) and report deterministic, job-named errors.

import (
	"fmt"
	"strings"
	"testing"
)

// TestValidateServiceCountTrustAwareCeilings pins the per-job ceiling
// boundary: exactly-at-limit is accepted, one over is rejected, and the
// untrusted limit is strictly lower than the trusted one so an untrusted job
// can never fan out to the trusted maximum.
func TestValidateServiceCountTrustAwareCeilings(t *testing.T) {
	if MaxUntrustedServicesPerJob >= maxServicesPerJob {
		t.Fatalf("untrusted ceiling %d must stay below the trusted ceiling %d", MaxUntrustedServicesPerJob, maxServicesPerJob)
	}
	services := func(n int) []Service {
		out := make([]Service, n)
		for i := range out {
			out[i] = Service{Name: fmt.Sprintf("svc-%d", i), Image: "alpine:3.19"}
		}
		return out
	}
	cases := []struct {
		name      string
		count     int
		untrusted bool
		wantErr   bool
	}{
		{"untrusted none", 0, true, false},
		{"untrusted at limit", MaxUntrustedServicesPerJob, true, false},
		{"untrusted over limit", MaxUntrustedServicesPerJob + 1, true, true},
		{"trusted at untrusted limit", MaxUntrustedServicesPerJob, false, false},
		{"trusted at trusted limit", maxServicesPerJob, false, false},
		{"trusted over trusted limit", maxServicesPerJob + 1, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateServiceCount("build", services(tc.count), tc.untrusted)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%d services accepted (untrusted=%v)", tc.count, tc.untrusted)
				}
				// The error names the job, the observed count, the applied
				// limit and the trust domain, so an operator can act on it.
				msg := err.Error()
				if !strings.Contains(msg, `"build"`) || !strings.Contains(msg, fmt.Sprintf("%d services", tc.count)) {
					t.Fatalf("error %q does not name the job and count", msg)
				}
				trust := "trusted"
				if tc.untrusted {
					trust = "untrusted"
				}
				if !strings.Contains(msg, trust) {
					t.Fatalf("error %q does not name the %s trust domain", msg, trust)
				}
				return
			}
			if err != nil {
				t.Fatalf("at-limit request rejected: %v", err)
			}
		})
	}
}

// TestValidateServiceQuotaDeterministicAcrossJobs proves the spec-level
// check walks every job (a first-job overflow cannot hide a second job's
// violation), is nil-safe, and reports jobs in sorted order so the same spec
// always yields the same error.
func TestValidateServiceQuotaDeterministicAcrossJobs(t *testing.T) {
	if err := ValidateServiceQuota(nil, true); err != nil {
		t.Fatalf("nil spec = %v, want nil", err)
	}
	if err := ValidateServiceQuota(&Spec{}, true); err != nil {
		t.Fatalf("empty spec = %v, want nil", err)
	}
	many := make([]Service, MaxUntrustedServicesPerJob+1)
	for i := range many {
		many[i] = Service{Name: fmt.Sprintf("svc-%d", i), Image: "alpine:3.19"}
	}
	// "bbb" is over the untrusted ceiling; "aaa" is fine. Sorted iteration
	// must still reach bbb, and the reported job must be bbb.
	spec := &Spec{Jobs: map[string]Job{
		"bbb": {Runtime: "container", Image: "alpine:3.19", Services: many},
		"aaa": {Runtime: "container", Image: "alpine:3.19"},
	}}
	err := ValidateServiceQuota(spec, true)
	if err == nil {
		t.Fatal("untrusted spec with an over-limit job accepted")
	}
	if !strings.Contains(err.Error(), `"bbb"`) {
		t.Fatalf("error %q does not name the offending job", err)
	}
	// The same spec is legal for a trusted pipeline (the untrusted ceiling
	// is strictly lower), proving the trust argument is what rejects it.
	if err := ValidateServiceQuota(spec, false); err != nil {
		t.Fatalf("trusted spec rejected: %v", err)
	}
	// With both jobs over the limit, sorted iteration reports the FIRST id
	// deterministically.
	both := &Spec{Jobs: map[string]Job{
		"zzz": {Services: many},
		"aaa": {Services: many},
	}}
	first, err := func() (string, error) {
		err := ValidateServiceQuota(both, true)
		return "aaa", err
	}()
	if err == nil || !strings.Contains(err.Error(), `"`+first+`"`) {
		t.Fatalf("over-limit spec = %v, want the sorted-first job aaa", err)
	}
}

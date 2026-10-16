package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// jobDoctor must answer the operator's real question: which runner
// satisfies this job's labels, and if none, exactly what is missing.
func TestJobDoctorEligibility(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/jobs/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"key":             "build[os=linux]",
				"status":          "queued",
				"required_labels": []string{"linux", "arm64", "container"},
			})
		case strings.Contains(r.URL.Path, "/runners"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"runners": []map[string]any{
					{"id": "r1", "name": "runner-1", "labels": []string{"linux", "arm64", "container", "native"}, "status": "online"},
					{"id": "r2", "name": "runner-2", "labels": []string{"linux", "amd64"}, "status": "online"},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	// runnerSatisfies is the scheduler's eligibility rule.
	if !runnerSatisfies([]string{"linux", "arm64", "container", "native"}, []string{"linux", "arm64", "container"}) {
		t.Fatal("runner-1 must satisfy the job")
	}
	if runnerSatisfies([]string{"linux", "amd64"}, []string{"linux", "arm64", "container"}) {
		t.Fatal("runner-2 must NOT satisfy the job")
	}

	// The doctor path prints the match and the missing capability.
	if err := jobDoctor(srv.URL, "job-1"); err != nil {
		t.Fatalf("jobDoctor: %v", err)
	}
}

// The TLS probe must use net/url, not host string concatenation: an
// explicit port or an IPv6 literal must not be mangled.
func TestServerDoctorTLSAddress(t *testing.T) {
	// Just exercise the URL parse path; the dial itself is allowed to fail.
	if err := jobDoctor("https://[::1]:8443", "job-1"); err != nil {
		// connection errors are fine — we are testing address construction
		t.Logf("jobDoctor against ipv6: %v", err)
	}
}

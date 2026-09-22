package server

// FAIL-before proofs for the stolen-certificate-serial privilege defect.
//
// The tests in this file deliberately use only APIs that existed BEFORE the
// fix (HTTP routes, runner registration, admin cert binding), so the whole
// file compiles and runs against the pre-fix tree: every test here FAILS
// there and PASSES after the fix. The stronger post-fix assertions (the
// runner_profile_links binding rows, the admin runner-binding endpoints)
// live in runner_profile_binding_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// perRunnerTokenServer builds a profile-enforced server whose runner tier is
// authenticated by per-runner bearer tokens (the production bearer mode):
// the shared dev token is rejected once these credentials exist.
func perRunnerTokenServer(t *testing.T, tokens map[string]string) *Server {
	t.Helper()
	s := New("shared-dev-tok")
	s.AdminToken = "admin-tok"
	s.RequireProfiles = true
	digests := map[string]string{}
	for id, raw := range tokens {
		digests[id] = auth.TokenDigest(raw)
	}
	s.LoadRunnerTokens(digests)
	return s
}

// privilegedProfile is the profile the attack targets: distinctive labels,
// region, repository ACL, capacity and rates.
func privilegedProfile() model.RunnerProfile {
	return model.RunnerProfile{
		ID: "priv", Labels: []string{"privileged"}, Region: "secure",
		Repositories: []string{"github.com/o/secret"},
		Capabilities: []string{"container"},
		MaxCapacity:  7, CostPerHour: 42, PowerWatts: 999,
	}
}

// assertNoPrivilegeInheritance fails when a runner record carries ANY
// profiling attribute, i.e. when the privileged profile (or any profile)
// was applied despite the runner having no binding of its own.
func assertNoPrivilegeInheritance(t *testing.T, who string, ri model.Runner) {
	t.Helper()
	if len(ri.Labels) != 0 || ri.Region != "" || len(ri.AllowedRepositories) != 0 ||
		ri.Capacity != 0 || ri.CostPerHour != 0 || ri.PowerWatts != 0 {
		t.Fatalf("%s inherited a profile without its own binding: %+v", who, ri)
	}
	if ri.CertSerial != "" {
		t.Fatalf("%s stored the client-asserted certificate serial %q", who, ri.CertSerial)
	}
}

// TestStolenCertSerialCannotInheritPrivilegedProfile is the direct attack:
// a low-privilege per-runner bearer token submits the certificate serial of
// a pre-bound but currently unregistered privileged runner. Pre-fix the
// serial is "unclaimed", so the payload serial is honored and the privileged
// profile is applied; post-fix the bearer identity never consults the
// payload serial and the runner registers empty under RequireProfiles.
func TestStolenCertSerialCannotInheritPrivilegedProfile(t *testing.T) {
	s := perRunnerTokenServer(t, map[string]string{
		"runner-low":  "token-low",
		"runner-priv": "token-priv",
	})
	createProfile(t, s, privilegedProfile())
	// The privileged runner's certificate serial is pre-bound; that runner
	// has NOT registered yet.
	bindSerial(t, s, "priv", "0priv")

	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{
			"id": "runner-low", "name": "low", "protocol_min": 3, "protocol_max": 3,
			"cert_serial": "0priv", "labels": []string{"self"}, "capacity": 1,
			"capabilities": []string{"container"},
		}, "token-low", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("attacker register: %d %s", w.Code, w.Body.String())
	}
	var low model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &low); err != nil {
		t.Fatal(err)
	}
	assertNoPrivilegeInheritance(t, "attacker", low)

	// The admin-managed certificate binding itself is untouched.
	s.mu.Lock()
	bound, still := s.certProfiles["0priv"]
	s.mu.Unlock()
	if !still || bound != "priv" {
		t.Fatalf("cert binding changed by the attack: %q ok=%v", bound, still)
	}
}

// TestStolenCertSerialCannotInheritPrivilegedProfileDB is the DB-mode twin:
// the per-runner credential comes from the durable runner_bearer_tokens
// contract and the profile binding from cert_profile_links.
func TestStolenCertSerialCannotInheritPrivilegedProfileDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("shared-dev-tok")
	s.AdminToken = "admin-tok"
	s.RequireProfiles = true
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if err := s.ProvisionRunnerTokensDB(context.Background(), map[string]string{
		"runner-low":  auth.TokenDigest("token-low"),
		"runner-priv": auth.TokenDigest("token-priv"),
	}); err != nil {
		t.Fatal(err)
	}
	createProfile(t, s, privilegedProfile())
	bindSerial(t, s, "priv", "0priv-db")

	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{
			"id": "runner-low", "name": "low", "protocol_min": 3, "protocol_max": 3,
			"cert_serial": "0priv-db", "labels": []string{"self"}, "capacity": 1,
		}, "token-low", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("attacker register: %d %s", w.Code, w.Body.String())
	}
	var low model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &low); err != nil {
		t.Fatal(err)
	}
	assertNoPrivilegeInheritance(t, "db attacker", low)
}

// TestUnverifiedPeerCertSerialCannotSelectProfile: with a runner CA
// configured, a presented certificate that does NOT chain to that CA must
// not contribute its serial as a profile key. Pre-fix the serial of ANY
// presented peer certificate was returned unverified, so an attacker could
// present a self-selected (or foreign) certificate whose serial was bound to
// a privileged profile and inherit it; post-fix only a verified certificate
// contributes a serial and the payload serial is not a fallback while mTLS
// is configured.
func TestUnverifiedPeerCertSerialCannotSelectProfile(t *testing.T) {
	caA, err := runnerpki.NewCA("trusted ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caB, err := runnerpki.NewCA("attacker ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
	s.RunnerCA = caA
	createProfile(t, s, privilegedProfile())
	_, foreign := pkiSignRunner(t, caB, "runner-a")
	bindSerial(t, s, "priv", foreign.SerialNumber.Text(16))

	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"cert_serial": foreign.SerialNumber.Text(16), "capacity": 8,
		}, "token-a", foreign)
	if w.Code != http.StatusOK {
		t.Fatalf("foreign-cert register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	assertNoPrivilegeInheritance(t, "unverified-cert runner", ri)
}

// TestConcurrentBearerSerialDoubleClaimNoInheritance is the TOCTOU proof:
// many per-runner bearer registrations race the same pre-bound serial. The
// old ownership check was a payload scan, so every racer that read "no
// runner holds this serial" inherited the privileged profile and two racers
// could both record the serial. Post-fix no racer inherits anything and at
// most one runner row records the serial (in per-runner bearer mode: none).
func TestConcurrentBearerSerialDoubleClaimNoInheritance(t *testing.T) {
	const n = 8
	tokens := map[string]string{}
	for i := 0; i < n; i++ {
		tokens[fmt.Sprintf("runner-%02d", i)] = fmt.Sprintf("token-%02d", i)
	}
	s := perRunnerTokenServer(t, tokens)
	createProfile(t, s, privilegedProfile())
	bindSerial(t, s, "priv", "0race")

	type result struct {
		code int
		body []byte
	}
	results := make([]result, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("runner-%02d", i)
			body, err := json.Marshal(map[string]any{
				"id": id, "name": id, "protocol_min": 3, "protocol_max": 3,
				"cert_serial": "0race", "capabilities": []string{"container"},
			})
			if err != nil {
				return
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer token-"+fmt.Sprintf("%02d", i))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			<-start
			s.Handler().ServeHTTP(w, req)
			results[i] = result{code: w.Code, body: w.Body.Bytes()}
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		if results[i].code != http.StatusOK {
			t.Fatalf("racer %d register = %d %s", i, results[i].code, results[i].body)
		}
		var ri model.Runner
		if err := json.Unmarshal(results[i].body, &ri); err != nil {
			t.Fatalf("racer %d decode: %v", i, err)
		}
		assertNoPrivilegeInheritance(t, fmt.Sprintf("racer %d", i), ri)
	}

	s.mu.Lock()
	claimants := 0
	for _, ri := range s.runners {
		if ri.CertSerial == "0race" {
			claimants++
		}
	}
	s.mu.Unlock()
	if claimants > 1 {
		t.Fatalf("%d runner rows claimed the raced serial, want at most one", claimants)
	}
}

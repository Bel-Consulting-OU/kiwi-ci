package runner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// TestIntersectStringLists pins the runner-side capability intersection:
// the profile list order survives, only shared values remain, and an empty
// side yields nothing.
func TestIntersectStringLists(t *testing.T) {
	got := intersectStringLists([]string{"native", "container", "tart"}, []string{"native", "tart"})
	if len(got) != 2 || got[0] != "native" || got[1] != "tart" {
		t.Fatalf("intersection = %v, want [native tart]", got)
	}
	if got := intersectStringLists([]string{"container"}, []string{"native"}); len(got) != 0 {
		t.Fatalf("disjoint intersection = %v, want empty", got)
	}
	if got := intersectStringLists(nil, []string{"native"}); len(got) != 0 {
		t.Fatalf("nil profile intersection = %v, want empty", got)
	}
	if got := intersectStringLists([]string{"native"}, nil); len(got) != 0 {
		t.Fatalf("nil reported intersection = %v, want empty", got)
	}
}

// TestRegisterAdvertisesDiscoveredCapsAndCertSerial drives the real
// register payload against a stub control plane: the payload carries the
// discovered hardware capabilities, the runner's certificate serial, and
// the runner stores the intersection of the response's profile caps with
// the discovered set (never enlarging the profile).
func TestRegisterAdvertisesDiscoveredCapsAndCertSerial(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, certPEM := signIdentity(t, ca, "runner-cap", time.Hour, 0)
	cert, err := runnerpki.ParseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	_ = keyPEM

	var mu sync.Mutex
	var gotPayload model.Runner
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in model.Runner
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode register payload: %v", err)
		}
		mu.Lock()
		gotPayload = in
		mu.Unlock()
		// The control plane replies with the profile-derived ceiling.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.Runner{
			ID: "runner-cap", Name: "runner-cap", Capacity: 2,
			Labels:       []string{"container"},
			Capabilities: []string{"native", "container", "tart"},
		})
	}))
	defer ts.Close()

	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-tok"}}
	r.ID = "runner-cap"
	r.clientCertPEM = certPEM
	r.Client = &http.Client{Timeout: 10 * time.Second}
	if err := r.register(t.Context()); err != nil {
		t.Fatalf("register: %v", err)
	}

	mu.Lock()
	payload := gotPayload
	mu.Unlock()
	if payload.CertSerial != cert.SerialNumber.Text(16) {
		t.Fatalf("payload cert_serial = %q, want %q", payload.CertSerial, cert.SerialNumber.Text(16))
	}
	discovered := discoveredCapabilities()
	for _, c := range payload.Capabilities {
		if !containsString(discovered, c) {
			t.Fatalf("payload advertised undiscovered capability %q (discovered=%v)", c, discovered)
		}
	}
	if !containsString(payload.Capabilities, "native") {
		t.Fatalf("payload capabilities %v must include native", payload.Capabilities)
	}
	// The stored intersection never exceeds the profile ceiling nor the
	// discovered set.
	for _, c := range r.effectiveCapabilities {
		if !containsString([]string{"native", "container", "tart"}, c) || !containsString(discovered, c) {
			t.Fatalf("effective capability %q outside profile∩discovered", c)
		}
	}
	if !r.capEnforced {
		t.Fatal("capEnforced must be set when the response declares profile capabilities")
	}
}

// TestCheckCapabilityEnforcesIntersection: with a profile ceiling the
// runner refuses runtimes outside its intersection; without one it accepts.
func TestCheckCapabilityEnforcesIntersection(t *testing.T) {
	r := &Runner{capEnforced: true, effectiveCapabilities: []string{"native"}}
	if err := r.checkCapability("native"); err != nil {
		t.Fatalf("native in intersection: %v", err)
	}
	if err := r.checkCapability("container"); err == nil {
		t.Fatal("container outside the intersection was accepted")
	}
	if err := r.checkCapability(""); err != nil {
		t.Fatalf("empty runtime must not be constrained: %v", err)
	}
	legacy := &Runner{}
	if err := legacy.checkCapability("container"); err != nil {
		t.Fatalf("legacy (no profile ceiling) refusal: %v", err)
	}
}

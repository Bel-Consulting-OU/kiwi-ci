package runner

import (
	"context"
	"encoding/json"
	"io"
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

// TestCheckCapabilityEnforcesIntersection: with a profile claim the runner
// refuses runtimes outside its intersection; without one it accepts.
func TestCheckCapabilityEnforcesIntersection(t *testing.T) {
	r := &Runner{capEnforced: true, effectiveCapabilities: []string{"native"}}
	if err := r.checkCapability("native"); err != nil {
		t.Fatalf("native in intersection: %v", err)
	}
	if err := r.checkCapability(""); err != nil {
		t.Fatalf("empty runtime (native default) in intersection: %v", err)
	}
	if err := r.checkCapability("container"); err == nil {
		t.Fatal("container outside the intersection was accepted")
	}
	// An empty runtime is the native default: it must be refused when
	// native is not in the intersection.
	containerOnly := &Runner{capEnforced: true, effectiveCapabilities: []string{"container"}}
	if err := containerOnly.checkCapability(""); err == nil {
		t.Fatal("native default (empty runtime) accepted without the native capability")
	}
	legacy := &Runner{}
	if err := legacy.checkCapability("container"); err != nil {
		t.Fatalf("legacy (no profile claim) refusal: %v", err)
	}
}

// TestCheckCapabilityEmptyEnforcedDeniesEveryRuntime covers CRITICAL-3 on
// the runner side: an enforced intersection that is EMPTY denies every
// runtime rather than meaning "no restriction".
func TestCheckCapabilityEmptyEnforcedDeniesEveryRuntime(t *testing.T) {
	r := &Runner{capEnforced: true}
	for _, runtime := range []string{"", "native", "container", "tart", "unknown"} {
		if err := r.checkCapability(runtime); err == nil {
			t.Fatalf("empty enforced capability intersection accepted runtime %q", runtime)
		}
	}
	// Enforced with an explicit empty (non-nil) list behaves identically.
	empty := &Runner{capEnforced: true, effectiveCapabilities: []string{}}
	if err := empty.checkCapability("native"); err == nil {
		t.Fatal("explicit empty enforced intersection accepted native")
	}
	// Without the claim the set stays unrestricted (legacy server).
	legacy := &Runner{effectiveCapabilities: []string{}}
	if err := legacy.checkCapability("native"); err != nil {
		t.Fatalf("legacy runner must accept native: %v", err)
	}
}

// TestRegisterCapabilityClaimPresenceEnforced pins the register-response
// semantics: the capabilities KEY being present (even empty or null) is an
// authoritative profile claim that enforces the intersection; only an
// absent key is the legacy no-claim server.
func TestRegisterCapabilityClaimPresenceEnforced(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantEnforced bool
		wantCaps     int
	}{
		{"explicit empty list is a claim", `{"id":"runner-claim","capabilities":[]}`, true, 0},
		{"explicit null is a claim", `{"id":"runner-claim","capabilities":null}`, true, 0},
		{"absent key is a legacy server", `{"id":"runner-claim"}`, false, 0},
		{"non-empty claim is enforced", `{"id":"runner-claim","capabilities":["native","container","tart"]}`, true, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer ts.Close()
			r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-tok"}, Client: ts.Client()}
			if err := r.register(context.Background()); err != nil {
				t.Fatalf("register: %v", err)
			}
			if r.capEnforced != tc.wantEnforced {
				t.Fatalf("capEnforced = %t, want %t", r.capEnforced, tc.wantEnforced)
			}
			if tc.wantCaps >= 0 && len(r.effectiveCapabilities) != tc.wantCaps {
				t.Fatalf("effective capabilities = %v, want %d entries", r.effectiveCapabilities, tc.wantCaps)
			}
			if tc.wantCaps < 0 {
				// Never enlarge the profile: every retained capability must
				// also be discovered on this host.
				discovered := discoveredCapabilities()
				for _, c := range r.effectiveCapabilities {
					if !containsString(discovered, c) {
						t.Fatalf("effective capability %q not discovered (%v)", c, discovered)
					}
				}
				if len(r.effectiveCapabilities) == 0 {
					t.Fatal("native must survive a profile that claims native")
				}
			}
		})
	}
}

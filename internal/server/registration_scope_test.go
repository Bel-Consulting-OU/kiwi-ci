package server

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// TestValidateRunnerRegistrationAdversarial extends the baseline table with
// the unicode/control/overflow edges an attacker controls: overlong labels
// and regions, confusable scripts, NUL/newline injection, protocol ranges
// and non-finite rates.
func TestValidateRunnerRegistrationAdversarial(t *testing.T) {
	valid := RunnerInfo{Capacity: 2, Labels: []string{"container"}, Region: "east", ProtocolMin: 3, ProtocolMax: 3}

	reject := []struct {
		name   string
		mutate func(*RunnerInfo)
	}{
		{"label 65 chars", func(in *RunnerInfo) { in.Labels = []string{strings.Repeat("a", 65)} }},
		{"label with NUL", func(in *RunnerInfo) { in.Labels = []string{"cont\x00ainer"} }},
		{"label with control char", func(in *RunnerInfo) { in.Labels = []string{"cont\x01ainer"} }},
		{"label with newline", func(in *RunnerInfo) { in.Labels = []string{"cont\nainer"} }},
		{"label trailing space", func(in *RunnerInfo) { in.Labels = []string{"container "} }},
		{"label leading space", func(in *RunnerInfo) { in.Labels = []string{" container"} }},
		{"label confusable cyrillic", func(in *RunnerInfo) { in.Labels = []string{"contain\u0435r"} }},
		{"label empty", func(in *RunnerInfo) { in.Labels = []string{""} }},
		{"label emoji", func(in *RunnerInfo) { in.Labels = []string{"build\U0001F600"} }},
		{"region 65 chars", func(in *RunnerInfo) { in.Region = strings.Repeat("r", 65) }},
		{"region with NUL", func(in *RunnerInfo) { in.Region = "ea\x00st" }},
		{"region with control char", func(in *RunnerInfo) { in.Region = "ea\x7fst" }},
		{"region confusable", func(in *RunnerInfo) { in.Region = "\u0435ast" }},
		{"region with slash", func(in *RunnerInfo) { in.Region = "eu/west" }},
		{"region with colon", func(in *RunnerInfo) { in.Region = "eu:west" }},
		{"capacity 4097", func(in *RunnerInfo) { in.Capacity = maxRunnerCapacity + 1 }},
		{"capacity max int", func(in *RunnerInfo) { in.Capacity = math.MaxInt }},
		{"capacity negative", func(in *RunnerInfo) { in.Capacity = -1 }},
		{"cost NaN", func(in *RunnerInfo) { in.CostPerHour = math.NaN() }},
		{"cost +Inf", func(in *RunnerInfo) { in.CostPerHour = math.Inf(1) }},
		{"cost -Inf", func(in *RunnerInfo) { in.CostPerHour = math.Inf(-1) }},
		{"watts NaN", func(in *RunnerInfo) { in.PowerWatts = math.NaN() }},
		{"watts -Inf", func(in *RunnerInfo) { in.PowerWatts = math.Inf(-1) }},
		{"watts negative", func(in *RunnerInfo) { in.PowerWatts = -0.1 }},
		{"protocol min > max", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = 4, 3 }},
		{"protocol below range", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = 1, 2 }},
		{"protocol above range", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = ProtocolMax+1, ProtocolMax+9 }},
		{"protocol max below min protocol", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = 0, 2 }},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			if err := validateRunnerRegistration(&in); err == nil {
				t.Fatalf("registration accepted %+v", in)
			}
		})
	}

	accept := []struct {
		name   string
		mutate func(*RunnerInfo)
	}{
		{"capacity zero", func(in *RunnerInfo) { in.Capacity = 0 }},
		{"capacity max", func(in *RunnerInfo) { in.Capacity = maxRunnerCapacity }},
		{"region empty", func(in *RunnerInfo) { in.Region = "" }},
		{"region 64 chars", func(in *RunnerInfo) { in.Region = strings.Repeat("r", 64) }},
		{"label 64 chars", func(in *RunnerInfo) { in.Labels = []string{strings.Repeat("a", 64)} }},
		{"label dots colons underscores", func(in *RunnerInfo) { in.Labels = []string{"os.macos:arm_64-x"} }},
		{"zero rates", func(in *RunnerInfo) { in.CostPerHour, in.PowerWatts = 0, 0 }},
		{"negative zero rates", func(in *RunnerInfo) { in.CostPerHour, in.PowerWatts = math.Copysign(0, -1), math.Copysign(0, -1) }},
		{"max float rates", func(in *RunnerInfo) { in.CostPerHour, in.PowerWatts = math.MaxFloat64, math.MaxFloat64 }},
		{"protocol clamped from below", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = 1, 3 }},
		// A negative minimum is nonsense but safe: it is clamped UP into
		// the supported window, never widening what the control plane
		// speaks ([-1,3] overlaps [3,3]).
		{"protocol negative min clamped", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = -1, 3 }},
		{"protocol clamped from above", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = 3, 99 }},
		// Duplicate labels are set-idempotent (matching and lease
		// predicates build a set), so they are accepted by design.
		{"duplicate labels", func(in *RunnerInfo) { in.Labels = []string{"container", "container"} }},
	}
	for _, tc := range accept {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			if err := validateRunnerRegistration(&in); err != nil {
				t.Fatalf("valid registration rejected: %v", err)
			}
		})
	}
	// Clamping only narrows to the supported window, never widens it.
	minClamp := valid
	minClamp.ProtocolMin, minClamp.ProtocolMax = 1, 99
	if err := validateRunnerRegistration(&minClamp); err != nil {
		t.Fatal(err)
	}
	if minClamp.ProtocolMin != ProtocolMin || minClamp.ProtocolMax != ProtocolMax {
		t.Fatalf("protocol clamp = [%d,%d]", minClamp.ProtocolMin, minClamp.ProtocolMax)
	}
}

// TestRegisterRejectsHostileLabelsOverHTTP drives the hostile label/region
// shapes through the real endpoint and proves 400s (no partial
// registration).
func TestRegisterRejectsHostileLabelsOverHTTP(t *testing.T) {
	s := New("secret")
	h := s.Handler()
	base := `{"name":"r","protocol_min":3,"protocol_max":3`
	cases := []struct {
		name string
		body string
	}{
		{"overlong label", base + `,"labels":["` + strings.Repeat("a", 65) + `"]}`},
		{"nul label", base + `,"labels":["a\u0000b"]}`},
		{"newline label", base + `,"labels":["a\nb"]}`},
		{"confusable label", base + `,"labels":["contain\u0435r"]}`},
		{"empty label", base + `,"labels":[""]}`},
		{"overlong region", base + `,"region":"` + strings.Repeat("r", 65) + `"}`},
		{"nul region", base + `,"region":"ea\u0000st"}`},
		{"NaN cost", base + `,"cost_per_hour":NaN}`},
		{"Inf watts", base + `,"power_watts":Infinity}`},
		{"negative cost", base + `,"cost_per_hour":-1}`},
		{"capacity overflow", base + `,"capacity":100000000}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", []byte(tc.body), "secret", nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400: %s", tc.name, w.Code, w.Body.String())
			}
		})
	}
	// Nothing was registered by the rejected attempts.
	s.mu.Lock()
	n := len(s.runners)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d runners registered despite rejected payloads", n)
	}
	// Duplicate labels are accepted and behave as a set: the runner still
	// matches a job requiring the label once.
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		[]byte(`{"name":"dup","protocol_min":3,"protocol_max":3,"labels":["container","container"],"capacity":1}`), "secret", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("duplicate labels rejected: %d %s", w.Code, w.Body.String())
	}
	if !labelsSatisfied([]string{"container", "container"}, []string{"container"}) {
		t.Fatal("duplicate labels must satisfy the label set")
	}
}

// TestEnrollRunnerIDCharacterGrammar pins the enroll-time runner ID
// grammar: valid UTF-8 without control characters. The ID is bound into the
// certificate identity and into identity comparisons, so framing-hostile
// bytes (NUL/newline/DEL) are refused while printable unicode names remain
// usable.
func TestEnrollRunnerIDCharacterGrammar(t *testing.T) {
	ca, err := runnerpki.NewCA("id ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-tok")
	s.RunnerCA = ca
	s.RunnerEnrollToken = "enroll-tok"
	h := s.Handler()

	for _, bad := range []string{"runner\u0000a", "runner\na", "runner\ra", "runner\u007f", "run\u0085ner"} {
		_, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-a")
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(EnrollRequest{RunnerID: bad, CSR: base64.StdEncoding.EncodeToString(csrPEM)})
		if err != nil {
			t.Fatal(err)
		}
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, "enroll-tok", nil); w.Code != http.StatusBadRequest {
			t.Errorf("runner_id %q = %d, want 400", bad, w.Code)
		}
	}
	// Overlong IDs are refused.
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-a")
	if err != nil {
		t.Fatal(err)
	}
	longBody, err := json.Marshal(EnrollRequest{RunnerID: strings.Repeat("r", 129), CSR: base64.StdEncoding.EncodeToString(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", longBody, "enroll-tok", nil); w.Code != http.StatusBadRequest {
		t.Errorf("overlong runner_id = %d, want 400", w.Code)
	}
	// Printable unicode IDs remain allowed (fail-closed only on framing).
	uniBody, err := json.Marshal(EnrollRequest{RunnerID: "runner-\u00e9\u4e2d\u6587", CSR: base64.StdEncoding.EncodeToString(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", uniBody, "enroll-tok", nil); w.Code != http.StatusOK {
		t.Fatalf("printable unicode runner_id = %d, want 200: %s", w.Code, w.Body.String())
	}
	_ = model.Runner{}
}

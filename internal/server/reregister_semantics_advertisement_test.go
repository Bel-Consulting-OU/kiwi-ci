package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestReregistrationKeepsExecutionSemanticsAdvertisement: a re-registration
// that still advertises v3 keeps the lease gate open; a re-registration that
// omits the field (pre-field binary / downgraded runner) must clear the
// advertisement so the runner is treated as legacy v2-only — never keep a
// claim the new payload does not make.
func TestReregistrationKeepsExecutionSemanticsAdvertisement(t *testing.T) {
	s := New("token")
	reg := func(body string) (int, model.Runner) {
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", body)
		var ri model.Runner
		if w.Code == http.StatusOK {
			_ = json.Unmarshal(w.Body.Bytes(), &ri)
		}
		return w.Code, ri
	}
	// First registration advertises v3.
	code, ri := reg(`{"id":"r-sem","name":"r-sem","protocol_version":2,"supported_execution_semantics":["kiwi.execution.v3"],"protocol_min":2,"protocol_max":3,"capacity":1}`)
	if code != http.StatusOK {
		t.Fatalf("first register = %d", code)
	}
	if len(ri.SupportedExecutionSemantics) != 1 || ri.SupportedExecutionSemantics[0] != model.ExecutionSemanticsVersion {
		t.Fatalf("first advertisement = %v", ri.SupportedExecutionSemantics)
	}
	s.mu.Lock()
	stored := s.runners["r-sem"]
	s.mu.Unlock()
	if !model.SupportsExecutionSemantics(stored.SupportedExecutionSemantics, model.ExecutionSemanticsVersion) {
		t.Fatalf("stored advertisement = %v, must support v3", stored.SupportedExecutionSemantics)
	}

	// Re-register still advertising v3 (new incarnation).
	code, _ = reg(`{"id":"r-sem","name":"r-sem","protocol_version":2,"supported_execution_semantics":["kiwi.execution.v3"],"protocol_min":2,"protocol_max":3,"capacity":1}`)
	if code != http.StatusOK {
		t.Fatalf("re-register with field = %d", code)
	}
	s.mu.Lock()
	stored = s.runners["r-sem"]
	s.mu.Unlock()
	if !model.SupportsExecutionSemantics(stored.SupportedExecutionSemantics, model.ExecutionSemanticsVersion) {
		t.Fatalf("after re-register advertisement = %v", stored.SupportedExecutionSemantics)
	}

	// Re-register WITHOUT the field (legacy binary): fail closed to v2-only.
	code, _ = reg(`{"id":"r-sem","name":"r-sem","protocol_version":2,"protocol_min":2,"protocol_max":3,"capacity":1}`)
	if code != http.StatusOK {
		t.Fatalf("re-register without field = %d", code)
	}
	s.mu.Lock()
	stored = s.runners["r-sem"]
	s.mu.Unlock()
	if model.SupportsExecutionSemantics(stored.SupportedExecutionSemantics, model.ExecutionSemanticsVersion) {
		t.Fatalf("omitted advertisement must not keep v3: %v", stored.SupportedExecutionSemantics)
	}
	if !model.SupportsExecutionSemantics(stored.SupportedExecutionSemantics, model.LegacyExecutionSemanticsVersion) {
		t.Fatalf("omitted advertisement must remain v2-capable: %v", stored.SupportedExecutionSemantics)
	}
}

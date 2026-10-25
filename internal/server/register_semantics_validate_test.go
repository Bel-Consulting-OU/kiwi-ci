package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRegisterRejectsUnknownExecutionSemantics: an unknown advertised
// engine version is refused 400 before anything is stored (fail closed),
// while the current stamp is accepted.
func TestRegisterRejectsUnknownExecutionSemantics(t *testing.T) {
	s := New("token")
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := post(`{"name":"r-bad","protocol_version":2,"supported_execution_semantics":["kiwi.execution.v99"],"protocol_min":2,"protocol_max":3,"capacity":1}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown semantics status = %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unsupported execution semantics") {
		t.Fatalf("body = %s", w.Body.String())
	}
	w = post(`{"name":"r-good","protocol_version":2,"supported_execution_semantics":["kiwi.execution.v3"],"protocol_min":2,"protocol_max":3,"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("current semantics status = %d body=%s", w.Code, w.Body.String())
	}
	// Empty advertisement stays the legacy contract (accepted).
	w = post(`{"name":"r-legacy","protocol_version":2,"protocol_min":2,"protocol_max":3,"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("empty semantics status = %d body=%s", w.Code, w.Body.String())
	}
}

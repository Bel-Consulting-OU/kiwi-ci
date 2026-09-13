package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunnerAuth(t *testing.T) {
	s := New("secret")
	r := httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", bytes.NewBufferString(`{"name":"x"}`))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", bytes.NewBufferString(`{"name":"x"}`))
	r.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

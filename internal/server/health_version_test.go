package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestVersionInfoPublicCompatibilityDocument: GET /version is an
// unauthenticated probe that reports build identity plus the generated
// compatibility contract, and it never touches the store (a control plane
// whose database is down still answers).
func TestVersionInfoPublicCompatibilityDocument(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /version = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET /version body does not parse: %v", err)
	}
	for _, key := range []string{"version", "go_version", "storage_schema_version", "compatibility"} {
		if _, ok := body[key]; !ok {
			t.Errorf("GET /version body missing %q", key)
		}
	}
	compat, ok := body["compatibility"].(map[string]any)
	if !ok {
		t.Fatalf("GET /version compatibility is %T, want object", body["compatibility"])
	}
	for _, key := range []string{"produces", "consumes", "storage_schema", "minimum_reader", "minimum_writer"} {
		if _, ok := compat[key]; !ok {
			t.Errorf("GET /version compatibility missing %q", key)
		}
	}
	// The document must name the completion-hash contract the corpora pin.
	produces, _ := compat["produces"].(map[string]any)
	if produces["completion_result_hash"] != "3" {
		t.Errorf("compatibility.produces.completion_result_hash = %v, want 3", produces["completion_result_hash"])
	}
}

// TestVersionInfoSkipsSchemaFence: /version is a static compile-time
// document and must never force a schema-floor DB read (same skip class as
// /liveness and /readiness).
func TestVersionInfoSkipsSchemaFence(t *testing.T) {
	_, fs, c := countingFloorServer(t, 1)
	if w := c.do(http.MethodGet, "/version", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("GET /version with a tight floor = %d, want 200", w.Code)
	}
	if fs.reads.Load() != 0 {
		t.Fatalf("GET /version triggered %d schema floor read(s); it must skip the fence", fs.reads.Load())
	}
}

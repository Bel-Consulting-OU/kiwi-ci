package verifyapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestResourceFactsSerialization pins the neutral economics wire shape: every
// fact survives a round trip, field names are stable snake_case, and the
// units comment in types.go (ns / bytes) is the wire contract.
func TestResourceFactsSerialization(t *testing.T) {
	rf := ResourceFacts{
		QueueLatencyNS:      123,
		ExecutionLatencyNS:  456,
		WallTimeNS:          579,
		CPUTimeNS:           400,
		PeakMemoryBytes:     70 << 20,
		IOBytes:             4096,
		CacheHits:           7,
		CacheMisses:         2,
		RunnerClass:         "spot",
		RetryCount:          1,
		Cancelled:           true,
		DuplicateAvoided:    true,
		Speculative:         true,
		VerificationGroupID: "grp-9",
		CandidateID:         "cand-9",
	}
	raw, err := json.Marshal(rf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Stable names: the documented snake_case keys must be present.
	for _, key := range []string{
		`"queue_latency_ns"`, `"execution_latency_ns"`, `"wall_time_ns"`, `"cpu_time_ns"`,
		`"peak_memory_bytes"`, `"io_bytes"`, `"cache_hits"`, `"cache_misses"`,
		`"runner_class"`, `"retry_count"`, `"cancelled"`, `"duplicate_avoided"`,
		`"speculative"`, `"verification_group_id"`, `"candidate_id"`,
	} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("serialized facts missing %s: %s", key, raw)
		}
	}
	var back ResourceFacts
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != rf {
		t.Fatalf("round trip = %+v, want %+v", back, rf)
	}
	// Negative measurements are refused (fail closed on garbage).
	bad := rf
	bad.CPUTimeNS = -1
	if err := bad.validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative cpu_time_ns = %v, want ErrInvalid", err)
	}
	// Speculative rows must carry group + candidate identity.
	bad = rf
	bad.VerificationGroupID = ""
	if err := bad.validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("speculative without group id = %v, want ErrInvalid", err)
	}
}

// TestOutcomeDocumentRoundTrip proves the versioned JSON codec is stable: the
// v1 document round-trips and carries schema_version=1.
func TestOutcomeDocumentRoundTrip(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	raw, err := MarshalOutcome(v)
	if err != nil {
		t.Fatalf("MarshalOutcome = %v", err)
	}
	if !bytes.Contains(raw, []byte(`"schema_version":1`)) {
		t.Fatalf("document missing schema_version:1: %s", raw)
	}
	back, err := UnmarshalOutcome(raw)
	if err != nil {
		t.Fatalf("UnmarshalOutcome = %v", err)
	}
	if back.VerificationID != v.VerificationID || back.EvidenceRoot != v.EvidenceRoot {
		t.Fatalf("round trip lost fields: %+v", back)
	}
	if back.Resources != v.Resources {
		t.Fatalf("resources round trip = %+v, want %+v", back.Resources, v.Resources)
	}
}

// TestCodecRejectsWrongSchemaVersion: fail closed on any schema other than
// verifyapi v1 — no guessing, no silent acceptance.
func TestCodecRejectsWrongSchemaVersion(t *testing.T) {
	ob := baseObligation(t)
	raw, err := MarshalObligation(ob)
	if err != nil {
		t.Fatalf("MarshalObligation = %v", err)
	}
	mutated := bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)
	if _, err := UnmarshalObligation(mutated); !errors.Is(err, ErrInvalid) {
		t.Fatalf("schema_version 2 = %v, want ErrInvalid", err)
	}
	// Unknown fields are refused as well (strict decoding).
	withExtra := bytes.Replace(raw, []byte("{"), []byte(`{"extra_field":true,`), 1)
	if _, err := UnmarshalObligation(withExtra); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field = %v, want ErrInvalid", err)
	}
}

func TestObligationDocumentRoundTrip(t *testing.T) {
	ob := baseObligation(t)
	raw, err := MarshalObligation(ob)
	if err != nil {
		t.Fatalf("MarshalObligation = %v", err)
	}
	back, err := UnmarshalObligation(raw)
	if err != nil {
		t.Fatalf("UnmarshalObligation = %v", err)
	}
	if back.ObligationID != ob.ObligationID ||
		back.ImmutableCandidateDigest != ob.ImmutableCandidateDigest ||
		back.OpaqueCorrelationMetadata["trace"] != "abc" {
		t.Fatalf("round trip = %+v", back)
	}
	// A structurally invalid document is refused at decode time.
	ob.RequiredChecks = nil
	raw, _ = MarshalObligation(ob)
	if _, err := UnmarshalObligation(raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty required_checks = %v, want ErrInvalid", err)
	}
}

func TestErrorDocumentClassification(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{ErrInvalid, "invalid"},
		{ErrNotFound, "not_found"},
		{ErrExists, "exists"},
		{ErrBinding, "binding"},
		{ErrFreshness, "freshness"},
		{ErrGroupBinding, "group_binding"},
	}
	for _, tc := range cases {
		raw, err := MarshalError(tc.err)
		if err != nil {
			t.Fatalf("MarshalError(%v) = %v", tc.err, err)
		}
		var doc ErrorDocument
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("unmarshal error doc: %v", err)
		}
		if doc.Code != tc.code || doc.SchemaVersion != SchemaVersion {
			t.Fatalf("MarshalError(%v) = %+v, want code %q", tc.err, doc, tc.code)
		}
	}
}

// TestHTTPFacade exercises the additive surface end-to-end: submit
// obligation, record outcome, and prove a wrong-candidate outcome is refused
// with 409 and no record.
func TestHTTPFacade(t *testing.T) {
	r := NewRegistry(nil)
	h := Handler(r)
	ob := baseObligation(t)
	obRaw, err := MarshalObligation(ob)
	if err != nil {
		t.Fatalf("MarshalObligation = %v", err)
	}
	rec := doRequest(t, h, "POST", "/api/v1/verifications/obligations", obRaw)
	if rec.Code != 201 {
		t.Fatalf("submit obligation status = %d body %s", rec.Code, rec.Body)
	}
	rec = doRequest(t, h, "GET", "/api/v1/verifications/obligations/ob-1", nil)
	if rec.Code != 200 {
		t.Fatalf("get obligation status = %d body %s", rec.Code, rec.Body)
	}

	v := baseOutcome(t, ob)
	v.CandidateDigest = mustDigest(t, "wrong-candidate")
	vRaw, err := MarshalOutcome(v)
	if err != nil {
		// Validation rejects the wrong digest shape? No — wrong digest is
		// still a well-formed digest; marshal must succeed.
		t.Fatalf("MarshalOutcome = %v", err)
	}
	rec = doRequest(t, h, "POST", "/api/v1/verifications/outcomes", vRaw)
	if rec.Code != 409 {
		t.Fatalf("unbound outcome status = %d body %s, want 409", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"code":"binding"`) {
		t.Fatalf("error body = %s, want code binding", rec.Body)
	}

	v.CandidateDigest = ob.ImmutableCandidateDigest
	vRaw, _ = MarshalOutcome(v)
	rec = doRequest(t, h, "POST", "/api/v1/verifications/outcomes", vRaw)
	if rec.Code != 201 {
		t.Fatalf("bound outcome status = %d body %s", rec.Code, rec.Body)
	}
	rec = doRequest(t, h, "GET", "/api/v1/verifications/outcomes/ver-1", nil)
	if rec.Code != 200 {
		t.Fatalf("get outcome status = %d body %s", rec.Code, rec.Body)
	}
}

func doRequest(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// fuzz_events_admission_test.go adds the two audit-round fuzz targets that
// pin the event-cursor wire contract (I4) and generated-fragment admission
// (I6): arbitrary cursor strings and fragment documents must never panic,
// every cursor input must land in exactly one of {ok, 400, 409
// scope-mismatch}, fragment admission must be deterministic (same input =>
// same accept/reject verdict) and a rejected fragment must mutate nothing.
// The seed corpus of each target is also replayed by an explicit test, so the
// seeds are covered by the ordinary `go test` lane as well as the seed-only
// `go test -run Fuzz` lane. Both targets are registered in
// scripts/fuzz-smoke.sh (the surfacecheck drift guard fails on divergence).
package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// ---------------------------------------------------------------------------
// FuzzEventCursorParse: the typed execution-event cursor parser (I4).
// ---------------------------------------------------------------------------

var (
	fuzzCursorScopeGlobal = storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeGlobal}
	fuzzCursorScopeRepo   = storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRepo, RepoID: "repo-a"}
	fuzzCursorScopeRun    = storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRun, RepoID: "repo-a", RunID: "run-1"}
)

// fuzzCursorScopeFor maps one selector byte onto the three fixed test scopes.
func fuzzCursorScopeFor(sel uint8) storage.ExecutionEventScope {
	switch sel % 3 {
	case 1:
		return fuzzCursorScopeRepo
	case 2:
		return fuzzCursorScopeRun
	default:
		return fuzzCursorScopeGlobal
	}
}

// fuzzCursorOtherScope returns a fixed scope distinct from the input scope,
// used to prove a typed cursor can never be replayed under another scope.
func fuzzCursorOtherScope(scope storage.ExecutionEventScope) storage.ExecutionEventScope {
	switch scope.Kind {
	case storage.ExecutionEventScopeGlobal:
		return fuzzCursorScopeRepo
	case storage.ExecutionEventScopeRepo:
		return fuzzCursorScopeRun
	default:
		return fuzzCursorScopeGlobal
	}
}

// fuzzCursorParse drives parseEventCursor exactly as the HTTP handlers do.
// The cursor travels percent-encoded in ?after so arbitrary bytes (NUL,
// control characters, invalid UTF-8) survive transport and reach the parser.
func fuzzCursorParse(raw string, scope storage.ExecutionEventScope) (int64, bool, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	q := url.Values{}
	q.Set("after", raw)
	r.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	seq, ok := parseEventCursor(w, r, scope)
	return seq, ok, w
}

// fuzzEventCursorParseCase is the shared assertion body of the fuzz target
// and its explicit seed test: classification, sequence round trip and scope
// binding.
func fuzzEventCursorParseCase(t *testing.T, scopeSel uint8, seq int64, raw string) {
	t.Helper()
	scope := fuzzCursorScopeFor(scopeSel)

	_, ok, w := fuzzCursorParse(raw, scope)
	switch {
	case ok:
		// Accepted: the parser must not have written any refusal.
		if w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Fatalf("cursor %q scope %s: accepted but wrote status %d body %q",
				raw, scope.ScopeKey(), w.Code, w.Body.String())
		}
	case w.Code == http.StatusBadRequest || w.Code == http.StatusConflict:
		if w.Body.Len() == 0 {
			t.Fatalf("cursor %q scope %s: refusal %d carried no body", raw, scope.ScopeKey(), w.Code)
		}
	default:
		t.Fatalf("cursor %q scope %s: verdict %v with status %d, want exactly one of {ok, 400, 409}",
			raw, scope.ScopeKey(), ok, w.Code)
	}

	// Round trip: a valid cursor generated for this scope parses back to the
	// same sequence. MinInt64 and negative sequences are clamped because the
	// parser intentionally refuses negative sequences.
	positive := seq
	if positive < 0 {
		positive = -positive
		if positive < 0 { // math.MinInt64 has no positive counterpart.
			positive = 0
		}
	}
	valid := buildExecutionEventCursor(positive, scope)
	got, ok, w := fuzzCursorParse(valid, scope)
	if !ok || w.Code != http.StatusOK || got != positive {
		t.Fatalf("round trip %q => (seq %d, ok %v, status %d), want (seq %d, ok true, status 200)",
			valid, got, ok, w.Code, positive)
	}

	// Scope binding: the same cursor under a different scope is a 409
	// cursor_scope_mismatch, never accepted.
	other := fuzzCursorOtherScope(scope)
	if executionEventScopeFingerprint(other) == executionEventScopeFingerprint(scope) {
		return // A 64-bit-prefix hash collision; never flake on it.
	}
	if _, ok, w := fuzzCursorParse(valid, other); ok || w.Code != http.StatusConflict {
		t.Fatalf("cursor %q issued for %s answered (ok %v, status %d) under %s, want 409",
			valid, scope.ScopeKey(), ok, w.Code, other.ScopeKey())
	}
}

type fuzzCursorSeed struct {
	scopeSel uint8
	seq      int64
	raw      string
}

// fuzzCursorSeeds is the deterministic seed corpus: typed cursors, bare
// integers, malformed, oversized and control-character inputs for all three
// scopes. Fingerprint-bearing seeds are built with the production helper so
// they stay valid if the fingerprint domain ever changes.
func fuzzCursorSeeds() []fuzzCursorSeed {
	globalFP := executionEventScopeFingerprint(fuzzCursorScopeGlobal)
	repoFP := executionEventScopeFingerprint(fuzzCursorScopeRepo)
	runFP := executionEventScopeFingerprint(fuzzCursorScopeRun)
	return []fuzzCursorSeed{
		{0, 0, ""},                                        // fresh start
		{0, 42, "42"},                                     // legacy bare integer, global
		{0, 42, " 42 "},                                   // trimmed bare integer
		{0, 0, "xe1:0:" + globalFP},                       // valid typed cursor, seq 0
		{0, 7, "xe1:7:" + globalFP},                       // valid typed cursor
		{0, 0, "xe1:+7:" + globalFP},                      // ParseInt accepts a leading plus
		{1, 0, "xe1:5:" + repoFP},                         // valid repo-scoped cursor
		{2, 0, "xe1:5:" + runFP},                          // valid run-scoped cursor
		{1, 0, "7"},                                       // bare integer under repo scope => 409
		{2, 0, "7"},                                       // bare integer under run scope => 409
		{1, 0, "xe1:7:" + globalFP},                       // wrong-scope fingerprint => 409
		{2, 0, "xe1:7:" + repoFP},                         // wrong-scope fingerprint => 409
		{0, 0, "xe1:7:" + repoFP},                         // wrong-scope fingerprint => 409
		{0, 0, "xe1:7:" + runFP + "x"},                    // mutated fingerprint => 409
		{0, 0, "xe1:7:zzzz"},                              // unknown fingerprint => 409
		{0, 0, "xe1:abc:" + globalFP},                     // non-numeric sequence => 400
		{0, 0, "xe1:-1:" + globalFP},                      // negative sequence => 400
		{0, 0, "xe1:99999999999999999999999:" + globalFP}, // int64 overflow => 400
		{0, 0, "xe1::" + globalFP},                        // empty sequence => 400
		{0, 0, "xe1:7"},                                   // missing fingerprint => 400
		{0, 0, "xe1:7:"},                                  // empty fingerprint => 400
		{0, 0, "xe1:"},                                    // nothing after the prefix => 400
		{0, 0, "-5"},                                      // negative bare integer => 400
		{0, 0, "0x10"},                                    // not decimal => 400
		{0, 0, "NaN"},                                     // not decimal => 400
		{0, 0, "\x00"},                                    // NUL => 400
		{0, 0, "xe1:\x00:" + globalFP},                    // control char in sequence => 400
		{0, 0, "xe1:1:\x01\x02"},                          // control chars in fingerprint => 409
		{0, 0, strings.Repeat("9", 1<<16)},                // oversized decimal => 400
		{0, 0, "xe1:1:" + strings.Repeat("f", 1<<16)},     // oversized fingerprint => 409
		{0, 0, "абв"},                                     // non-ASCII => 400
	}
}

// FuzzEventCursorParse drives the typed execution-event cursor parser with
// arbitrary scope selections, sequences and cursor strings. Invariants: no
// panic; every input is exactly one of accepted, 400 or 409
// cursor_scope_mismatch; a generated valid cursor round-trips to its
// sequence; and a cursor issued for one scope is a 409 under any other.
func FuzzEventCursorParse(f *testing.F) {
	for _, s := range fuzzCursorSeeds() {
		f.Add(s.scopeSel, s.seq, s.raw)
	}
	f.Fuzz(func(t *testing.T, scopeSel uint8, seq int64, raw string) {
		fuzzEventCursorParseCase(t, scopeSel, seq, raw)
	})
}

// TestFuzzEventCursorParseSeeds replays the fuzz seed corpus in the ordinary
// test lane (the same bodies the seed-only `go test -run Fuzz` run drives).
func TestFuzzEventCursorParseSeeds(t *testing.T) {
	for _, s := range fuzzCursorSeeds() {
		fuzzEventCursorParseCase(t, s.scopeSel, s.seq, s.raw)
	}
}

// ---------------------------------------------------------------------------
// FuzzGeneratedFragmentAdmission: fragment JSON/spec admission (I6).
// ---------------------------------------------------------------------------

// fuzzFragmentImage is the digest-pinned image every valid seed fragment uses.
const fuzzFragmentImage = "alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// fuzzFragmentSeed is one seed-corpus entry. mode selects how the body is
// prepared before the POST:
//
//	0 - parse, recompute fragment_id from the body (the runner contract) and
//	    post the canonical form; malformed bodies are posted raw;
//	1 - post the raw bytes unchanged (missing, malformed or mismatched
//	    fragment_id, unknown fields, oversized bodies);
//	2 - like 0 but corrupt the computed fragment_id (digest mismatch).
type fuzzFragmentSeed struct {
	raw  string
	mode uint8
}

// fuzzFragmentSeeds is the deterministic seed corpus: valid graphs, dep
// cycles, self/duplicate/unknown edges, matrix fragments, unknown fields,
// the external_context grammar (valid, control characters, over-limit —
// the field is deliberately excluded from the fragment digest), malformed
// JSON, control/unicode characters, deep nesting and an over-limit body.
func fuzzFragmentSeeds() []fuzzFragmentSeed {
	job := func(extra string) string {
		return `{"runtime":"container","image":"` + fuzzFragmentImage + `"` + extra + `,"steps":[{"run":"echo child"}]}`
	}
	return []fuzzFragmentSeed{{`{"jobs":{"child-a":` + job("") + `},"deps":{}}`, 0},
		{`{"jobs":{"child-a":` + job("") + `,"child-b":` + job("") + `},"deps":{"child-b":["child-a"]}}`, 0},
		{`{"jobs":{"c0":` + job("") + `,"c1":` + job("") + `},"deps":{"c0":["c1"],"c1":["c0"]}}`, 0}, // cycle
		{`{"jobs":{"c0":` + job("") + `},"deps":{"c0":["c0"]}}`, 0},                                  // self edge
		{`{"jobs":{"c0":` + job("") + `},"deps":{"c0":["missing"]}}`, 0},                             // unknown dep
		{`{"jobs":{"c0":` + job("") + `},"deps":{"unknown":["c0"]}}`, 0},                             // deps key outside fragment
		{`{"jobs":{"c0":` + job("") + `},"deps":{"c0":["c0","c0"]}}`, 0},                             // duplicate dep
		{`{"jobs":{},"deps":{}}`, 0}, // no jobs
		{`{"jobs":{"c-matrix":` + job(`,"matrix":{"os":["linux"]}`) + `},"deps":{}}`, 0},                       // pre-expanded only
		{`{"jobs":{"bad key":` + job("") + `},"deps":{}}`, 0},                                                  // illegal key charset
		{`{"jobs":{"c\u0000key":` + job("") + `},"deps":{}}`, 0},                                               // control char key
		{`{"jobs":{"c0":` + job(`,"run":"\u2028\u0000Ünïcödé"`) + `},"deps":{}}`, 1},                           // weird unicode/control value
		{`{"jobs":{"c0":` + job("") + `},"deps":{},"external_context":"fuzz-seed-外部-🙂 trace-123"}`, 0},         // valid printable context
		{`{"jobs":{"c0":` + job("") + `},"deps":{},"external_context":"\u0000\u2028pre-\u0001post-🙂"}`, 0},     // control chars in context => rejected
		{`{"jobs":{"c0":` + job("") + `},"deps":{},"external_context":"` + strings.Repeat("c", 300) + `"}`, 0}, // over-limit context => rejected
		{`{"jobs":{"c0":` + job("") + `},"deps":{},"external_context":{"object":"not a string"}}`, 1},          // wrong JSON type => rejected
		{`{"jobs":{"c0":` + job("") + `},"deps":{},"unknown_field":1}`, 1},                                     // strict decode rejects unknown fields
		{`{"jobs":{"c0":` + job("") + `},"deps":{}}`, 2},                                                       // digest mismatch
		{`{"jobs":{"c0":` + job("") + `},"deps":{}}`, 1},                                                       // missing fragment_id
		{`not json`, 0},
		{`{"jobs":`, 1},
		{`{"jobs":{"c0":` + job("") + `},"deps":{}}{"trailing":true}`, 1},
		{`{"jobs":{"c0":` + job("") + `},"deps":{"c0":[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]}}`, 1},
		{`{"jobs":{"` + strings.Repeat("k", maxGeneratedFragmentBytes) + `":` + job("") + `},"deps":{}}`, 1}, // over-limit
	}
}

// fuzzFragmentChildCount counts the run's jobs other than the parent.
func fuzzFragmentChildCount(s *Server, runID, parentJobID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, j := range s.jobs {
		if j.RunID == runID && j.ID != parentJobID {
			n++
		}
	}
	return n
}

// fuzzFragmentPreparedBody renders the request body for one seed/fuzz input.
func fuzzFragmentPreparedBody(raw string, mode uint8) string {
	if mode%3 == 1 {
		return raw
	}
	var frag generatedFragment
	if err := json.Unmarshal([]byte(raw), &frag); err != nil {
		return raw
	}
	id, err := frag.Digest()
	if err != nil {
		return raw
	}
	frag.FragmentID = id
	if mode%3 == 2 && id != "" {
		flip := byte('0')
		if id[0] == '0' {
			flip = '1'
		}
		frag.FragmentID = string(flip) + id[1:]
	}
	b, err := json.Marshal(frag)
	if err != nil {
		return raw
	}
	return string(b)
}

// fuzzGeneratedFragmentAdmissionCase is the shared assertion body of the
// fuzz target and its explicit seed test. It runs on a FRESH memory-mode
// server per case, so every verdict is state-independent.
func fuzzGeneratedFragmentAdmissionCase(t *testing.T, raw string, mode uint8) {
	t.Helper()
	s, run := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	path := "/api/v1/jobs/" + task.Job.ID + "/generated"
	body := fuzzFragmentPreparedBody(raw, mode)

	w1 := doJSONHeaders(t, s, http.MethodPost, path, "token", body, leaseHeaders(task, runnerID))
	accepted1 := w1.Code >= 200 && w1.Code < 300
	children := fuzzFragmentChildCount(s, run.ID, task.Job.ID)
	switch {
	case accepted1:
		if children == 0 {
			t.Fatalf("accepted fragment mutated nothing: status %d body %s raw %q mode %d",
				w1.Code, w1.Body.String(), raw, mode)
		}
	case w1.Code >= 400:
		if children != 0 {
			t.Fatalf("rejected fragment mutated %d child job(s): status %d body %s raw %q mode %d",
				children, w1.Code, w1.Body.String(), raw, mode)
		}
	default:
		t.Fatalf("fragment admission answered status %d (neither 2xx nor >=400): body %s raw %q mode %d",
			w1.Code, w1.Body.String(), raw, mode)
	}

	// Determinism: the identical request twice must yield the same verdict
	// class; a rejected input must also be rejected with the identical
	// status (the first call committed nothing).
	w2 := doJSONHeaders(t, s, http.MethodPost, path, "token", body, leaseHeaders(task, runnerID))
	accepted2 := w2.Code >= 200 && w2.Code < 300
	if accepted1 != accepted2 {
		t.Fatalf("nondeterministic fragment verdict: first %d second %d raw %q mode %d",
			w1.Code, w2.Code, raw, mode)
	}
	if !accepted1 && w1.Code != w2.Code {
		t.Fatalf("nondeterministic fragment rejection: first %d second %d raw %q mode %d",
			w1.Code, w2.Code, raw, mode)
	}
}

// FuzzGeneratedFragmentAdmission pushes random fragment documents through the
// REAL admission path with a live parent lease on a fresh server per input.
// Invariants: no panic; the verdict is deterministic (same input twice => same
// accept/reject); a rejected fragment mutates nothing (no child job row, no
// receipt), and an accepted one mutates at least one child.
func FuzzGeneratedFragmentAdmission(f *testing.F) {
	for _, s := range fuzzFragmentSeeds() {
		f.Add(s.raw, s.mode)
	}
	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		fuzzGeneratedFragmentAdmissionCase(t, raw, mode)
	})
}

// TestFuzzGeneratedFragmentAdmissionSeeds replays the fuzz seed corpus in the
// ordinary test lane (the same bodies the seed-only `go test -run Fuzz` run
// drives), so a broken seed is caught without invoking the fuzz engine.
func TestFuzzGeneratedFragmentAdmissionSeeds(t *testing.T) {
	for _, s := range fuzzFragmentSeeds() {
		fuzzGeneratedFragmentAdmissionCase(t, s.raw, s.mode)
	}
}

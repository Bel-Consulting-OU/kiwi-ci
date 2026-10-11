// fuzz_completion_credential_test.go closes the two fuzz lanes the
// invariants evidence map recorded as honest gaps: the completion wire body
// (I1: one terminal outcome per job) and the credential wire bodies (I9:
// credentials never exceed the execution that requested them). Each target
// drives the REAL HTTP endpoint on a fresh server per input with a live lease
// and asserts the same contract class the deterministic suites pin, but over
// arbitrary input: no panic; every input lands in exactly one verdict class;
// a rejected request mutates nothing durable; an accepted request terminalizes
// the attempt and its replay is an idempotent acknowledgment; and no response
// ever echoes a lease token or a secret value. `go test` automatically runs
// each target's seed corpus as subtests, so the seeds are covered by the
// ordinary lane as well as by `-fuzz`; the targets carry no duplicate explicit
// seed test. All targets are registered in scripts/fuzz-smoke.sh (the
// surfacecheck drift guard fails on divergence).
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// ---------------------------------------------------------------------------
// FuzzCompletionRequest: the completion wire body (I1).
// ---------------------------------------------------------------------------

// fuzzCompletionSeed is one seed-corpus entry. mode selects how the request
// identity is prepared before the POST:
//
//	0 - parse the body; fill MISSING runner_id/lease_token/lease_generation
//	    from the live lease (provided values are preserved, so a seed can
//	    present a stale generation or a foreign runner on purpose); a
//	    body that does not parse as JSON is posted raw.
//	1 - post the raw bytes unchanged (missing/foreign identity, malformed
//	    JSON, unknown fields, oversized bodies).
//	2 - like 0, but force a stale lease generation (live+1).
type fuzzCompletionSeed struct {
	raw  string
	mode uint8
}

// fuzzCompletionSeeds is the deterministic seed corpus: valid completions
// for every terminal status, error/output/runtime shapes on both sides of
// every bound, identity tampering, and malformed bodies.
func fuzzCompletionSeeds() []fuzzCompletionSeed {
	return []fuzzCompletionSeed{
		{`{"status":"success"}`, 0},
		{`{"status":"failure","error":"boom"}`, 0},
		{`{"status":"cancelled"}`, 0},
		{`{"status":"skipped"}`, 0},
		{`{"status":"blocked"}`, 0},
		{`{"status":"success","outputs":{"a":"b","unicode":"ü🙂"}}`, 0},
		{`{"status":"success","outputs":{"nul":"\u0000\u2028"}}`, 0},
		{`{"status":"success","observed_runtime":{"os":"linux","arch":"amd64"}}`, 0},
		{`{"status":"success","observed_runtime":{"os":"linux","arch":"amd64","components":{"go":"1.27"}}}`, 0},
		{`{"status":"success","observed_runtime":{"os":123}}`, 0},                   // wrong type => 400
		{`{"status":"success","observed_runtime":{"os":"\u0000"}}`, 0},              // control chars => 400
		{`{"status":"success","error":"` + strings.Repeat("e", 64<<10+1) + `"}`, 0}, // over error limit => 400
		{`{"status":"success","error":"` + strings.Repeat("e", 1024) + `"}`, 0},     // long error within limit
		{`{"status":"bogus"}`, 0}, // unknown status
		{`{}`, 0},                 // missing status
		{`{"status":"success","runner_id":"someone-else"}`, 0}, // foreign runner => 4xx
		{`{"status":"success","lease_token":"wrong"}`, 0},      // wrong token => 4xx
		{`{"status":"success","lease_generation":999}`, 0},     // stale generation => 4xx
		{`{"status":"success","lease_generation":999}`, 1},     // stale generation, raw
		{`{"status":"success"}`, 2},                            // forced stale generation
		{`{"status":"success","unknown_field":1}`, 1},          // strict decode => 400
		{`not json`, 1},
		{``, 1},
		{`{"status":`, 1},
		{`{"status":"success"}{"trailing":true}`, 1},
		{`{"status":"success","outputs":{"a":"b"},}`, 1},
		{`{"status":"success","lease_generation":1e300}`, 1}, // out-of-range integer => 400
		{`{"status":"success","lease_generation":-1}`, 1},    // negative generation => 4xx
		{`{"status":"success","error":"\x00control"}`, 1},    // raw control byte in string
	}
}

// fuzzCompletionFingerprint is the authoritative in-memory job state a
// rejected completion must leave byte-identical.
type fuzzCompletionFingerprint struct {
	status      model.Status
	generation  int64
	runner      string
	tokenHash   string
	attempts    int
	terminal    bool
	completions int
}

// fuzzCompletionState snapshots the leased job's committed state.
func fuzzCompletionState(s *Server, jobID string) fuzzCompletionFingerprint {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[jobID]
	return fuzzCompletionFingerprint{
		status:      j.Status,
		generation:  j.LeaseGeneration,
		runner:      j.LeaseRunnerID,
		tokenHash:   string(j.LeaseTokenHash),
		attempts:    j.Attempts,
		terminal:    j.Status.Terminal(),
		completions: len(s.completions),
	}
}

// fuzz_fillLeaseIdentity backfills the missing lease identity fields of a
// JSON body from the live lease. Both the completion and secret body builders
// share it so a change to the wire identity cannot silently turn one lane's
// live-lease seeds into plain rejections.
func fuzzFillLeaseIdentity(m map[string]any, runnerID string, task Task) {
	if _, ok := m["runner_id"]; !ok {
		m["runner_id"] = runnerID
	}
	if _, ok := m["lease_token"]; !ok {
		m["lease_token"] = task.LeaseToken
	}
	if _, ok := m["lease_generation"]; !ok {
		m["lease_generation"] = task.LeaseGeneration
	}
}

// fuzzCompletionBody renders the request body for one seed/fuzz input.
func fuzzCompletionBody(raw string, mode uint8, runnerID string, task Task) string {
	if mode%3 == 1 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return raw
	}
	fuzzFillLeaseIdentity(m, runnerID, task)
	if mode%3 == 2 {
		m["lease_generation"] = task.LeaseGeneration + 1
	}
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return string(b)
}

// fuzzCompletionRequestCase is the shared assertion body of the fuzz target
// and its explicit seed test. It runs on a FRESH persistent server per case.
func fuzzCompletionRequestCase(t *testing.T, raw string, mode uint8) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := registerUsageRunner(t, s)
	path := "/api/v1/jobs/" + task.Job.ID + "/complete"
	body := fuzzCompletionBody(raw, mode, runnerID, task)

	before := fuzzCompletionState(s, task.Job.ID)
	w1 := doJSONHeaders(t, s, http.MethodPost, path, "token", body, nil)
	if s := w1.Body.String(); strings.Contains(s, task.LeaseToken) {
		t.Fatalf("completion response echoed the lease token: %s (raw %q mode %d)", s, raw, mode)
	}

	switch {
	case w1.Code >= 200 && w1.Code < 300:
		after := fuzzCompletionState(s, task.Job.ID)
		if !after.terminal {
			t.Fatalf("accepted completion left the job non-terminal: status %d job %s raw %q mode %d",
				w1.Code, after.status, raw, mode)
		}
		// An accepted completion is idempotent under replay (receipt).
		w2 := doJSONHeaders(t, s, http.MethodPost, path, "token", body, nil)
		if w2.Code < 200 || w2.Code >= 300 {
			t.Fatalf("accepted completion replay answered %d, want 2xx: %s (raw %q mode %d)",
				w2.Code, w2.Body.String(), raw, mode)
		}
	case w1.Code >= 400 && w1.Code < 500:
		after := fuzzCompletionState(s, task.Job.ID)
		if after != before {
			t.Fatalf("rejected completion mutated authoritative state:\n before %+v\n after  %+v\n raw %q mode %d body %s",
				before, after, raw, mode, body)
		}
		// A rejected completion is deterministic: the identical request is
		// rejected with the identical status (nothing was committed).
		w2 := doJSONHeaders(t, s, http.MethodPost, path, "token", body, nil)
		if w2.Code != w1.Code {
			t.Fatalf("nondeterministic completion rejection: first %d second %d raw %q mode %d",
				w1.Code, w2.Code, raw, mode)
		}
	default:
		t.Fatalf("completion answered status %d (neither 2xx nor 4xx): %s raw %q mode %d body %s",
			w1.Code, w1.Body.String(), raw, mode, body)
	}
}

// FuzzCompletionRequest pushes arbitrary completion bodies through the REAL
// endpoint with a live lease on a fresh server per input. Invariants: never
// panics; every verdict is 2xx or 4xx; a 2xx terminalizes the attempt and
// replays idempotently; a 4xx leaves the authoritative state (status,
// generation, holder, token hash, attempts, receipt count) byte-identical and
// is deterministic; and no response echoes the lease credential.
func FuzzCompletionRequest(f *testing.F) {
	for _, s := range fuzzCompletionSeeds() {
		f.Add(s.raw, s.mode)
	}
	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		fuzzCompletionRequestCase(t, raw, mode)
	})
}

// ---------------------------------------------------------------------------
// FuzzSecretIssueRequest: the secret-issuance wire body (I9).
// ---------------------------------------------------------------------------

// fuzzSecretValue is the plaintext the fuzz broker serves; no response may
// ever contain it.
const fuzzSecretValue = "fuzz-secret-plaintext-0xC0FFEE"

// fuzzEphemeralPlaceholder is replaced by a fresh valid X25519 client public
// key before a seed is posted, so the valid seeds exercise the sealing path.
const fuzzEphemeralPlaceholder = "$EPHEMERAL_PUBLIC$"

// fuzzSecretSeed is one seed-corpus entry. mode selects how the body is
// prepared before the POST:
//
//	0 - parse the body; fill MISSING runner_id/lease_token/lease_generation
//	    from the live lease and replace the ephemeral placeholder; provided
//	    values are preserved.
//	1 - like 0, but ALSO fill a missing name with the declared "tok" and a
//	    missing ephemeral_public with the live key, so structurally arbitrary
//	    bodies still reach the sealing/commit path.
//	2 - post the raw bytes unchanged.
type fuzzSecretSeed struct {
	raw  string
	mode uint8
}

// fuzzSecretSeeds is the deterministic seed corpus: valid deliveries, a
// foreign identity, undeclared/malformed names, malformed keys, identity
// tampering and malformed bodies.
func fuzzSecretSeeds() []fuzzSecretSeed {
	return []fuzzSecretSeed{
		{`{"name":"tok","ephemeral_public":"` + fuzzEphemeralPlaceholder + `"}`, 0},
		{`{}`, 1},
		{`{"name":"tok","ephemeral_public":"` + fuzzEphemeralPlaceholder + `","lease_generation":999}`, 0}, // stale => 4xx
		{`{"name":"tok","ephemeral_public":"` + fuzzEphemeralPlaceholder + `","runner_id":"someone-else"}`, 0},
		{`{"name":"tok","ephemeral_public":"` + fuzzEphemeralPlaceholder + `","lease_token":"wrong"}`, 0},
		{`{"name":"other","ephemeral_public":"` + fuzzEphemeralPlaceholder + `"}`, 0}, // undeclared => 403
		{`{"name":"","ephemeral_public":"` + fuzzEphemeralPlaceholder + `"}`, 0},      // empty name => 400
		{`{"name":"tok\n","ephemeral_public":"` + fuzzEphemeralPlaceholder + `"}`, 0}, // punctuation => 400
		{`{"name":"tok","ephemeral_public":"AAAA"}`, 0},                               // wrong key length => 400
		{`{"name":"tok","ephemeral_public":"!!!not-base64!!!"}`, 0},                   // bad encoding => 400
		{`{"name":"tok"}`, 0}, // missing key => 400
		{`{"name":"` + strings.Repeat("n", 1<<16) + `","ephemeral_public":"x"}`, 0},             // oversized name => 4xx
		{`{"name":"tok","ephemeral_public":{"not":"string"}}`, 1},                               // wrong JSON type => 400
		{`{"name":"tok","ephemeral_public":"` + fuzzEphemeralPlaceholder + `","unknown":1}`, 1}, // strict decode => 400
		{`{"name":"tok","ephemeral_public":"` + fuzzEphemeralPlaceholder + `"}`, 2},             // raw: identity missing => 401/4xx
		{`not json`, 2},
		{``, 2},
		{`{"name":`, 2},
		{`{"name":"tok","ephemeral_public":"` + fuzzEphemeralPlaceholder + `"}{"trailing":true}`, 2},
		{`{"name":"tok","ephemeral_public":"` + fuzzEphemeralPlaceholder + `","name":"other"}`, 2}, // duplicate key
	}
}

// fuzzSecretBody renders the request body for one seed/fuzz input.
func fuzzSecretBody(t *testing.T, raw string, mode uint8, runnerID string, task Task, ephemeral string) string {
	t.Helper()
	if mode%3 == 2 {
		return strings.ReplaceAll(raw, fuzzEphemeralPlaceholder, ephemeral)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return strings.ReplaceAll(raw, fuzzEphemeralPlaceholder, ephemeral)
	}
	fuzzFillLeaseIdentity(m, runnerID, task)
	if mode%3 == 1 {
		if _, ok := m["name"]; !ok {
			m["name"] = "tok"
		}
		if _, ok := m["ephemeral_public"]; !ok {
			m["ephemeral_public"] = fuzzEphemeralPlaceholder
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return strings.ReplaceAll(string(b), fuzzEphemeralPlaceholder, ephemeral)
}

// fuzzSecretRequestCase is the shared assertion body of the fuzz target and
// its explicit seed test. It runs on a FRESH server per case with one trusted
// job declaring the "tok" secret and a static broker holding the sentinel
// plaintext.
func fuzzSecretRequestCase(t *testing.T, raw string, mode uint8) {
	t.Helper()
	s := New("secret")
	s.SecretBroker = secretbroker.StaticBroker{"tok": fuzzSecretValue}
	jobID, runnerID, token, generation := seedJob(t, s, true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	task := Task{LeaseToken: token, LeaseGeneration: generation}
	task.Job.ID = jobID
	body := fuzzSecretBody(t, raw, mode, runnerID, task, pubB64)
	path := "/api/v1/jobs/" + jobID + "/secrets"

	receiptsBefore := fuzzSecretReceiptCount(s)
	w1 := doJSONHeaders(t, s, http.MethodPost, path, "secret", body, nil)
	response := w1.Body.String()
	if strings.Contains(response, fuzzSecretValue) {
		t.Fatalf("secret plaintext leaked into the response: %s (raw %q mode %d)", response, raw, mode)
	}

	switch {
	case w1.Code >= 200 && w1.Code < 300:
		var out SecretResponse
		if err := json.Unmarshal([]byte(response), &out); err != nil {
			t.Fatalf("accepted issuance did not return a sealed envelope: %v: %s (raw %q mode %d)",
				err, response, raw, mode)
		}
		if out.Ciphertext == "" || out.Nonce == "" {
			t.Fatalf("accepted issuance returned an incomplete envelope: %s (raw %q mode %d)", response, raw, mode)
		}
		// An accepted delivery is replayable with the identical recipient key.
		w2 := doJSONHeaders(t, s, http.MethodPost, path, "secret", body, nil)
		if w2.Code < 200 || w2.Code >= 300 {
			t.Fatalf("accepted issuance replay answered %d, want 2xx: %s (raw %q mode %d)",
				w2.Code, w2.Body.String(), raw, mode)
		}
	case w1.Code >= 400 && w1.Code < 500:
		if after := fuzzSecretReceiptCount(s); after != receiptsBefore {
			t.Fatalf("rejected issuance persisted a receipt: before %d after %d raw %q mode %d",
				receiptsBefore, after, raw, mode)
		}
		w2 := doJSONHeaders(t, s, http.MethodPost, path, "secret", body, nil)
		if w2.Code != w1.Code {
			t.Fatalf("nondeterministic issuance rejection: first %d second %d raw %q mode %d",
				w1.Code, w2.Code, raw, mode)
		}
	default:
		t.Fatalf("secret issuance answered status %d (neither 2xx nor 4xx): %s raw %q mode %d body %s",
			w1.Code, response, raw, mode, body)
	}
}

// fuzzSecretReceiptCount counts the in-memory durable issuance receipts.
func fuzzSecretReceiptCount(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.secretReceipts)
}

// FuzzSecretIssueRequest pushes arbitrary secret-request bodies through the
// REAL endpoint with a live lease and a configured broker. Invariants: never
// panics; every verdict is 2xx or 4xx; a 2xx returns a sealed envelope and
// replays idempotently; a 4xx persists no receipt and is deterministic; and
// NO response ever contains the broker's plaintext value.
func FuzzSecretIssueRequest(f *testing.F) {
	for _, s := range fuzzSecretSeeds() {
		f.Add(s.raw, s.mode)
	}
	f.Fuzz(func(t *testing.T, raw string, mode uint8) {
		fuzzSecretRequestCase(t, raw, mode)
	})
}

// ---------------------------------------------------------------------------
// FuzzOIDCRequest: the OIDC issuance wire body (I9).
// ---------------------------------------------------------------------------

// fuzzOIDCSeeds is the deterministic seed corpus for the OIDC body: the
// allowed audience, oversized/empty/control-character audiences, wrong JSON
// shapes, malformed bodies and unknown fields. The lease credential travels
// in the Authorization header and stays fixed, so every input is judged by
// the decode + audience + lease gates.
func fuzzOIDCSeeds() []string {
	return []string{
		`{"audience":"https://aud.example.com"}`,
		`{"audience":"https://other.example.com"}`,
		`{"audience":""}`,
		`{"audience":"` + strings.Repeat("a", 513) + `"}`,
		`{"audience":"https://aud.example.com","extra":true}`,
		`{"audience":42}`,
		`{}`,
		`not json`,
		``,
		`{"audience":`,
		`{"audience":"\u0000"}`,
		`{"audience":"https://aud.example.com"}{"trailing":true}`,
	}
}

// fuzzOIDCRequestCase is the shared assertion body of the fuzz target and
// its explicit seed test. It runs on a FRESH memory server per case with a
// seeded trusted job holding the "lease1" credential.
func fuzzOIDCRequestCase(t *testing.T, raw string) {
	t.Helper()
	s, _ := oidcScopeServer(t, false)
	w1 := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-oidc/oidc", "lease1", raw, nil)
	response := w1.Body.String()

	switch {
	case w1.Code >= 200 && w1.Code < 300:
		if !strings.Contains(response, `"value"`) {
			t.Fatalf("accepted issuance returned no token: %s (raw %q)", response, raw)
		}
		w2 := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-oidc/oidc", "lease1", raw, nil)
		if w2.Code < 200 || w2.Code >= 300 {
			t.Fatalf("accepted issuance replay answered %d, want 2xx: %s (raw %q)", w2.Code, w2.Body.String(), raw)
		}
	case w1.Code >= 400 && w1.Code < 500:
		requireNoToken(t, w1)
		w2 := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-oidc/oidc", "lease1", raw, nil)
		if w2.Code != w1.Code {
			t.Fatalf("nondeterministic issuance rejection: first %d second %d raw %q", w1.Code, w2.Code, raw)
		}
	default:
		t.Fatalf("OIDC issuance answered status %d (neither 2xx nor 4xx): %s raw %q", w1.Code, response, raw)
	}
}

// FuzzOIDCRequest pushes arbitrary OIDC request bodies through the REAL
// endpoint with a live lease. Invariants: never panics; every verdict is 2xx
// or 4xx; a 2xx carries a token and replays idempotently; a rejected request
// never leaks a credential and is deterministic.
func FuzzOIDCRequest(f *testing.F) {
	for _, raw := range fuzzOIDCSeeds() {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		fuzzOIDCRequestCase(t, raw)
	})
}

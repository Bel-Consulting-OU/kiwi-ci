package supplychain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// swapRekorClient points the Rekor HTTP factory at an arbitrary test client.
func swapRekorClient(t *testing.T, c *http.Client) {
	t.Helper()
	old := rekorHTTPClient
	rekorHTTPClient = func() *http.Client { return c }
	t.Cleanup(func() { rekorHTTPClient = old })
}

// TestDefaultRekorHTTPClient proves the default client refuses redirects and
// carries a timeout.
func TestDefaultRekorHTTPClient(t *testing.T) {
	c := defaultRekorHTTPClient()
	if c.Timeout <= 0 {
		t.Fatal("default client has no timeout")
	}
	if c.CheckRedirect == nil {
		t.Fatal("default client does not set CheckRedirect")
	}
	req, err := http.NewRequest(http.MethodGet, "https://rekor.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

// TestFetchRekorEntryInputErrors proves malformed base URLs are rejected
// before any request is made.
func TestFetchRekorEntryInputErrors(t *testing.T) {
	cases := map[string]string{
		"parse error":  "https://[::1",
		"not https":    "http://rekor.example",
		"missing host": "https://",
		"empty":        "",
	}
	for label, base := range cases {
		if _, err := fetchRekorEntry(base, "uuid"); err == nil {
			t.Errorf("%s: fetch succeeded, want error", label)
		}
	}
}

// TestFetchRekorEntryHTTPErrors proves redirect refusal, transport failures,
// non-200 statuses, and short response bodies are surfaced.
func TestFetchRekorEntryHTTPErrors(t *testing.T) {
	// Redirects are never followed even when the injected client would.
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	swapRekorClient(t, redirect.Client())
	if _, err := fetchRekorEntry(redirect.URL, "uuid"); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect = %v, want 302 error", err)
	}

	// Transport failure: the server is gone.
	dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	swapRekorClient(t, &http.Client{Timeout: time.Second})
	if _, err := fetchRekorEntry(deadURL, "uuid"); err == nil || !strings.Contains(err.Error(), "fetch Rekor log entry") {
		t.Fatalf("transport failure = %v, want fetch error", err)
	}

	// Non-200 with a body: the status and body are reported.
	serverError := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(serverError.Close)
	swapRekorClient(t, serverError.Client())
	if _, err := fetchRekorEntry(serverError.URL, "uuid"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("server error = %v, want 500 error", err)
	}

	// Truncated body: the declared length exceeds what the handler writes.
	short := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}))
	t.Cleanup(short.Close)
	swapRekorClient(t, short.Client())
	if _, err := fetchRekorEntry(short.URL, "uuid"); err == nil {
		t.Fatal("truncated body must fail")
	}
}

// serveJSON serves a fixed body with status 200 over TLS.
func serveRaw(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestVerifyRekorInclusionDecodeErrors drives every decode/validation branch
// of verifyRekorInclusion with server responses that are well-formed enough
// to reach the branch under test.
func TestVerifyRekorInclusionDecodeErrors(t *testing.T) {
	pub, _ := sigKey(t)
	uuid := "abcd"
	bodyBytes := []byte("log entry body")
	sum := sha256.Sum256(bodyBytes)
	wantHash := sum[:]
	cfg := func(base string) RekorConfig { return RekorConfig{PublicKey: pub, BaseURL: base} }

	body := func(entry string) string { return `{"` + uuid + `":` + entry + `}` }

	cases := []struct {
		label      string
		response   string
		wantSubstr string
	}{
		{"invalid response JSON", `{`, "decode Rekor response"},
		{"missing entry", `{"other":"x"}`, "does not contain log entry"},
		{"entry not an object", body(`"just a string"`), "decode Rekor log entry"},
		{"no body", body(`{"integratedTime":1}`), "no body"},
		{"bad body base64", body(`{"body":"!!!","integratedTime":1}`), "decode Rekor log entry body"},
		{"body hash mismatch", body(`{"body":"` + base64.StdEncoding.EncodeToString([]byte("other")) + `","integratedTime":1}`), "body hash mismatch"},
		{"missing integratedTime", body(`{"body":"` + base64.StdEncoding.EncodeToString(bodyBytes) + `"}`), "missing integratedTime"},
		{"integratedTime not a number", body(`{"body":"` + base64.StdEncoding.EncodeToString(bodyBytes) + `","integratedTime":"1"}`), "missing integratedTime"},
		{"integratedTime mismatch", body(`{"body":"` + base64.StdEncoding.EncodeToString(bodyBytes) + `","integratedTime":2}`), "integratedTime mismatch"},
		{"bad SET base64", body(`{"body":"` + base64.StdEncoding.EncodeToString(bodyBytes) + `","integratedTime":1,"verification":{"signedEntryTimestamp":"!!!"}}`), "decode signed entry timestamp"},
		{"no SET", body(`{"body":"` + base64.StdEncoding.EncodeToString(bodyBytes) + `","integratedTime":1,"verification":{}}`), "invalid Rekor signed entry timestamp"},
		{"bad SET signature", body(`{"body":"` + base64.StdEncoding.EncodeToString(bodyBytes) + `","integratedTime":1,"verification":{"signedEntryTimestamp":"` + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + `"}}`), "invalid Rekor signed entry timestamp"},
	}
	for _, tc := range cases {
		srv := serveRaw(t, http.StatusOK, tc.response)
		swapRekorClient(t, srv.Client())
		err := verifyRekorInclusion(cfg(srv.URL), uuid, wantHash, 1)
		if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
			t.Errorf("%s: err = %v, want %q", tc.label, err, tc.wantSubstr)
		}
	}
}

// TestJCSCanonicalShapes proves the canonicalizer handles every supported
// JSON shape and rejects unsupported values.
func TestJCSCanonicalShapes(t *testing.T) {
	in := map[string]any{
		"b": true,
		"a": false,
		"n": nil,
		"m": map[string]any{"z": json.Number("1.5"), "y": []any{json.Number("2"), "x"}},
		"s": "quote\" back\\slash \b\f\n\r\t end\x01\u00e9",
	}
	got, err := jcsCanonical(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":false,"b":true,"m":{"y":[2,"x"],"z":1.5},"n":null,"s":"quote\" back\\slash \b\f\n\r\t end\u0001é"}`
	if string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}

	// Unsupported scalar type (top level).
	if _, err := jcsCanonical(42); err == nil {
		t.Fatal("unsupported top-level value must fail")
	}
	// Unsupported nested map value.
	if _, err := jcsCanonical(map[string]any{"bad": 42}); err == nil {
		t.Fatal("unsupported nested map value must fail")
	}
	// Unsupported array element.
	if _, err := jcsCanonical([]any{json.Number("1"), 42}); err == nil {
		t.Fatal("unsupported array element must fail")
	}
	// Empty containers and arrays of size one exercise the separators.
	if got, err := jcsCanonical(map[string]any{}); err != nil || string(got) != "{}" {
		t.Fatalf("empty map = %s, %v", got, err)
	}
	if got, err := jcsCanonical([]any{}); err != nil || string(got) != "[]" {
		t.Fatalf("empty array = %s, %v", got, err)
	}
}

// TestSignArtifactInputErrors proves key and digest validation plus the
// created-at default and encode failure.
func TestSignArtifactInputErrors(t *testing.T) {
	_, priv := sigKey(t)
	if _, err := SignArtifact(ed25519.PrivateKey{1, 2, 3}, "kid", sigDigest, "r", "ref", SignOptions{}); err == nil {
		t.Fatal("short private key must fail")
	}
	if _, err := SignArtifact(priv, "kid", "", "r", "ref", SignOptions{}); err == nil {
		t.Fatal("empty digest must fail")
	}
	// Zero CreatedAt takes the clock default.
	env, err := SignArtifact(priv, "kid", sigDigest, "r", "", SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var e dsseEnvelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	if st.Predicate.CreatedAt.IsZero() {
		t.Fatal("zero CreatedAt must default to the clock")
	}
	// Unrepresentable timestamp: json encoding fails.
	if _, err := SignArtifact(priv, "kid", sigDigest, "r", "ref", SignOptions{CreatedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("unrepresentable timestamp must fail encoding")
	}
}

// envelopeBytes signs an arbitrary payload into a DSSE envelope.
func envelopeBytes(t *testing.T, payload []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, pae(AttestationPayloadType, payload))
	raw, err := json.Marshal(dsseEnvelope{
		PayloadType: AttestationPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []dsseSignature{{KeyID: "kid-1", Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestVerifyAttestationParseErrors proves malformed envelopes, keys, and
// signatures are rejected.
func TestVerifyAttestationParseErrors(t *testing.T) {
	pub, priv := sigKey(t)
	valid := signForTest(t, priv)

	if _, err := VerifyAttestation([]byte("{"), pub, VerifyOptions{}); err == nil {
		t.Fatal("invalid envelope JSON must fail")
	}
	if _, err := VerifyAttestation(valid, ed25519.PublicKey{1}, VerifyOptions{}); err == nil {
		t.Fatal("short public key must fail")
	}

	var e dsseEnvelope
	if err := json.Unmarshal(valid, &e); err != nil {
		t.Fatal(err)
	}
	noSig := e
	noSig.Signatures = nil
	raw, _ := json.Marshal(noSig)
	if _, err := VerifyAttestation(raw, pub, VerifyOptions{}); err == nil {
		t.Fatal("missing signature must fail")
	}
	badSig := e
	badSig.Signatures = []dsseSignature{{KeyID: "kid-1", Sig: "!!!"}}
	raw, _ = json.Marshal(badSig)
	if _, err := VerifyAttestation(raw, pub, VerifyOptions{}); err == nil {
		t.Fatal("undecodable signature must fail")
	}

	// Correctly signed payloads that fail statement validation.
	ok := envelopeBytes(t, []byte(`{"_type":"https://example.com/other"}`), priv)
	if _, err := VerifyAttestation(ok, pub, VerifyOptions{}); err == nil {
		t.Fatal("wrong statement type must fail")
	}
	noSubject := envelopeBytes(t, []byte(`{"_type":"`+StatementType+`"}`), priv)
	if _, err := VerifyAttestation(noSubject, pub, VerifyOptions{}); err == nil {
		t.Fatal("subjectless statement must fail")
	}
	notJSON := envelopeBytes(t, []byte("this is not json"), priv)
	if _, err := VerifyAttestation(notJSON, pub, VerifyOptions{}); err == nil {
		t.Fatal("undecodable statement must fail")
	}
}

// TestParseEnvelopeErrors proves every rejection branch of parseEnvelope.
func TestParseEnvelopeErrors(t *testing.T) {
	cases := map[string]string{
		"invalid JSON":        `{`,
		"trailing data":       `{"payloadType":"` + AttestationPayloadType + `","payload":"e30="}` + " trailing",
		"wrong payload type":  `{"payloadType":"text/plain","payload":"e30="}`,
		"bad payload base64":  `{"payloadType":"` + AttestationPayloadType + `","payload":"!!!"}`,
		"empty payload":       `{"payloadType":"` + AttestationPayloadType + `","payload":""}`,
		"payload decodes nil": `{"payloadType":"` + AttestationPayloadType + `"}`,
	}
	for label, raw := range cases {
		if _, _, err := parseEnvelope([]byte(raw)); err == nil {
			t.Errorf("%s: parseEnvelope accepted, want error", label)
		}
	}
}

// TestRejectTrailing covers the trailing-data helper directly.
func TestRejectTrailing(t *testing.T) {
	first := func(t *testing.T, in string) *json.Decoder {
		t.Helper()
		dec := json.NewDecoder(strings.NewReader(in))
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return dec
	}
	if err := rejectTrailing(first(t, `{"a":1}`)); err != nil {
		t.Fatalf("single value: %v", err)
	}
	if err := rejectTrailing(first(t, `{"a":1}{"b":2}`)); err == nil {
		t.Fatal("second value must be rejected as trailing data")
	}
	if err := rejectTrailing(json.NewDecoder(strings.NewReader(`{"a":`))); err == nil {
		t.Fatal("truncated JSON must fail")
	}
}

// bundleWith builds a bundle around a signed payload, with hooks to corrupt
// specific parts.
func bundleWith(t *testing.T, pub ed25519.PublicKey, payload []byte, priv ed25519.PrivateKey, mut func(*sigstoreBundle)) []byte {
	t.Helper()
	var e dsseEnvelope
	if err := json.Unmarshal(envelopeBytes(t, payload, priv), &e); err != nil {
		t.Fatal(err)
	}
	b := sigstoreBundle{
		MediaType: SigstoreBundleMediaType,
		VerificationMaterial: bundleVerificationMaterial{
			PublicKey: &bundlePublicKey{RawBytes: base64.StdEncoding.EncodeToString(pub), KeyDetails: "PKIX_ED25519"},
		},
		DSSEEnvelope: &e,
	}
	if mut != nil {
		mut(&b)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func statementPayload(t *testing.T, st Statement) []byte {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func validStatement(t *testing.T) Statement {
	t.Helper()
	return Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "repo@ref", Digest: map[string]string{"sha256": sigDigest}}},
		PredicateType: PredicateType,
		Predicate:     Predicate{Issuer: bundleIssuer, Identity: bundleIdentity},
	}
}

// TestVerifySigstoreBundleParseErrors proves the bundle-level parse matrix.
func TestVerifySigstoreBundleParseErrors(t *testing.T) {
	pub, priv := sigKey(t)
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	good := bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, nil)

	if err := VerifySigstoreBundle([]byte("{"), sigDigest, cfg); err == nil {
		t.Fatal("invalid bundle JSON must fail")
	}
	if err := VerifySigstoreBundle(append(append([]byte(nil), good...), []byte(" {}")...), sigDigest, cfg); err == nil {
		t.Fatal("trailing bundle data must fail")
	}
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, func(b *sigstoreBundle) { b.MediaType = "text/plain" }), sigDigest, cfg); err == nil {
		t.Fatal("wrong media type must fail")
	}
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, func(b *sigstoreBundle) { b.DSSEEnvelope = nil }), sigDigest, cfg); err == nil {
		t.Fatal("missing DSSE envelope must fail")
	}
	badPayloadType := func(b *sigstoreBundle) { b.DSSEEnvelope.PayloadType = "text/plain" }
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, badPayloadType), sigDigest, cfg); err == nil {
		t.Fatal("wrong payload type must fail")
	}
	badPayloadB64 := func(b *sigstoreBundle) { b.DSSEEnvelope.Payload = "!!!" }
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, badPayloadB64), sigDigest, cfg); err == nil {
		t.Fatal("undecodable payload must fail")
	}
	noSigs := func(b *sigstoreBundle) { b.DSSEEnvelope.Signatures = nil }
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, noSigs), sigDigest, cfg); err == nil {
		t.Fatal("missing signature must fail")
	}
	badSigB64 := func(b *sigstoreBundle) { b.DSSEEnvelope.Signatures[0].Sig = "!!!" }
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, badSigB64), sigDigest, cfg); err == nil {
		t.Fatal("undecodable signature must fail")
	}

	// Invalid pinned key material.
	badPin := verifyCfgFor(t, SigstoreTrustRoot{Keys: map[string]ed25519.PublicKey{"short": {1}}})
	if err := VerifySigstoreBundle(good, sigDigest, badPin); err == nil {
		t.Fatal("invalid pinned key must fail")
	}

	// Rekor configured without a base URL.
	noURL := verifyCfgFor(t, pinKeys("kid-1", pub))
	noURL.TrustRoot.Rekor = &RekorConfig{PublicKey: pub}
	if err := VerifySigstoreBundle(good, sigDigest, noURL); err == nil {
		t.Fatal("Rekor without base URL must fail")
	}

	// Embedded key that does not decode.
	badEmbedded := func(b *sigstoreBundle) { b.VerificationMaterial.PublicKey.RawBytes = "!!!" }
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, badEmbedded), sigDigest, cfg); err == nil {
		t.Fatal("undecodable embedded key must fail")
	}
	// Embedded key of the wrong size.
	shortEmbedded := func(b *sigstoreBundle) {
		b.VerificationMaterial.PublicKey.RawBytes = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	}
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, shortEmbedded), sigDigest, cfg); err == nil {
		t.Fatal("short embedded key must fail")
	}

	// Rekor-only trust root without an embedded key fails closed.
	rekorOnly := verifyCfgFor(t, SigstoreTrustRoot{Rekor: &RekorConfig{PublicKey: pub, BaseURL: "https://rekor.example"}})
	noEmbedded := func(b *sigstoreBundle) { b.VerificationMaterial.PublicKey = nil }
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, noEmbedded), sigDigest, rekorOnly); err == nil {
		t.Fatal("rekor-only trust without an embedded key must fail")
	}
}

// TestVerifySigstoreBundleStatementAndClaimErrors proves statement parsing
// and claim checks run after a valid signature.
func TestVerifySigstoreBundleStatementAndClaimErrors(t *testing.T) {
	pub, priv := sigKey(t)
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))

	wrongType := Statement{Type: "https://example.com/other"}
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, wrongType), priv, nil), sigDigest, cfg); err == nil {
		t.Fatal("wrong statement type must fail")
	}
	if err := VerifySigstoreBundle(bundleWith(t, pub, noSubjectPayload(t), priv, nil), sigDigest, cfg); err == nil {
		t.Fatal("subjectless statement must fail")
	}
	if err := VerifySigstoreBundle(bundleWith(t, pub, []byte("not json"), priv, nil), sigDigest, cfg); err == nil {
		t.Fatal("undecodable statement must fail")
	}
	// Digest mismatch against the caller's artifact digest.
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, nil), strings.Repeat("9", 64), cfg); err == nil {
		t.Fatal("artifact digest mismatch must fail")
	}
	// Claim mismatch.
	otherIdentity := verifyCfgFor(t, pinKeys("kid-1", pub))
	otherIdentity.ExpectedIdentity = "other/subject"
	if err := VerifySigstoreBundle(bundleWith(t, pub, statementPayload(t, validStatement(t)), priv, nil), sigDigest, otherIdentity); err == nil {
		t.Fatal("identity mismatch must fail")
	}
}

func noSubjectPayload(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(Statement{Type: StatementType})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVerifySigstoreBundleRekorLogEntryValidation proves the per-log-entry
// validation branches run before any network access.
func TestVerifySigstoreBundleRekorLogEntryValidation(t *testing.T) {
	pub, priv := sigKey(t)
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: pub, BaseURL: "https://rekor.example"}
	payload := statementPayload(t, validStatement(t))

	// Missing body hash.
	noBodyHash := func(b *sigstoreBundle) {
		b.VerificationMaterial.LogEntries = []bundleLogEntry{{UUID: rekorUUID, IntegratedTime: 1700000000}}
	}
	if err := VerifySigstoreBundle(bundleWith(t, pub, payload, priv, noBodyHash), sigDigest, cfg); err == nil || !strings.Contains(err.Error(), "body hash") {
		t.Fatalf("missing body hash = %v, want body hash error", err)
	}
	// Undecodable body hash.
	badBodyHash := func(b *sigstoreBundle) {
		b.VerificationMaterial.LogEntries = []bundleLogEntry{{UUID: rekorUUID, IntegratedTime: 1700000000, BodyHash: "!!!"}}
	}
	if err := VerifySigstoreBundle(bundleWith(t, pub, payload, priv, badBodyHash), sigDigest, cfg); err == nil || !strings.Contains(err.Error(), "body hash") {
		t.Fatalf("bad body hash = %v, want body hash error", err)
	}
}

// TestVerifySigstoreBundleRekorInclusionFailure proves a fetch failure from
// the Rekor log propagates through bundle verification.
func TestVerifySigstoreBundleRekorInclusionFailure(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	// The log has no such entry.
	if err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log)); err == nil {
		t.Fatal("missing log entry must fail bundle verification")
	}
}

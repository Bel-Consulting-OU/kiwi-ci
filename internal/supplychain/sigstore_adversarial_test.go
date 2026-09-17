package supplychain

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestVerifySigstoreBundleOnlyPrimarySignatureIsAuthoritative pins the
// multi-signature semantics: the bundle's first signature is the one that
// must verify against a trusted key. A bundle whose first signature is
// invalid but whose second signature would verify is rejected — accepting a
// trailing signature would let a bundle smuggle an unverifiable primary
// signature past consumers that only look at the first entry.
func TestVerifySigstoreBundleOnlyPrimarySignatureIsAuthoritative(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	var e dsseEnvelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	// Signature 0 is signed by an untrusted key; signature 1 is the valid
	// one. The bundle must be rejected because only [0] is authoritative.
	_, otherPriv := sigKey(t)
	bad, err := SignArtifact(otherPriv, "kid-1", sigDigest, "example/repo", "refs/heads/main", SignOptions{
		Issuer: bundleIssuer, Identity: bundleIdentity, CreatedAt: time.Unix(1000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var badEnv dsseEnvelope
	if err := json.Unmarshal(bad, &badEnv); err != nil {
		t.Fatal(err)
	}
	e.Signatures = []dsseSignature{badEnv.Signatures[0], e.Signatures[0]}
	raw, err := json.Marshal(sigstoreBundle{
		MediaType: SigstoreBundleMediaType,
		VerificationMaterial: bundleVerificationMaterial{
			PublicKey: &bundlePublicKey{RawBytes: base64.StdEncoding.EncodeToString(pub), KeyDetails: "PKIX_ED25519"},
		},
		DSSEEnvelope: &e,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigstoreBundle(raw, sigDigest, verifyCfgFor(t, pinKeys("kid-1", pub))); err == nil {
		t.Fatal("a bundle whose primary signature does not verify must be rejected")
	}
}

// TestVerifySigstoreBundleRekorWrongLogKeyRejected verifies the signed entry
// timestamp is checked against the configured log key: a SET signed by any
// key other than the pinned log key fails even when the entry body and
// integratedTime match.
func TestVerifySigstoreBundleRekorWrongLogKeyRejected(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	log.put(rekorUUID, payloadOf(t, env), 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	cfg := rekorBundleConfig(t, pub, log)
	wrongPub, _ := sigKey(t)
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: wrongPub, BaseURL: log.srv.URL}
	err := VerifySigstoreBundle(bundle, sigDigest, cfg)
	if err == nil || !strings.Contains(err.Error(), "signed entry timestamp") {
		t.Fatalf("SET signed by a non-trusted log key must be rejected, got %v", err)
	}
}

// TestVerifySigstoreBundleRekorMissingSETRejected verifies a log response
// without a signedEntryTimestamp cannot pass inclusion verification.
func TestVerifySigstoreBundleRekorMissingSETRejected(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	body := payloadOf(t, env)
	// Serve a hand-built entry without verification material.
	srv := newRawRekorServer(t, map[string]any{
		rekorUUID: map[string]any{
			"body":           base64.StdEncoding.EncodeToString(body),
			"integratedTime": json.Number("1700000000"),
			"logID":          "aa",
			"logIndex":       json.Number("1"),
		},
	})
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	logPub, _ := sigKey(t)
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: logPub, BaseURL: srv.URL}
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	if err := VerifySigstoreBundle(bundle, sigDigest, cfg); err == nil {
		t.Fatal("log entry without a SET must be rejected")
	}
}

// TestVerifySigstoreBundleIntegratedTimeFutureRejected verifies an absurd
// future integratedTime is rejected even when the log signs it.
func TestVerifySigstoreBundleIntegratedTimeFutureRejected(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	future := time.Now().Add(365 * 24 * time.Hour).Unix()
	le := logEntryForTest(t, env, rekorUUID, future)
	log.put(rekorUUID, payloadOf(t, env), future)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log))
	if err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("implausibly future integratedTime must be rejected, got %v", err)
	}
}

// TestVerifySigstoreBundleIntegratedTimePastAccepted verifies genuine past
// timestamps remain acceptable (artifacts are verified long after build).
func TestVerifySigstoreBundleIntegratedTimePastAccepted(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000) // 2023
	log.put(rekorUUID, payloadOf(t, env), 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	if err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log)); err != nil {
		t.Fatalf("past integratedTime must verify: %v", err)
	}
}

// TestVerifySigstoreBundleUntrustedEmbeddedKeyNoRekor verifies an
// otherwise-valid bundle signed by a key that is neither pinned nor
// inclusion-proven is rejected.
func TestVerifySigstoreBundleUntrustedEmbeddedKeyNoRekor(t *testing.T) {
	pinned, _ := sigKey(t)
	otherPub, otherPriv := sigKey(t)
	bundle := bundleForTest(t, otherPriv, otherPub, nil)
	if err := VerifySigstoreBundle(bundle, sigDigest, verifyCfgFor(t, pinKeys("kid-1", pinned))); err == nil {
		t.Fatal("bundle signed by an unpinned key must be rejected")
	}
}

// TestVerifySigstoreBundleOversizedBody verifies the bundle size bound is
// enforced before decoding.
func TestVerifySigstoreBundleOversizedBody(t *testing.T) {
	huge := make([]byte, maxEnvelopeBytes+1)
	if err := VerifySigstoreBundle(huge, sigDigest, verifyCfgFor(t, pinKeys("kid-1", ed25519.PublicKey(make([]byte, 32))))); err == nil {
		t.Fatal("oversized bundle must be rejected")
	}
}

// rawRekorServer serves a fixed JSON map as the Rekor log-entry API.
type rawRekorServer struct {
	URL string
}

func startRawServer(t *testing.T, entries map[string]any) *rawRekorServer {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(entries)
	}))
	t.Cleanup(srv.Close)
	old := rekorHTTPClient
	rekorHTTPClient = func() *http.Client { return srv.Client() }
	t.Cleanup(func() { rekorHTTPClient = old })
	return &rawRekorServer{URL: srv.URL}
}

func newRawRekorServer(t *testing.T, entries map[string]any) *rawRekorServer {
	t.Helper()
	return startRawServer(t, entries)
}

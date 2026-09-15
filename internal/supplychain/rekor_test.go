package supplychain

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// rekorTestLog is an in-test Rekor API serving log entries whose signed
// entry timestamps are real Ed25519 signatures over the JCS-canonicalized
// entry (matching Rekor's signEntry construction).
type rekorTestLog struct {
	t       *testing.T
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	srv     *httptest.Server
	entries map[string]rekorTestEntry
	tamper  bool
}

type rekorTestEntry struct {
	body           []byte
	integratedTime int64
}

const rekorUUID = "8f1c9e3d0a2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5"

func newRekorTestLog(t *testing.T) *rekorTestLog {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l := &rekorTestLog{t: t, pub: pub, priv: priv, entries: map[string]rekorTestEntry{}}
	l.srv = httptest.NewTLSServer(http.HandlerFunc(l.serve))
	t.Cleanup(l.srv.Close)
	old := rekorHTTPClient
	rekorHTTPClient = func() *http.Client { return l.srv.Client() }
	t.Cleanup(func() { rekorHTTPClient = old })
	return l
}

func (l *rekorTestLog) put(uuid string, body []byte, integratedTime int64) {
	l.entries[uuid] = rekorTestEntry{body: body, integratedTime: integratedTime}
}

func (l *rekorTestLog) rekorPtr() *RekorConfig {
	c := RekorConfig{PublicKey: l.pub, BaseURL: l.srv.URL}
	return &c
}

func (l *rekorTestLog) serve(w http.ResponseWriter, r *http.Request) {
	uuid := strings.TrimPrefix(r.URL.Path, rekorEntryPathPrefix)
	e, ok := l.entries[uuid]
	if !ok {
		http.NotFound(w, r)
		return
	}
	logID := sha256.Sum256(l.pub)
	entry := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(e.body),
		"integratedTime": json.Number(strconv.FormatInt(e.integratedTime, 10)),
		"logID":          hex.EncodeToString(logID[:]),
		"logIndex":       json.Number("1"),
	}
	canonical, err := jcsCanonical(entry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	set := ed25519.Sign(l.priv, canonical)
	if l.tamper {
		set[len(set)-1] ^= 0xff
	}
	entry["verification"] = map[string]any{
		"signedEntryTimestamp": base64.StdEncoding.EncodeToString(set),
	}
	_ = json.NewEncoder(w).Encode(map[string]any{uuid: entry})
}

// rekorBundleConfig builds a verification config with the keys pinned and
// the test log as the Rekor trust root.
func rekorBundleConfig(t *testing.T, pub ed25519.PublicKey, log *rekorTestLog) SigstoreVerifyConfig {
	t.Helper()
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.TrustRoot.Rekor = log.rekorPtr()
	return cfg
}

func TestVerifySigstoreBundleRekorInclusionPositive(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	log.put(rekorUUID, payloadOf(t, env), 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	if err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySigstoreBundleRekorOnlyTrustsInclusion(t *testing.T) {
	// No pinned keys: the embedded key verifies the envelope, but the
	// bundle is accepted only with a valid inclusion proof.
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	log.put(rekorUUID, payloadOf(t, env), 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	cfg := verifyCfgFor(t, SigstoreTrustRoot{})
	cfg.TrustRoot.Rekor = log.rekorPtr()
	if err := VerifySigstoreBundle(bundle, sigDigest, cfg); err != nil {
		t.Fatal(err)
	}
	// The same key without any log entry is rejected even though the
	// embedded key is valid.
	noEntry := bundleForTest(t, priv, pub, nil)
	if err := VerifySigstoreBundle(noEntry, sigDigest, cfg); err == nil {
		t.Fatal("rekor-only trust must require a log entry")
	}
}

func TestVerifySigstoreBundleRekorEntryNotFound(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	// The entry is never registered in the log.
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	if err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log)); err == nil {
		t.Fatal("bundle referencing an unknown log entry must be rejected")
	}
}

func TestVerifySigstoreBundleRekorBodyHashMismatch(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	log.put(rekorUUID, []byte("a different body than the statement payload"), 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log))
	if err == nil || !strings.Contains(err.Error(), "body hash") {
		t.Fatalf("log entry body hash mismatch must be rejected, got %v", err)
	}
}

func TestVerifySigstoreBundleRekorIntegratedTimeMismatch(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	log.put(rekorUUID, payloadOf(t, env), 1699999999)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log))
	if err == nil || !strings.Contains(err.Error(), "integratedTime") {
		t.Fatalf("integratedTime mismatch must be rejected, got %v", err)
	}
}

func TestVerifySigstoreBundleRekorTamperedSETRejected(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	log.tamper = true
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	log.put(rekorUUID, payloadOf(t, env), 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	if err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log)); err == nil {
		t.Fatal("tampered signed entry timestamp must be rejected")
	}
}

func TestVerifySigstoreBundleRekorOversizeResponseRejected(t *testing.T) {
	pub, priv := sigKey(t)
	log := newRekorTestLog(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	// A log body whose base64 form blows past the 1 MiB response bound.
	log.put(rekorUUID, make([]byte, maxRekorResponseBytes), 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	err := VerifySigstoreBundle(bundle, sigDigest, rekorBundleConfig(t, pub, log))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized Rekor response must be rejected, got %v", err)
	}
}

func TestVerifySigstoreBundleRekorHTTPBaseURLRejected(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, rekorUUID, 1700000000)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: pub, BaseURL: "http://rekor.example"}
	err := VerifySigstoreBundle(bundle, sigDigest, cfg)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain-HTTP Rekor base URL must be rejected, got %v", err)
	}
}

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// oidcScopeServer builds a memory or DB-fake server with one trusted,
// running job holding the "lease1" lease. The returned mutate hook edits
// the job in whichever store backs the server.
func oidcScopeServer(t *testing.T, db bool) (*Server, func(func(*model.Job))) {
	t.Helper()
	if db {
		f := newDBFakeStore()
		s := New("secret")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		s.ExternalURL = "https://ci.example.com"
		seedDBOIDCJob(t, f, s, "lease1")
		return s, func(mut func(*model.Job)) {
			f.mu.Lock()
			defer f.mu.Unlock()
			j := f.jobs["job-oidc"]
			mut(&j)
			f.jobs["job-oidc"] = j
		}
	}
	s := New("secret")
	s.ExternalURL = "https://ci.example.com"
	seedOIDCJob(t, s, "lease1")
	return s, func(mut func(*model.Job)) {
		s.mu.Lock()
		defer s.mu.Unlock()
		j := s.jobs["job-oidc"]
		mut(&j)
		s.jobs["job-oidc"] = j
	}
}

// TestOIDCIssuanceDenialMatrixMemoryAndDB pins every issuance denial in
// BOTH storage modes: unknown job, untrusted job, missing id_token
// permission, disallowed audience, empty/oversized audience, expired or
// missing lease, and a wrong lease token.
func TestOIDCIssuanceDenialMatrixMemoryAndDB(t *testing.T) {
	type tc struct {
		name      string
		token     string
		audience  string
		mutate    func(*model.Job)
		wantCode  int
		wantValue bool
	}
	cases := []tc{
		{name: "happy path", token: "lease1", audience: "https://aud.example.com", wantCode: http.StatusOK, wantValue: true},
		{name: "untrusted job", token: "lease1", audience: "https://aud.example.com", mutate: func(j *model.Job) { j.Trusted = false }, wantCode: http.StatusForbidden},
		{name: "missing id_token permission", token: "lease1", audience: "https://aud.example.com", mutate: func(j *model.Job) { j.OIDCAllowed = false }, wantCode: http.StatusForbidden},
		{name: "disallowed audience", token: "lease1", audience: "https://evil.example.com", mutate: func(j *model.Job) { j.OIDCAudiences = []string{"https://aud.example.com"} }, wantCode: http.StatusForbidden},
		{name: "empty audience", token: "lease1", audience: "   ", wantCode: http.StatusBadRequest},
		{name: "oversized audience", token: "lease1", audience: strings.Repeat("a", 513), wantCode: http.StatusBadRequest},
		{name: "expired lease", token: "lease1", audience: "https://aud.example.com", mutate: func(j *model.Job) {
			past := time.Now().Add(-time.Minute)
			j.LeaseExpiresAt = &past
		}, wantCode: http.StatusConflict},
		{name: "missing lease", token: "lease1", audience: "https://aud.example.com", mutate: func(j *model.Job) { j.LeaseExpiresAt = nil }, wantCode: http.StatusConflict},
		{name: "wrong lease token", token: "not-the-lease", audience: "https://aud.example.com", wantCode: http.StatusUnauthorized},
		{name: "empty lease token", token: "", audience: "https://aud.example.com", wantCode: http.StatusUnauthorized},
	}
	for _, mode := range []string{"memory", "db"} {
		t.Run(mode, func(t *testing.T) {
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					s, mutate := oidcScopeServer(t, mode == "db")
					if c.mutate != nil {
						mutate(c.mutate)
					}
					cl := newTestClient(t, s.Handler(), c.token)
					w := cl.do(http.MethodPost, "/api/v1/jobs/job-oidc/oidc", map[string]any{"audience": c.audience}, nil)
					if w.Code != c.wantCode {
						t.Fatalf("%s/%s = %d, want %d: %s", mode, c.name, w.Code, c.wantCode, w.Body.String())
					}
					gotValue := strings.Contains(w.Body.String(), `"value"`)
					if gotValue != c.wantValue {
						t.Fatalf("%s/%s returned value=%v, want %v", mode, c.name, gotValue, c.wantValue)
					}
					if !c.wantValue && gotValue {
						t.Fatal("token leaked on a denied issuance")
					}
				})
			}
			// Unknown job: 404 (and never an issuance).
			s, _ := oidcScopeServer(t, mode == "db")
			w := newTestClient(t, s.Handler(), "lease1").do(http.MethodPost, "/api/v1/jobs/ghost/oidc", map[string]any{"audience": "a"}, nil)
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s unknown job = %d, want 404", mode, w.Code)
			}
		})
	}
}

// TestOIDCCoarseClockRotationEveryIssue pins the >= comparison used for
// rotation: with activeKeyMaxAge=0 every issuance rotates, all rotated keys
// stay advertised (they are unexpired), and every issued token still
// verifies against the JWKS.
func TestOIDCCoarseClockRotationEveryIssue(t *testing.T) {
	s := newOIDCTestServer(t, false)
	_, jobID := seedOIDCJob(t, s, "lease1")
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = 0
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	type issued struct {
		kid, token string
	}
	var tokens []issued
	kids := map[string]bool{}
	for i := 0; i < 3; i++ {
		tok := issueOIDCToken(t, s, jobID, "lease1", "https://aud.example.com")
		jwt := parseTestJWT(t, tok)
		if kids[jwt.headerKID] {
			t.Fatalf("issuance %d reused kid %q: the key did not rotate", i, jwt.headerKID)
		}
		kids[jwt.headerKID] = true
		tokens = append(tokens, issued{kid: jwt.headerKID, token: tok})
	}
	// Every rotated-out key must remain in the JWKS until its retire time,
	// and every token must verify with the advertised key. New() installs
	// one initial key, and each of the 3 issuances rotates it out, so the
	// ring advertises the active key plus 3 unretired previous keys.
	keys := fetchJWKS(t, s)
	if len(keys) != 1+len(tokens) {
		t.Fatalf("JWKS has %d keys, want active + %d unretired previous keys", len(keys), len(tokens))
	}
	for _, is := range tokens {
		jwt := parseTestJWT(t, is.token)
		found, k := findJWK(keys, jwt.headerKID)
		if !found {
			t.Fatalf("JWKS dropped the unretired key %q", jwt.headerKID)
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(pub, []byte(jwt.signingInput), jwt.sig) {
			t.Fatalf("token signed by %q does not verify with the advertised key", is.kid)
		}
	}
	// Rotating again must not evict an unretired key either, and the JWKS
	// validator must change with the body so a cached 304 can never serve
	// a stale key set.
	cl := newTestClient(t, s.Handler(), "")
	before := cl.do(http.MethodGet, "/api/v1/oidc/jwks", nil, nil)
	if before.Code != http.StatusOK {
		t.Fatalf("jwks: %d", before.Code)
	}
	oldETag := before.Header().Get("ETag")
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	s.mu.Unlock()
	after := cl.do(http.MethodGet, "/api/v1/oidc/jwks", nil, nil)
	if after.Code != http.StatusOK {
		t.Fatalf("jwks after rotation: %d", after.Code)
	}
	if keys := fetchJWKS(t, s); len(keys) != 2+len(tokens) {
		t.Fatalf("JWKS has %d keys after another rotation, want %d", len(keys), 2+len(tokens))
	}
	if got := after.Header().Get("ETag"); got == oldETag || got == "" {
		t.Fatalf("JWKS ETag did not change across rotation: %q", got)
	}
	if stale := cl.do(http.MethodGet, "/api/v1/oidc/jwks", nil, map[string]string{"If-None-Match": oldETag}); stale.Code != http.StatusOK {
		t.Fatalf("stale ETag served %d, want 200 with the new key set", stale.Code)
	}
}

// TestOIDCJWKSRetireBoundary pins the JWKS retention boundary: a previous
// key is advertised strictly until RetireAfter and dropped strictly after.
func TestOIDCJWKSRetireBoundary(t *testing.T) {
	s := newOIDCTestServer(t, false)
	now := time.Now().UTC()
	s.mu.Lock()
	s.rotateOIDCKeyLocked(now)
	oldKID := s.oidc.Previous[0].KID
	s.oidc.Previous[0].RetireAfter = now.Add(time.Hour)
	s.mu.Unlock()
	if found, _ := findJWK(fetchJWKS(t, s), oldKID); !found {
		t.Fatal("unretired previous key missing from JWKS")
	}
	s.mu.Lock()
	s.oidc.Previous[0].RetireAfter = now.Add(-time.Nanosecond)
	s.mu.Unlock()
	if found, _ := findJWK(fetchJWKS(t, s), oldKID); found {
		t.Fatal("retired previous key still advertised")
	}
}

// TestOIDCFileRingReloadAfterExternalModification proves a replica reloads
// a ring another writer replaced on disk: the next issuance signs with the
// externally installed active key.
func TestOIDCFileRingReloadAfterExternalModification(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	// A second instance on the same data dir rotates the ring (simulating
	// another replica/operator rewriting oidc-keyring.json externally).
	s2, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.ExternalURL = "https://ci.example.com"
	s2.mu.Lock()
	s2.rotateOIDCKeyLocked(time.Now().UTC())
	newKID := s2.oidc.KID
	s2.mu.Unlock()

	s1.ExternalURL = "https://ci.example.com"
	_, jobID := seedOIDCJob(t, s1, "lease1")
	tok := issueOIDCToken(t, s1, jobID, "lease1", "https://aud.example.com")
	jwt := parseTestJWT(t, tok)
	if jwt.headerKID != newKID {
		t.Fatalf("replica signed with kid %q, want the externally installed %q", jwt.headerKID, newKID)
	}
	// And the external ring's previous key (the old active key) stays
	// verifiable through the replica's JWKS.
	s1.mu.Lock()
	prev := s1.oidc.Previous
	s1.mu.Unlock()
	if len(prev) == 0 {
		t.Fatal("reload lost the previous key ring")
	}
	if found, _ := findJWK(fetchJWKS(t, s1), prev[0].KID); !found {
		t.Fatal("reload dropped an unretired previous key")
	}
}

// TestOIDCIssuerValidationRejectsLookalikes pins the issuer URL strictness:
// only real loopback hosts may use plaintext HTTP, and userinfo/query/
// fragment are never valid in an issuer identifier.
func TestOIDCIssuerValidationRejectsLookalikes(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://ci.example.com", true},
		{"https://ci.example.com/", true},
		{"https://ci.example.com/kiwi", true},
		{"http://localhost", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:9000", true},
		{"http://[::1]:9000", true},
		{"https://LOCALHOST", true},
		// Lookalikes must never be treated as loopback.
		{"http://localhost.evil.example", false},
		{"http://localhostfoo", false},
		{"http://127.0.0.1.attacker.test", false},
		{"http://127.0.0.10.evil.example", false},
		{"http://[::1].evil.example", false},
		{"http://localhost./evil", false},
		// Non-http(s), relative and empty values.
		{"", false},
		{"not a url", false},
		{"ftp://ci.example.com", false},
		{"//ci.example.com", false},
		// Userinfo / query / fragment are not valid issuer identifiers.
		{"https://user:pw@ci.example.com", false},
		{"https://ci.example.com?x=1", false},
		{"https://ci.example.com/#frag", false},
	}
	for _, tc := range cases {
		s := New("secret")
		s.ExternalURL = tc.url
		got, err := s.oidcIssuer()
		if tc.want != (err == nil) {
			t.Errorf("oidcIssuer(%q) = %q, err=%v; want ok=%v", tc.url, got, err, tc.want)
			continue
		}
		w := doJSON(t, s, http.MethodGet, "/.well-known/openid-configuration", "", "")
		if tc.want && w.Code != http.StatusOK {
			t.Errorf("configuration for %q = %d", tc.url, w.Code)
		}
		if !tc.want && w.Code != http.StatusServiceUnavailable {
			t.Errorf("configuration for rejected issuer %q = %d, want 503", tc.url, w.Code)
		}
	}
}

// TestOIDCTokenClaimsBoundToJobAndLease pins the issued claims: the subject
// and coordinates derive from the stored run/job, never from client input.
func TestOIDCTokenClaimsBoundToJobAndLease(t *testing.T) {
	s := newOIDCTestServer(t, false)
	_, jobID := seedOIDCJob(t, s, "lease1")
	tok := issueOIDCToken(t, s, jobID, "lease1", "https://aud.example.com")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt %q", tok)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "https://ci.example.com" || claims["aud"] != "https://aud.example.com" {
		t.Fatalf("issuer/audience wrong: %v", claims)
	}
	if claims["trusted"] != true {
		t.Fatalf("trusted claim = %v, want true", claims["trusted"])
	}
	if claims["run_id"] != "run-oidc" || claims["job_id"] != "job-oidc" || claims["job"] != "build" {
		t.Fatalf("job coordinates not from the store: %v", claims)
	}
	if claims["sub"] != "repo:kiwi/repo:ref:main:job:build" {
		t.Fatalf("subject = %v", claims["sub"])
	}
	if claims["jti"] == "" || claims["jti"] == nil {
		t.Fatal("jti missing")
	}
}

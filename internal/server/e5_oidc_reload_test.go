package server

// E5-E: OIDC freshness must not perform key-store I/O under the global server
// mutex, and issuance must authenticate the job/lease/audience BEFORE any
// signer (rotation/key-store) work. These tests pin both properties with a
// controllable in-memory cluster key store.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// countingOIDCClusterStore is an in-memory ClusterKeyStore whose lookups and
// stores are counted and whose lookups can BLOCK until released, so a test can
// stall the key store while it inspects the server's locking behavior.
type countingOIDCClusterStore struct {
	mu      sync.Mutex
	keys    map[string][]byte
	lookups int
	stores  int
	// block makes every Lookup wait until release is closed (or ctx in a
	// context-aware call is done).
	block   bool
	started chan struct{}
	release chan struct{}
}

func newCountingOIDCClusterStore() *countingOIDCClusterStore {
	return &countingOIDCClusterStore{
		keys:    map[string][]byte{},
		started: make(chan struct{}, 64),
		release: make(chan struct{}),
	}
}

func (c *countingOIDCClusterStore) LoadOrCreate(kind string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.keys[kind]; ok {
		return append([]byte(nil), b...), nil
	}
	b, err := createClusterKey(kind)
	if err != nil {
		return nil, err
	}
	c.keys[kind] = append([]byte(nil), b...)
	return append([]byte(nil), b...), nil
}

func (c *countingOIDCClusterStore) Lookup(kind string) ([]byte, bool, error) {
	c.mu.Lock()
	block, started, release := c.block, c.started, c.release
	c.lookups++
	c.mu.Unlock()
	if block {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.keys[kind]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), b...), true, nil
}

func (c *countingOIDCClusterStore) Store(kind string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stores++
	c.keys[kind] = append([]byte(nil), data...)
	return nil
}

func (c *countingOIDCClusterStore) counts() (lookups, stores int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lookups, c.stores
}

// clusterSignerFor installs a cluster-backed signer derived from the store's
// ring, optionally aged past any rotation max age.
func clusterSignerFor(t *testing.T, store ClusterKeyStore, due bool) *oidcSigner {
	t.Helper()
	b, err := store.LoadOrCreate(clusterKindOIDC)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := oidcSignerFromRing(b)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	signer.cluster = store
	signer.ringDigest = hex.EncodeToString(sum[:])
	if due {
		signer.NotBefore = time.Now().UTC().Add(-2 * time.Hour)
	}
	return signer
}

// TestE5OIDCJWKSStalledKeyStoreDoesNotHoldServerMutex is the lock-release
// regression: a JWKS request whose cluster key store stalls must NOT hold
// s.mu, so an unrelated control-plane operation can still take the lock. It
// also proves the stalled request still serves a key set (the last published
// one) instead of failing.
func TestE5OIDCJWKSStalledKeyStoreDoesNotHoldServerMutex(t *testing.T) {
	store := newCountingOIDCClusterStore()
	s := New("secret")
	s.ExternalURL = "https://ci.example.com"
	s.mu.Lock()
	s.oidc = clusterSignerFor(t, store, false)
	s.oidc.ringDigest = "stale-on-purpose"
	s.mu.Unlock()
	store.mu.Lock()
	store.block = true
	store.mu.Unlock()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.oidcJWKS(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/jwks", nil))
		done <- w
	}()
	// The handler reached the blocked key store: it is doing I/O, not holding
	// the server mutex.
	select {
	case <-store.started:
	case <-time.After(5 * time.Second):
		t.Fatal("JWKS never reached the cluster key store")
	}
	locked := make(chan struct{})
	go func() {
		s.mu.Lock()
		// An unrelated mutation under s.mu must be possible while the key
		// store lookup is stalled.
		s.ExternalURL = "https://ci.example.com"
		s.mu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled cluster key store held s.mu: an unrelated locked operation could not proceed")
	}
	close(store.release)
	select {
	case w := <-done:
		if w.Code != http.StatusOK {
			t.Fatalf("JWKS during a recovering store = %d: %s", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("JWKS did not finish after the key store recovered")
	}
}

// TestE5OIDCJWKSCanceledRequestKeepsServing pins the request-context half of
// the fix: a request whose context ends while the key store is stalled gives
// up on the refresh and answers with the last published key set instead of
// pinning the handler on the store.
func TestE5OIDCJWKSCanceledRequestKeepsServing(t *testing.T) {
	store := newCountingOIDCClusterStore()
	s := New("secret")
	s.ExternalURL = "https://ci.example.com"
	s.mu.Lock()
	published := clusterSignerFor(t, store, false)
	published.KID = "published-kid"
	s.oidc = published
	s.oidc.ringDigest = "stale-on-purpose"
	s.mu.Unlock()
	store.mu.Lock()
	store.block = true
	store.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.oidcJWKS(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/jwks", nil).WithContext(ctx))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled JWKS request hung on the stalled key store")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("JWKS with a canceled refresh context = %d, want 200 with the published key set: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "published-kid") {
		t.Fatalf("JWKS did not serve the published key: %s", w.Body.String())
	}
	close(store.release)
}

// TestE5OIDCIssuanceAuthenticatesBeforeSignerWork pins the ordering fix: every
// denial (unknown job, wrong lease token, missing id_token permission,
// disallowed audience, inactive lease) performs ZERO cluster-key-store reads
// and writes, while a successful issuance does resolve (and, with an aged key,
// rotate) the signer.
func TestE5OIDCIssuanceAuthenticatesBeforeSignerWork(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = 0 // every issuance is due, so signer work is visible
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	type tc struct {
		name     string
		mutate   func(*model.Job)
		token    string
		audience string
		jobID    string
		want     int
	}
	cases := []tc{
		{name: "unknown job", audience: "https://aud.example.com", token: "lease1", jobID: "ghost", want: http.StatusNotFound},
		{name: "wrong lease token", audience: "https://aud.example.com", token: "wrong", jobID: "job-oidc", want: http.StatusUnauthorized},
		{name: "missing id_token permission", audience: "https://aud.example.com", token: "lease1", jobID: "job-oidc",
			mutate: func(j *model.Job) { j.OIDCAllowed = false }, want: http.StatusForbidden},
		{name: "untrusted job", audience: "https://aud.example.com", token: "lease1", jobID: "job-oidc",
			mutate: func(j *model.Job) { j.Trusted = false }, want: http.StatusForbidden},
		{name: "disallowed audience", audience: "https://evil.example.com", token: "lease1", jobID: "job-oidc",
			mutate: func(j *model.Job) { j.OIDCAudiences = []string{"https://aud.example.com"} }, want: http.StatusForbidden},
		{name: "inactive lease", audience: "https://aud.example.com", token: "lease1", jobID: "job-oidc",
			mutate: func(j *model.Job) { past := time.Now().Add(-time.Minute); j.LeaseExpiresAt = &past }, want: http.StatusConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newCountingOIDCClusterStore()
			s := New("secret")
			s.ExternalURL = "https://ci.example.com"
			seedOIDCJob(t, s, "lease1")
			s.mu.Lock()
			s.oidc = clusterSignerFor(t, store, true)
			s.mu.Unlock()
			if c.mutate != nil {
				s.mu.Lock()
				j := s.jobs["job-oidc"]
				c.mutate(&j)
				s.jobs["job-oidc"] = j
				s.mu.Unlock()
			}
			cl := newTestClient(t, s.Handler(), c.token)
			w := cl.do(http.MethodPost, "/api/v1/jobs/"+c.jobID+"/oidc", map[string]any{"audience": c.audience}, nil)
			if w.Code != c.want {
				t.Fatalf("issuance = %d, want %d: %s", w.Code, c.want, w.Body.String())
			}
			if lookups, stores := store.counts(); lookups != 0 || stores != 0 {
				t.Fatalf("denied issuance performed key-store work: %d lookups, %d stores", lookups, stores)
			}
		})
	}

	// The authorized path DOES resolve the signer (and rotates the aged key).
	store := newCountingOIDCClusterStore()
	s := New("secret")
	s.ExternalURL = "https://ci.example.com"
	seedOIDCJob(t, s, "lease1")
	s.mu.Lock()
	s.oidc = clusterSignerFor(t, store, true)
	s.mu.Unlock()
	tok := issueOIDCToken(t, s, "job-oidc", "lease1", "https://aud.example.com")
	if tok == "" {
		t.Fatal("authorized issuance returned no token")
	}
	if lookups, stores := store.counts(); lookups == 0 || stores == 0 {
		t.Fatalf("authorized issuance performed no signer work: %d lookups, %d stores", lookups, stores)
	}
}

// TestE5OIDCRefreshAdoptsPeerRotationWithoutRacing is a small race stress: the
// same server is refreshed and rotated concurrently while a peer replica
// publishes new rings, and the published signer must always be one of the
// rings (never a torn or empty signer).
func TestE5OIDCRefreshAdoptsPeerRotationWithoutRacing(t *testing.T) {
	store := newCountingOIDCClusterStore()
	s := New("secret")
	s.ExternalURL = "https://ci.example.com"
	s.mu.Lock()
	s.oidc = clusterSignerFor(t, store, false)
	s.mu.Unlock()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if i%2 == 0 {
					_ = s.refreshOIDCRing(context.Background())
					continue
				}
				ring, err := createOIDCRingBytes()
				if err != nil {
					return
				}
				_ = store.Store(clusterKindOIDC, ring)
			}
		}(i)
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	s.mu.Lock()
	signer := s.oidc
	s.mu.Unlock()
	if signer == nil || signer.KID == "" || len(signer.Private) != ed25519.PrivateKeySize || len(signer.Public) != ed25519.PublicKeySize {
		t.Fatalf("published signer is torn: %+v", signer)
	}
}

// createOIDCRingBytes renders a fresh persisted ring for the race stress.
func createOIDCRingBytes() ([]byte, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	ring := oidcKeyRingJSON{Active: oidcActiveKeyFile{
		KID:       base64.RawURLEncoding.EncodeToString(pub)[:12],
		Pub:       base64.RawStdEncoding.EncodeToString(pub),
		Priv:      base64.RawStdEncoding.EncodeToString(priv),
		NotBefore: time.Now().UTC().Format(time.RFC3339Nano),
	}}
	b, err := json.Marshal(ring)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

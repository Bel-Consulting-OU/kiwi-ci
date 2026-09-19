package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// enrollFaultStore injects failures into the durable grant store.
type enrollFaultStore struct {
	*dbFakeStore
	putErr     error
	getErr     error
	consumeErr error
}

func (f *enrollFaultStore) PutEnrollGrant(ctx context.Context, digest string, expiresAt time.Time, boundLabels []string) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.dbFakeStore.PutEnrollGrant(ctx, digest, expiresAt, boundLabels)
}

func (f *enrollFaultStore) GetEnrollGrant(ctx context.Context, digest string) (storage.EnrollGrantRecord, bool, error) {
	if f.getErr != nil {
		return storage.EnrollGrantRecord{}, false, f.getErr
	}
	return f.dbFakeStore.GetEnrollGrant(ctx, digest)
}

func (f *enrollFaultStore) ConsumeEnrollGrant(ctx context.Context, digest string, consumedBy string) (storage.EnrollGrantRecord, error) {
	if f.consumeErr != nil {
		return storage.EnrollGrantRecord{}, f.consumeErr
	}
	return f.dbFakeStore.ConsumeEnrollGrant(ctx, digest, consumedBy)
}

// idcovGrantStoreOnly hides the optional EnrollGrantStore methods.
type idcovGrantStoreOnly struct{ storage.Store }

// grantServer builds a memory-mode server with a temp data dir and the
// persistence seam restored after the test.
func grantServer(t *testing.T) *Server {
	t.Helper()
	s := New("t")
	s.dataDir = t.TempDir()
	orig := persistEnrollGrantsFunc
	t.Cleanup(func() { persistEnrollGrantsFunc = orig })
	return s
}

// TestIDCovCreateEnrollGrantPaths covers the TTL guard, memory minting with
// persistence, DB minting and every failure branch.
func TestIDCovCreateEnrollGrantPaths(t *testing.T) {
	s := grantServer(t)
	if _, err := s.CreateEnrollGrant(context.Background(), 0, nil); err == nil {
		t.Fatal("non-positive ttl = nil error")
	}
	if _, err := s.CreateEnrollGrant(context.Background(), -time.Minute, nil); err == nil {
		t.Fatal("negative ttl = nil error")
	}
	s.EnrollGrants = nil
	tok, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"container"})
	if err != nil || tok == "" {
		t.Fatalf("memory grant = %q, %v", tok, err)
	}
	if s.EnrollGrants == nil {
		t.Fatal("grant map not initialized")
	}
	rec, ok := s.EnrollGrants[auth.TokenDigest(tok)]
	if !ok || rec.Used || len(rec.BoundLabels) != 1 {
		t.Fatalf("stored grant = %+v (ok=%v)", rec, ok)
	}
	// Persisted state reloads from the data dir.
	s2 := New("t")
	if err := s2.loadEnrollGrants(s.dataDir); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.EnrollGrants[auth.TokenDigest(tok)]; !ok {
		t.Fatal("grant not persisted")
	}
	// Expired grants are pruned on mint.
	s.EnrollGrants[auth.TokenDigest("stale")] = EnrollGrant{ExpiresAt: time.Now().Add(-time.Minute)}
	if _, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.EnrollGrants[auth.TokenDigest("stale")]; ok {
		t.Fatal("expired grant survived a mint")
	}
	// A persistence failure rolls the in-memory grant back.
	orig := persistEnrollGrantsFunc
	persistEnrollGrantsFunc = func(*Server) error { return errors.New("disk full") }
	if _, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil); err == nil {
		t.Fatal("persist failure = nil error")
	}
	persistEnrollGrantsFunc = orig

	// DB mode requires the durable grant store.
	s3 := New("t")
	s3.DB = idcovGrantStoreOnly{Store: newDBFakeStore()}
	if _, err := s3.CreateEnrollGrant(context.Background(), time.Hour, nil); err == nil || !strings.Contains(err.Error(), "does not support enrollment grants") {
		t.Fatalf("DB without grant store = %v", err)
	}
	// A store write failure propagates.
	fault := &enrollFaultStore{dbFakeStore: newDBFakeStore(), putErr: errors.New("write failed")}
	s4 := New("t")
	s4.DB = fault
	if _, err := s4.CreateEnrollGrant(context.Background(), time.Hour, nil); err == nil {
		t.Fatal("DB put failure = nil error")
	}
	// Success stores the digest durably.
	s4.DB = fault.dbFakeStore
	tok4, err := s4.CreateEnrollGrant(context.Background(), time.Hour, []string{"a"})
	if err != nil || tok4 == "" {
		t.Fatalf("DB grant = %q, %v", tok4, err)
	}
	if rec, ok, _ := fault.dbFakeStore.GetEnrollGrant(context.Background(), auth.TokenDigest(tok4)); !ok || len(rec.BoundLabels) != 1 {
		t.Fatalf("durable grant missing: %+v (ok=%v)", rec, ok)
	}
}

// TestIDCovEnrollGrantOKPaths covers the tier gate validation in both modes.
func TestIDCovEnrollGrantOKPaths(t *testing.T) {
	s := grantServer(t)
	if s.enrollGrantOK(context.Background(), "") {
		t.Fatal("empty token accepted")
	}
	if s.enrollGrantOK(context.Background(), "unknown") {
		t.Fatal("unknown token accepted")
	}
	live, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s.enrollGrantOK(context.Background(), live) {
		t.Fatal("live grant rejected")
	}
	used, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	g := s.EnrollGrants[auth.TokenDigest(used)]
	g.Used = true
	s.EnrollGrants[auth.TokenDigest(used)] = g
	s.mu.Unlock()
	if s.enrollGrantOK(context.Background(), used) {
		t.Fatal("used grant accepted")
	}
	expired, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	g = s.EnrollGrants[auth.TokenDigest(expired)]
	g.ExpiresAt = time.Now().Add(-time.Second)
	s.EnrollGrants[auth.TokenDigest(expired)] = g
	s.mu.Unlock()
	if s.enrollGrantOK(context.Background(), expired) {
		t.Fatal("expired grant accepted")
	}

	// DB mode.
	s2 := New("t")
	s2.DB = idcovGrantStoreOnly{Store: newDBFakeStore()}
	if s2.enrollGrantOK(context.Background(), "anything") {
		t.Fatal("DB without grant store accepted a token")
	}
	fault := &enrollFaultStore{dbFakeStore: newDBFakeStore()}
	s3 := New("t")
	s3.DB = fault
	fault.getErr = errors.New("down")
	if s3.enrollGrantOK(context.Background(), "x") {
		t.Fatal("DB read error accepted a token")
	}
	fault.getErr = nil
	if s3.enrollGrantOK(context.Background(), "x") {
		t.Fatal("unknown DB token accepted")
	}
	dbTok, err := s3.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s3.enrollGrantOK(context.Background(), dbTok) {
		t.Fatal("live DB grant rejected")
	}
	// Consumed and expired durable records are rejected.
	digest := auth.TokenDigest(dbTok)
	rec, _, _ := fault.dbFakeStore.GetEnrollGrant(context.Background(), digest)
	rec.Consumed = true
	fault.dbFakeStore.mu.Lock()
	fault.dbFakeStore.grants[digest] = rec
	fault.dbFakeStore.mu.Unlock()
	if s3.enrollGrantOK(context.Background(), dbTok) {
		t.Fatal("consumed DB grant accepted")
	}
	rec.Consumed = false
	rec.ExpiresAt = time.Now().Add(-time.Minute)
	fault.dbFakeStore.mu.Lock()
	fault.dbFakeStore.grants[digest] = rec
	fault.dbFakeStore.mu.Unlock()
	if s3.enrollGrantOK(context.Background(), dbTok) {
		t.Fatal("expired DB grant accepted")
	}
}

// TestIDCovConsumeEnrollGrantMemoryPaths covers the memory-mode consume
// contract: unknown, used, expired, label mismatch, success and the persist
// rollback.
func TestIDCovConsumeEnrollGrantMemoryPaths(t *testing.T) {
	s := grantServer(t)
	if err := s.consumeEnrollGrant(context.Background(), "", nil); err == nil {
		t.Fatal("empty token consumed")
	}
	if err := s.consumeEnrollGrant(context.Background(), "unknown", nil); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown grant = %v", err)
	}
	tok, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"container"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.consumeEnrollGrant(context.Background(), tok, []string{"container", "extra"}); err == nil || !strings.Contains(err.Error(), "does not permit label") {
		t.Fatalf("label mismatch = %v", err)
	}
	if !s.enrollGrantOK(context.Background(), tok) {
		t.Fatal("label mismatch burned the grant")
	}
	if err := s.consumeEnrollGrant(context.Background(), tok, []string{"container"}); err != nil {
		t.Fatalf("consume = %v", err)
	}
	if err := s.consumeEnrollGrant(context.Background(), tok, nil); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("double consume = %v", err)
	}
	expired, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	g := s.EnrollGrants[auth.TokenDigest(expired)]
	g.ExpiresAt = time.Now().Add(-time.Second)
	s.EnrollGrants[auth.TokenDigest(expired)] = g
	s.mu.Unlock()
	if err := s.consumeEnrollGrant(context.Background(), expired, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired consume = %v", err)
	}
	// A persistence failure restores the pre-consume entry.
	rollback, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	orig := persistEnrollGrantsFunc
	persistEnrollGrantsFunc = func(*Server) error { return errors.New("disk full") }
	if err := s.consumeEnrollGrant(context.Background(), rollback, nil); err == nil {
		t.Fatal("persist failure = nil error")
	}
	persistEnrollGrantsFunc = orig
	if !s.enrollGrantOK(context.Background(), rollback) {
		t.Fatal("failed consume did not restore the grant")
	}
}

// TestIDCovConsumeEnrollGrantDBPaths covers the durable consume contract and
// its error mapping.
func TestIDCovConsumeEnrollGrantDBPaths(t *testing.T) {
	s := New("t")
	s.DB = idcovGrantStoreOnly{Store: newDBFakeStore()}
	if err := s.consumeEnrollGrant(context.Background(), "x", nil); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("DB without grant store = %v", err)
	}
	fault := &enrollFaultStore{dbFakeStore: newDBFakeStore()}
	s2 := New("t")
	s2.DB = fault
	fault.getErr = errors.New("read failed")
	if err := s2.consumeEnrollGrant(context.Background(), "x", nil); err == nil || !strings.Contains(err.Error(), "read enrollment grant") {
		t.Fatalf("DB read error = %v", err)
	}
	fault.getErr = nil
	if err := s2.consumeEnrollGrant(context.Background(), "missing", nil); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("DB missing = %v", err)
	}
	tok, err := s2.CreateEnrollGrant(context.Background(), time.Hour, []string{"container"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.consumeEnrollGrant(context.Background(), tok, []string{"other"}); err == nil || !strings.Contains(err.Error(), "does not permit label") {
		t.Fatalf("DB label mismatch = %v", err)
	}
	if !s2.enrollGrantOK(context.Background(), tok) {
		t.Fatal("DB label mismatch burned the grant")
	}
	if err := s2.consumeEnrollGrant(context.Background(), tok, []string{"container"}); err != nil {
		t.Fatalf("DB consume = %v", err)
	}
	if err := s2.consumeEnrollGrant(context.Background(), tok, nil); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("DB double consume = %v", err)
	}

	// The durable consume error mapping: ErrNotFound, ErrGrantConsumed,
	// ErrGrantExpired and a generic error.
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"not found", storage.ErrNotFound, "unknown enrollment grant"},
		{"consumed", storage.ErrGrantConsumed, "enrollment grant already used"},
		{"expired", storage.ErrGrantExpired, "enrollment grant expired"},
		{"generic", errors.New("boom"), "consume enrollment grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &enrollFaultStore{dbFakeStore: newDBFakeStore(), consumeErr: tc.err}
			ss := New("t")
			ss.DB = f
			tok, err := ss.CreateEnrollGrant(context.Background(), time.Hour, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = ss.consumeEnrollGrant(context.Background(), tok, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("consume error = %v, want %q", err, tc.want)
			}
		})
	}

	// A durable record that is consumed/expired between the read and the
	// consume is reported with the mapped error.
	exp := time.Now().Add(-time.Minute)
	f2 := &enrollFaultStore{dbFakeStore: newDBFakeStore()}
	f2.dbFakeStore.mu.Lock()
	f2.dbFakeStore.grants[auth.TokenDigest("expired-db")] = storage.EnrollGrantRecord{ExpiresAt: exp}
	f2.dbFakeStore.mu.Unlock()
	s3 := New("t")
	s3.DB = f2
	if err := s3.consumeEnrollGrant(context.Background(), "expired-db", nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired durable grant = %v", err)
	}
}

// TestIDCovLoadEnrollGrantsPaths covers the file loader's branches.
func TestIDCovLoadEnrollGrantsPaths(t *testing.T) {
	s := New("t")
	if err := s.loadEnrollGrants(""); err != nil {
		t.Fatalf("empty dir = %v", err)
	}
	empty := t.TempDir()
	s2 := New("t")
	if err := s2.loadEnrollGrants(empty); err != nil || s2.EnrollGrants == nil {
		t.Fatalf("missing file = %v (map=%v)", err, s2.EnrollGrants)
	}
	// An unreadable path (directory) is an error.
	dirPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirPath, enrollGrantsFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New("t").loadEnrollGrants(dirPath); err == nil {
		t.Fatal("directory as grant file = nil error")
	}
	// A corrupt file is refused.
	corrupt := t.TempDir()
	writeTestFile(t, filepath.Join(corrupt, enrollGrantsFile), []byte("{"))
	if err := New("t").loadEnrollGrants(corrupt); err == nil {
		t.Fatal("corrupt grant file = nil error")
	}
	// Valid state loads, expired grants are pruned and the map is reused.
	good := t.TempDir()
	live := EnrollGrant{ExpiresAt: time.Now().Add(time.Hour), BoundLabels: []string{"a"}}
	stale := EnrollGrant{ExpiresAt: time.Now().Add(-time.Hour)}
	staleJSON, err := json.MarshalIndent(map[string]EnrollGrant{"live": live, "stale": stale}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(good, enrollGrantsFile), staleJSON)
	s3 := New("t")
	s3.EnrollGrants = map[string]EnrollGrant{"keep": live}
	if err := s3.loadEnrollGrants(good); err != nil {
		t.Fatal(err)
	}
	if _, ok := s3.EnrollGrants["live"]; !ok {
		t.Fatal("live grant not loaded")
	}
	if _, ok := s3.EnrollGrants["stale"]; ok {
		t.Fatal("expired grant loaded")
	}
	if _, ok := s3.EnrollGrants["keep"]; !ok {
		t.Fatal("existing map entries were dropped")
	}
}

// TestIDCovPruneEnrollGrantsLocked pins the pruning predicate.
func TestIDCovPruneEnrollGrantsLocked(t *testing.T) {
	s := New("t")
	now := time.Now().UTC()
	s.EnrollGrants = map[string]EnrollGrant{
		"live":    {ExpiresAt: now.Add(time.Minute)},
		"expired": {ExpiresAt: now.Add(-time.Second)},
		"exact":   {ExpiresAt: now},
	}
	s.pruneEnrollGrantsLocked(now)
	if _, ok := s.EnrollGrants["live"]; !ok {
		t.Fatal("live grant pruned")
	}
	if _, ok := s.EnrollGrants["expired"]; ok {
		t.Fatal("expired grant kept")
	}
	if _, ok := s.EnrollGrants["exact"]; ok {
		t.Fatal("grant expiring exactly now kept")
	}
}

// TestIDCovEnrollGrantHTTPEndToEnd proves the grant flow through the real
// handler: a label mismatch never burns the grant, the permitted enrollment
// consumes it exactly once, and a second use is refused.
func TestIDCovEnrollGrantHTTPEndToEnd(t *testing.T) {
	ca, err := runnerpki.NewCA("grant ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := grantServer(t)
	s.RunnerCA = ca
	tok, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"container"})
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-g")
	if err != nil {
		t.Fatal(err)
	}
	csr := base64.StdEncoding.EncodeToString(csrPEM)
	h := s.Handler()

	// A label the grant does not permit is refused and leaves the grant
	// consumable.
	bad := `{"runner_id":"runner-g","csr":"` + csr + `","labels":["gpu"]}`
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", []byte(bad), tok, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unpermitted label = %d: %s", w.Code, w.Body.String())
	}
	if !s.enrollGrantOK(context.Background(), tok) {
		t.Fatal("unpermitted label consumed the grant")
	}
	good := `{"runner_id":"runner-g","csr":"` + csr + `","labels":["container"]}`
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", []byte(good), tok, nil); w.Code != http.StatusOK {
		t.Fatalf("permitted enrollment = %d: %s", w.Code, w.Body.String())
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", []byte(good), tok, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("grant replay = %d, want 401", w.Code)
	}
}

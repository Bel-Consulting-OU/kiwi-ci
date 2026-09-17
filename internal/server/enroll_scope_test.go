package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// grantTestServer builds a memory-mode server with a runner CA and no
// static enrollment token (grant-only enrollment).
func grantTestServer(t *testing.T) *Server {
	t.Helper()
	ca, err := runnerpki.NewCA("grant ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	s.RunnerCA = ca
	s.RunnerEnrollToken = ""
	return s
}

// enrollBodyFor mints an enroll request for the runner with the given
// labels.
func enrollBodyFor(t *testing.T, runnerID string, labels []string) []byte {
	t.Helper()
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR(runnerID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(EnrollRequest{RunnerID: runnerID, CSR: base64.StdEncoding.EncodeToString(csrPEM), Labels: labels})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestEnrollGrantLabelMismatchDoesNotConsumeGrant pins single-use
// consumption to SUCCESSFUL validation: a request missing a bound label is
// refused without burning the grant, in memory and DB mode alike. Before
// the fix the DB path consumed (conditional UPDATE) first and checked the
// labels after, so one wrong-label attempt destroyed the grant.
func TestEnrollGrantLabelMismatchDoesNotConsumeGrant(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := grantTestServer(t)
		raw, err := s.CreateEnrollGrant(time.Hour, []string{"os:macos", "arm64"})
		if err != nil {
			t.Fatal(err)
		}
		h := s.Handler()
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r1", []string{"os:macos"}), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("missing one bound label = %d, want 401", w.Code)
		}
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r2", nil), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("missing all bound labels = %d, want 401", w.Code)
		}
		// The grant is still usable with the full label set.
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r3", []string{"os:macos", "arm64"}), raw, nil); w.Code != http.StatusOK {
			t.Fatalf("grant burned by a rejected attempt: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("runner-tok")
		ca, err := runnerpki.NewCA("grant ca", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		s.RunnerCA = ca
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		raw, err := s.CreateEnrollGrant(time.Hour, []string{"os:macos", "arm64"})
		if err != nil {
			t.Fatal(err)
		}
		h := s.Handler()
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r1", []string{"os:macos"}), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("missing one bound label = %d, want 401", w.Code)
		}
		f.mu.Lock()
		rec := f.grants[auth.TokenDigest(raw)]
		f.mu.Unlock()
		if rec.Consumed {
			t.Fatal("rejected label binding consumed the durable grant")
		}
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r2", []string{"os:macos", "arm64"}), raw, nil); w.Code != http.StatusOK {
			t.Fatalf("durable grant burned by a rejected attempt: %d %s", w.Code, w.Body.String())
		}
		// And a replay now conflicts.
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r3", []string{"os:macos", "arm64"}), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("consumed grant replay = %d, want 401", w.Code)
		}
	})
}

// TestEnrollGrantConcurrentConsumptionMemory proves the memory-mode
// single-use arbitration under concurrency: exactly one enrollment wins.
func TestEnrollGrantConcurrentConsumptionMemory(t *testing.T) {
	s := grantTestServer(t)
	raw, err := s.CreateEnrollGrant(time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	body := enrollBodyFor(t, "runner-x", nil)
	const n = 8
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, raw, nil).Code
		}()
	}
	wg.Wait()
	close(codes)
	wins, losses := 0, 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			wins++
		case http.StatusUnauthorized:
			losses++
		default:
			t.Fatalf("unexpected enroll status %d", code)
		}
	}
	if wins != 1 || losses != n-1 {
		t.Fatalf("concurrent memory consumption: %d winners, %d losers", wins, losses)
	}
}

// TestEnrollGrantGarbageAndExpiredTokens feeds the enrollment tier garbage
// credentials and expired/consumed state: every one must 401.
func TestEnrollGrantGarbageAndExpiredTokens(t *testing.T) {
	s := grantTestServer(t)
	h := s.Handler()
	body := enrollBodyFor(t, "runner-g", nil)
	garbage := []string{
		"",
		" ",
		"not-a-grant",
		strings.Repeat("a", 64),
		strings.Repeat("f", 129),
		"grant\x00with-nul",
		"grant\nwith-newline",
		"GRANTWITHUPPERCASE",
	}
	for _, tok := range garbage {
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, tok, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("garbage grant %q = %d, want 401", tok, w.Code)
		}
	}
	// Expired (memory): forcing the stored expiry into the past refuses.
	raw, err := s.CreateEnrollGrant(time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	g := s.EnrollGrants[auth.TokenDigest(raw)]
	g.ExpiresAt = time.Now().UTC().Add(-time.Second)
	s.EnrollGrants[auth.TokenDigest(raw)] = g
	s.mu.Unlock()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, raw, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired memory grant = %d, want 401", w.Code)
	}
	// Expired (DB) is rejected by the consume path and by the tier gate.
	f := newDBFakeStore()
	dbs := New("runner-tok")
	ca, err := runnerpki.NewCA("grant ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dbs.RunnerCA = ca
	if err := dbs.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	dbRaw, err := dbs.CreateEnrollGrant(time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	rec := f.grants[auth.TokenDigest(dbRaw)]
	rec.ExpiresAt = time.Now().UTC().Add(-time.Second)
	f.grants[auth.TokenDigest(dbRaw)] = rec
	f.mu.Unlock()
	if w := pkiRequest(t, dbs.Handler(), http.MethodPost, "/api/v1/runners/enroll", body, dbRaw, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired DB grant = %d, want 401", w.Code)
	}
}

// grantlessStore hides the optional EnrollGrantStore contract from the
// server while still satisfying the base Store interface.
type grantlessStore struct{ storage.Store }

// TestEnrollGrantDBModeRequiresDurableStore proves DB mode never silently
// falls back to a replica-local memory grant: without the durable store the
// mint refuses and validation denies.
func TestEnrollGrantDBModeRequiresDurableStore(t *testing.T) {
	f := newDBFakeStore()
	s := New("runner-tok")
	s.DB = grantlessStore{Store: f}
	if _, err := s.CreateEnrollGrant(time.Hour, nil); err == nil {
		t.Fatal("DB mode without a durable grant store minted a memory grant")
	}
	if s.enrollGrantOK(strings.Repeat("a", 64)) {
		t.Fatal("DB mode without a durable grant store validated a grant")
	}
	if err := s.consumeEnrollGrant(strings.Repeat("a", 64), nil); err == nil {
		t.Fatal("DB mode without a durable grant store consumed a grant")
	}
	// The grantless base store itself still works for the base contract.
	if err := f.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestEnrollGrantExtraLabelsCannotEscalate documents the (intentional)
// label-binding direction: the request must CARRY every bound label, and
// extra request labels are ignored because enrollment labels are never
// persisted — scheduling attributes come exclusively from the registration
// profile. This is why a superset request cannot escalate, and why it is
// deliberately not rejected.
func TestEnrollGrantExtraLabelsCannotEscalate(t *testing.T) {
	s := grantTestServer(t)
	s.RequireProfiles = true
	createProfile(t, s, model.RunnerProfile{ID: "plain", Labels: []string{"os:linux"}, Capabilities: []string{"container"}, MaxCapacity: 1})
	_, cert := pkiSignRunner(t, s.RunnerCA, "runner-extra")
	bindSerial(t, s, "plain", cert.SerialNumber.Text(16))
	raw, err := s.CreateEnrollGrant(time.Hour, []string{"os:linux"})
	if err != nil {
		t.Fatal(err)
	}
	// Superset request: bound label present plus an extra privileged one.
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		enrollBodyFor(t, "runner-extra", []string{"os:linux", "trusted-production"}), raw, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("superset request with all bound labels = %d, want 200", w.Code)
	}
	// The enrolled identity registers with the PROFILE's labels: the extra
	// enrollment label never becomes a scheduling attribute.
	ri := registerProfiled(t, s, map[string]any{
		"id": "runner-extra", "name": "re", "protocol_min": 3, "protocol_max": 3,
	}, cert)
	if len(ri.Labels) != 1 || ri.Labels[0] != "os:linux" {
		t.Fatalf("enrollment labels leaked into scheduling: %+v", ri.Labels)
	}
	if containsString(ri.Labels, "trusted-production") {
		t.Fatal("extra enrollment label escalated the runner's scheduling labels")
	}
}

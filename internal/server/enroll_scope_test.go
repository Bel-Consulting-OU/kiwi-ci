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
// consumption to SUCCESSFUL validation: a request carrying a label outside
// the grant's complete allowed set is refused without burning the grant, in
// memory and DB mode alike. A request whose labels are all allowed (a
// subset of the allowed set) succeeds. Before the consume-before-check fix
// the DB path consumed (conditional UPDATE) first and checked the labels
// after, so one wrong-label attempt destroyed the grant.
func TestEnrollGrantLabelMismatchDoesNotConsumeGrant(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := grantTestServer(t)
		raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"os:macos", "arm64"})
		if err != nil {
			t.Fatal(err)
		}
		h := s.Handler()
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r1", []string{"os:macos", "trusted-production"}), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("extra label = %d, want 401", w.Code)
		}
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r2", []string{"os:ubuntu"}), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("disallowed label = %d, want 401", w.Code)
		}
		// The grant is still usable with an allowed label subset.
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r3", []string{"os:macos"}), raw, nil); w.Code != http.StatusOK {
			t.Fatalf("grant burned by a rejected attempt: %d %s", w.Code, w.Body.String())
		}
		// And a replay is refused.
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r4", []string{"os:macos"}), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("consumed grant replay = %d, want 401", w.Code)
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
		raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"os:macos", "arm64"})
		if err != nil {
			t.Fatal(err)
		}
		h := s.Handler()
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r1", []string{"os:macos", "arm64", "extra"}), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("extra label = %d, want 401", w.Code)
		}
		f.mu.Lock()
		rec := f.grants[auth.TokenDigest(raw)]
		f.mu.Unlock()
		if rec.Consumed {
			t.Fatal("rejected label binding consumed the durable grant")
		}
		// An allowed subset still works exactly once.
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r2", []string{"os:macos"}), raw, nil); w.Code != http.StatusOK {
			t.Fatalf("durable grant burned by a rejected attempt: %d %s", w.Code, w.Body.String())
		}
		// And a replay now conflicts.
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "r3", []string{"os:macos"}), raw, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("consumed grant replay = %d, want 401", w.Code)
		}
	})
}

// TestEnrollGrantAllowedLabelsContract pins the allowed-label contract: the
// grant's BoundLabels are the COMPLETE ALLOWED set (every requested label
// must appear in it), an empty allowed set is the legacy no-constraint
// grant, and comparison is exact — byte-for-byte, case-sensitive, no
// trimming — matching the runner label grammar (runnerLabelRegexp). Every
// rejection leaves the grant unconsumed and therefore still usable.
func TestEnrollGrantAllowedLabelsContract(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		request []string
		permit  bool
	}{
		{"subset of allowed set", []string{"os:macos", "arm64"}, []string{"os:macos"}, true},
		{"exact allowed set", []string{"os:macos", "arm64"}, []string{"os:macos", "arm64"}, true},
		{"no allowed set accepts any", nil, []string{"anything", "else"}, true},
		{"extra label rejected", []string{"os:macos"}, []string{"os:macos", "trusted-production"}, false},
		{"label outside allowed set rejected", []string{"os:macos"}, []string{"os:linux"}, false},
		{"trailing space is a different label", []string{"os:macos"}, []string{"os:macos "}, false},
		{"leading space in allowed label is a different label", []string{" os:macos"}, []string{"os:macos"}, false},
		{"case is significant", []string{"os:macos"}, []string{"OS:Macos"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := grantTestServer(t)
			raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, tc.allowed)
			if err != nil {
				t.Fatal(err)
			}
			err = s.consumeEnrollGrant(context.Background(), raw, tc.request)
			if tc.permit {
				if err != nil {
					t.Fatalf("allowed request rejected: %v", err)
				}
				if err := s.consumeEnrollGrant(context.Background(), raw, tc.request); err == nil {
					t.Fatal("grant consumed twice")
				}
				return
			}
			if err == nil {
				t.Fatal("disallowed request consumed the grant")
			}
			if !strings.Contains(err.Error(), "grant does not permit label") {
				t.Fatalf("rejection error = %q, want the unpermitted-label message", err)
			}
			// The rejected attempt must leave the grant consumable.
			if err := s.consumeEnrollGrant(context.Background(), raw, tc.allowed); err != nil {
				t.Fatalf("rejection burned the grant: %v", err)
			}
		})
	}
}

// TestEnrollGrantPersistFailureRollsBackConsumption pins the memory-mode
// consume path to all-or-nothing: when persisting the consumed state fails,
// the in-memory mutation is rolled back, no certificate is issued, and the
// on-disk state stays unconsumed — so a restarted server still accepts the
// original grant exactly once.
func TestEnrollGrantPersistFailureRollsBackConsumption(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := runnerpki.NewCA("rollback ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.RunnerCA = ca
	s.RunnerEnrollToken = ""
	raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}

	origPersist := persistEnrollGrantsFunc
	persistEnrollGrantsFunc = func(*Server) error { return errors.New("injected persist failure") }
	t.Cleanup(func() { persistEnrollGrantsFunc = origPersist })

	// A handler enrollment fails on the failed consume and must not issue a
	// certificate.
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll", enrollBodyFor(t, "runner-rb", nil), raw, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("enroll with failing persist = %d, want 401: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "CERTIFICATE") {
		t.Fatalf("certificate issued for a failed consume: %s", w.Body.String())
	}

	// The in-memory mutation was rolled back: the grant is still unused.
	s.mu.Lock()
	g, ok := s.EnrollGrants[auth.TokenDigest(raw)]
	s.mu.Unlock()
	if !ok {
		t.Fatal("failed persist deleted the in-memory grant")
	}
	if g.Used {
		t.Fatal("failed persist left the grant marked used in memory")
	}
	// The failed persist never rewrote the file: on disk the grant is unused.
	onDisk, err := os.ReadFile(filepath.Join(dir, enrollGrantsFile))
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]EnrollGrant
	if err := json.Unmarshal(onDisk, &persisted); err != nil {
		t.Fatal(err)
	}
	if rec, ok := persisted[auth.TokenDigest(raw)]; !ok || rec.Used {
		t.Fatalf("on-disk grant after failed persist = %+v (present=%v)", rec, ok)
	}

	// Simulate a restart over the same data dir: persistence works again and
	// the original token is accepted exactly once.
	persistEnrollGrantsFunc = origPersist
	s2, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.RunnerCA = ca
	s2.RunnerEnrollToken = ""
	s2.mu.Lock()
	loaded, ok := s2.EnrollGrants[auth.TokenDigest(raw)]
	s2.mu.Unlock()
	if !ok || loaded.Used {
		t.Fatalf("restart loaded grant = %+v (present=%v), want unused", loaded, ok)
	}
	if err := s2.consumeEnrollGrant(context.Background(), raw, nil); err != nil {
		t.Fatalf("consume after restart: %v", err)
	}
	if err := s2.consumeEnrollGrant(context.Background(), raw, nil); err == nil {
		t.Fatal("grant consumed twice after restart")
	}
}

// TestEnrollGrantConcurrentConsumptionMemory proves the memory-mode
// single-use arbitration under concurrency: exactly one enrollment wins.
func TestEnrollGrantConcurrentConsumptionMemory(t *testing.T) {
	s := grantTestServer(t)
	raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
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
	raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
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
	dbRaw, err := dbs.CreateEnrollGrant(context.Background(), time.Hour, nil)
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
	if _, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil); err == nil {
		t.Fatal("DB mode without a durable grant store minted a memory grant")
	}
	if s.enrollGrantOK(context.Background(), strings.Repeat("a", 64)) {
		t.Fatal("DB mode without a durable grant store validated a grant")
	}
	if err := s.consumeEnrollGrant(context.Background(), strings.Repeat("a", 64), nil); err == nil {
		t.Fatal("DB mode without a durable grant store consumed a grant")
	}
	// The grantless base store itself still works for the base contract.
	if err := f.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestEnrollGrantExtraLabelsRejected pins the escalation boundary of the
// allowed-label contract: a request carrying a label the grant does not
// permit is refused BEFORE consumption (with a clear error), so the grant
// survives for a legitimate enrollment — and the enrolled runner still
// registers with its PROFILE's labels, because enrollment labels are
// advisory and never become scheduling attributes.
func TestEnrollGrantExtraLabelsRejected(t *testing.T) {
	s := grantTestServer(t)
	s.RequireProfiles = true
	createProfile(t, s, model.RunnerProfile{ID: "plain", Labels: []string{"os:linux"}, Capabilities: []string{"container"}, MaxCapacity: 1})
	_, cert := pkiSignRunner(t, s.RunnerCA, "runner-extra")
	bindSerial(t, s, "plain", cert.SerialNumber.Text(16))
	raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"os:linux"})
	if err != nil {
		t.Fatal(err)
	}
	// Superset request: the extra privileged label is not in the allowed
	// set and must be rejected with the documented error.
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		enrollBodyFor(t, "runner-extra", []string{"os:linux", "trusted-production"}), raw, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("superset request = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), `grant does not permit label "trusted-production"`) {
		t.Fatalf("rejection body = %q, want the unpermitted-label message", w.Body.String())
	}
	// The rejection did not consume the grant: an allowed request enrolls.
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		enrollBodyFor(t, "runner-extra", []string{"os:linux"}), raw, nil); w.Code != http.StatusOK {
		t.Fatalf("allowed enrollment after rejection = %d: %s", w.Code, w.Body.String())
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

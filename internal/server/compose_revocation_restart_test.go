package server

// Revocation x restart composition (FS mode): an enrollment grant, a runner
// disable and its certificate revocation must all survive a control-plane
// restart on the same data dir and stay enforced, and a revocation whose
// durable write FAILED (opaque 503, no acknowledgement) must never be
// resurrected — or prematurely enforced — by the restart.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// composeEnrollRunner enrolls a fresh runner through the HTTP enrollment
// endpoint with the given single-use grant and returns the issued
// certificate.
func composeEnrollRunner(t *testing.T, s *Server, grant, runnerID string) *x509.Certificate {
	t.Helper()
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR(runnerID)
	if err != nil {
		t.Fatal(err)
	}
	body := EnrollRequest{RunnerID: runnerID, CSR: base64.StdEncoding.EncodeToString(csrPEM)}
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll", body, grant, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll %s = %d: %s", runnerID, w.Code, w.Body.String())
	}
	var out EnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return pkiParseCert(t, []byte(out.Certificate))
}

// composeRunnerBearer is the per-runner bearer credential used by the
// restart test.
const composeRunnerBearer = "rev-runner-bearer"

// composeProvisionRunnerBearer installs the per-runner bearer credential
// through the same startup seam production uses (LoadRunnerTokens).
func composeProvisionRunnerBearer(s *Server, runnerID string) {
	s.LoadRunnerTokens(map[string]string{runnerID: auth.TokenDigest(composeRunnerBearer)})
}

// composeRegisterCert registers a runner presenting its certificate under the
// given runner credential (the shared runner token or a per-runner bearer).
func composeRegisterCert(t *testing.T, s *Server, runnerID, bearer string, cert *x509.Certificate) int {
	t.Helper()
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": runnerID, "name": runnerID, "capacity": 1, "protocol_min": 3, "protocol_max": 3},
		bearer, cert)
	return w.Code
}

// TestComposeRevocationAndGrantStateSurviveFSRestart drives enroll -> consume
// -> disable, then restarts the control plane on the same data dir and asserts
// the whole composed state survived: the certificate stays revoked (no
// re-registration, no lease), the disabled flag stays set (bearer polls get no
// lease), and the consumed enrollment grant stays consumed while an unused
// one is still usable exactly once.
func TestComposeRevocationAndGrantStateSurviveFSRestart(t *testing.T) {
	dir := t.TempDir()
	ca, err := runnerpki.NewCA("compose revocation ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.RunnerCA = ca
	// The runner carries a per-runner bearer credential (the production
	// identity shape) in addition to its certificate, so the disabled-runner
	// poll can be driven without a certificate while every certificate path
	// still goes through the revocation check.
	composeProvisionRunnerBearer(s, "rev-runner")

	grantUsed, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := composeEnrollRunner(t, s, grantUsed, "rev-runner")
	serial := cert.SerialNumber.Text(16)
	if code := composeRegisterCert(t, s, "rev-runner", composeRunnerBearer, cert); code != http.StatusOK {
		t.Fatalf("register = %d", code)
	}
	// The consumed grant is already single-use before the restart.
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		EnrollRequest{RunnerID: "nope"}, grantUsed, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("reused grant = %d, want 401", w.Code)
	}
	grantUnused, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Disable: revokes the certificate and cancels leases.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/rev-runner/disable", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	if !crlRevoked(t, s, serial) {
		t.Fatal("serial not revoked before the restart")
	}
	// Already enforced before the restart.
	if code := composeRegisterCert(t, s, "rev-runner", composeRunnerBearer, cert); code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatalf("revoked-cert re-registration before restart = %d", code)
	}
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/rev-runner/next", map[string]any{}, "runner-tok", cert); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked-cert lease before restart = %d", w.Code)
	}
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/rev-runner/next", map[string]any{}, composeRunnerBearer, nil); w.Code != http.StatusNoContent || w.Header().Get("X-Kiwi-Disabled") != "true" {
		t.Fatalf("disabled-runner lease before restart = %d headers=%v", w.Code, w.Header())
	}

	// Restart on the same data dir.
	s2, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.RunnerCA = ca
	composeProvisionRunnerBearer(s2, "rev-runner")

	if !crlRevoked(t, s2, serial) {
		t.Fatal("revocation did not survive the restart")
	}
	s2.mu.Lock()
	ri, ok := s2.runners["rev-runner"]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("runner record did not survive the restart")
	}
	if !ri.Disabled || ri.RevokedAt == nil {
		t.Fatalf("restarted runner = disabled=%v revoked_at=%v, want a revoked disabled runner", ri.Disabled, ri.RevokedAt)
	}
	// No re-registration with the revoked serial, after the restart.
	if code := composeRegisterCert(t, s2, "rev-runner", composeRunnerBearer, cert); code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatalf("revoked-cert re-registration after restart = %d", code)
	}
	// No lease with the revoked certificate, and no lease for the disabled
	// runner on the shared bearer either.
	if w := pkiRequest(t, s2.Handler(), http.MethodPost, "/api/v1/runners/rev-runner/next", map[string]any{}, "runner-tok", cert); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked-cert lease after restart = %d", w.Code)
	}
	w := pkiRequest(t, s2.Handler(), http.MethodPost, "/api/v1/runners/rev-runner/next", map[string]any{}, composeRunnerBearer, nil)
	if w.Code != http.StatusNoContent || w.Header().Get("X-Kiwi-Disabled") != "true" {
		t.Fatalf("disabled-runner lease after restart = %d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Lease-Token") != "" || w.Body.Len() != 0 {
		t.Fatalf("disabled runner received a lease: %s", w.Body.String())
	}

	// The consumed grant stays consumed; the unused grant is still usable
	// exactly once.
	if w := pkiRequest(t, s2.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		EnrollRequest{RunnerID: "nope"}, grantUsed, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("consumed grant reused after restart = %d, want 401", w.Code)
	}
	// The unused grant survived the restart and is consumed exactly once by a
	// real enrollment.
	composeEnrollRunner(t, s2, grantUnused, "second-runner")
	if w := pkiRequest(t, s2.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		EnrollRequest{RunnerID: "nope"}, grantUnused, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("grant reused after its one real enrollment = %d, want 401", w.Code)
	}
}

// TestComposeUnacknowledgedRevocationNeverSurvivesFSRestart composes the
// durable-write seam with the restart: when the disable's snapshot write
// fails, the handler answers an opaque 503, the state rolls back, and a
// restart must find NO revocation (nothing was acknowledged). A later
// successful disable then survives a restart.
func TestComposeUnacknowledgedRevocationNeverSurvivesFSRestart(t *testing.T) {
	const serial = "0c0ffee"
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.runners["runner-a"] = model.Runner{ID: "runner-a", Name: "ra", Capacity: 1, CertSerial: serial}
	perr := s.persistCheckedErrLocked("test.seed")
	s.mu.Unlock()
	if perr != nil {
		t.Fatalf("seed persist: %v", perr)
	}

	restore := fsutil.SetHooks(fsutil.Hooks{FileSync: func(*os.File) error {
		return errors.New("injected file fsync failure")
	}})
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", "")
	restore()
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disable with a failing snapshot write = %d, want 503: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	disabledInMemory := s.runners["runner-a"].Disabled
	s.mu.Unlock()
	if disabledInMemory {
		t.Fatal("unacknowledged disable left the runner disabled in memory")
	}
	if crlRevoked(t, s, serial) {
		t.Fatal("unacknowledged disable left the serial revoked in memory")
	}

	// Restart: the unacknowledged revocation must not be resurrected.
	s2, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	if crlRevoked(t, s2, serial) {
		t.Fatal("restart resurrected a revocation that was never acknowledged")
	}
	s2.mu.Lock()
	ri2, ok := s2.runners["runner-a"]
	s2.mu.Unlock()
	if !ok || ri2.Disabled || ri2.RevokedAt != nil {
		t.Fatalf("restarted runner = %+v, want it to stay in service", ri2)
	}

	// A successful disable is acknowledged and then survives the next
	// restart, so the seam composes in both directions.
	if w := doJSON(t, s2, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("retried disable = %d: %s", w.Code, w.Body.String())
	}
	s3, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !crlRevoked(t, s3, serial) {
		t.Fatal("acknowledged revocation did not survive the restart")
	}
	s3.mu.Lock()
	ri3 := s3.runners["runner-a"]
	s3.mu.Unlock()
	if !ri3.Disabled || ri3.RevokedAt == nil {
		t.Fatalf("restarted runner = %+v, want the acknowledged disable", ri3)
	}
}

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// internalErrorTestSentinel is shaped like a real store failure — a
// filesystem path plus SQL/provider detail — so every test proves such text
// can never reach a client through a hardened 5xx path.
const internalErrorTestSentinel = `/var/lib/kiwi/private/state.db: pq: password authentication failed for user "kiwi"`

// captureInternalErrorLogs points s.Logger at a buffer so tests can assert
// that the detailed error is retained server-side. New does not start
// goroutines, so the buffer only sees this request's synchronous logs.
func captureInternalErrorLogs(s *Server) *bytes.Buffer {
	var buf bytes.Buffer
	s.Logger = logging.NewStructured(&buf)
	return &buf
}

// doInternalErrorReq drives one authenticated request with a fixed
// X-Kiwi-Request-ID through the real middleware chain.
func doInternalErrorReq(t *testing.T, s *Server, method, path, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("X-Kiwi-Request-ID", requestID)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

// assertOpaqueBody pins the client-visible contract: the raw error text is
// absent and the body is the fixed opaque message.
func assertOpaqueBody(t *testing.T, w *httptest.ResponseRecorder, sentinel, want string) {
	t.Helper()
	body := w.Body.String()
	if strings.Contains(body, sentinel) {
		t.Fatalf("internal error detail leaked into the response body: %q", body)
	}
	if strings.Contains(body, "pq:") || strings.Contains(body, "/var/lib/kiwi") {
		t.Fatalf("store detail leaked into the response body: %q", body)
	}
	if body != want+"\n" {
		t.Fatalf("body = %q, want the opaque %q", body, want+"\n")
	}
}

// assertInternalErrorLog finds the "server error" record for requestID and
// pins the diagnostic fields: the detail, the request ID, method, path and
// status.
func assertInternalErrorLog(t *testing.T, logs *bytes.Buffer, requestID, method, path, sentinel string, status int) {
	t.Helper()
	found := false
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v (%q)", err, line)
		}
		if rec["msg"] != "server error" || rec["request_id"] != requestID {
			continue
		}
		found = true
		if rec["method"] != method || rec["path"] != path {
			t.Fatalf("logged method/path = %v %v, want %s %s", rec["method"], rec["path"], method, path)
		}
		if got, _ := rec["status"].(float64); int(got) != status {
			t.Fatalf("logged status = %v, want %d", rec["status"], status)
		}
		if detail, _ := rec["error"].(string); !strings.Contains(detail, sentinel) {
			t.Fatalf("log lost the error detail: %q", detail)
		}
	}
	if !found {
		t.Fatalf("no \"server error\" log record for request_id=%q: %s", requestID, logs.String())
	}
}

// TestInternalErrorStatusAndOpaqueBody pins status preservation (500/502/503)
// and the default opaque body through the helper itself.
func TestInternalErrorStatusAndOpaqueBody(t *testing.T) {
	s := New("secret")
	cases := []struct {
		status int
		msg    string
		want   string
	}{
		{http.StatusInternalServerError, "", "internal server error"},
		{http.StatusBadGateway, "bad gateway", "bad gateway"},
		{http.StatusServiceUnavailable, "state not durable", "state not durable"},
	}
	for i, tc := range cases {
		logs := captureInternalErrorLogs(s)
		rid := "rid-status-" + strconv.Itoa(i)
		path := "/probe/" + strconv.Itoa(tc.status)
		h := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.serverError(w, r, tc.status, errors.New(internalErrorTestSentinel), tc.msg)
		}))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Kiwi-Request-ID", rid)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("status = %d, want %d", w.Code, tc.status)
		}
		assertOpaqueBody(t, w, internalErrorTestSentinel, tc.want)
		assertInternalErrorLog(t, logs, rid, http.MethodGet, path, internalErrorTestSentinel, tc.status)
	}
}

// TestInternalErrorOpaqueBlobsList covers a blobs path: the DB artifact-list
// handler used to echo the store error verbatim.
func TestInternalErrorOpaqueBlobsList(t *testing.T) {
	s := New("secret")
	f := newDBFakeStore()
	f.getRunErr = errors.New(internalErrorTestSentinel)
	s.DB = f
	logs := captureInternalErrorLogs(s)
	const rid = "rid-blobs-1"
	w := doInternalErrorReq(t, s, http.MethodGet, "/api/v1/runs/run-1/artifacts", rid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	assertOpaqueBody(t, w, internalErrorTestSentinel, "internal server error")
	assertInternalErrorLog(t, logs, rid, http.MethodGet, "/api/v1/runs/run-1/artifacts", internalErrorTestSentinel, http.StatusInternalServerError)
}

// TestInternalErrorOpaqueSchedulesList covers a schedules path.
func TestInternalErrorOpaqueSchedulesList(t *testing.T) {
	s := New("secret")
	f := newDBFakeStore()
	f.listSchedulesErr = errors.New(internalErrorTestSentinel)
	s.DB = f
	logs := captureInternalErrorLogs(s)
	const rid = "rid-schedules-1"
	w := doInternalErrorReq(t, s, http.MethodGet, "/api/v1/schedules", rid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	assertOpaqueBody(t, w, internalErrorTestSentinel, "internal server error")
	assertInternalErrorLog(t, logs, rid, http.MethodGet, "/api/v1/schedules", internalErrorTestSentinel, http.StatusInternalServerError)
}

// internalErrorProfileStore injects a ListProfiles failure and delegates
// every other store method to the behavioral fake.
type internalErrorProfileStore struct {
	*dbFakeStore
	listErr error
}

func (f internalErrorProfileStore) ListProfiles(context.Context) ([]model.RunnerProfile, error) {
	return nil, f.listErr
}

// TestInternalErrorOpaqueRunnerProfilesList covers a profiles path.
func TestInternalErrorOpaqueRunnerProfilesList(t *testing.T) {
	s := New("secret")
	s.DB = internalErrorProfileStore{dbFakeStore: newDBFakeStore(), listErr: errors.New(internalErrorTestSentinel)}
	logs := captureInternalErrorLogs(s)
	const rid = "rid-profiles-1"
	w := doInternalErrorReq(t, s, http.MethodGet, "/api/v1/runner-profiles", rid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	assertOpaqueBody(t, w, internalErrorTestSentinel, "internal server error")
	assertInternalErrorLog(t, logs, rid, http.MethodGet, "/api/v1/runner-profiles", internalErrorTestSentinel, http.StatusInternalServerError)
}

// TestInternalErrorOpaqueOIDCConfiguration covers an OIDC path: issuer
// misconfiguration used to be echoed on the public discovery endpoint.
func TestInternalErrorOpaqueOIDCConfiguration(t *testing.T) {
	s := New("secret")
	s.ExternalURL = ""
	logs := captureInternalErrorLogs(s)
	const rid = "rid-oidc-1"
	w := doInternalErrorReq(t, s, http.MethodGet, "/.well-known/openid-configuration", rid)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", w.Code, w.Body.String())
	}
	assertOpaqueBody(t, w, "KIWI_EXTERNAL_URL/--external-url is required for OIDC", "OIDC unavailable")
	assertInternalErrorLog(t, logs, rid, http.MethodGet, "/.well-known/openid-configuration", "KIWI_EXTERNAL_URL/--external-url is required for OIDC", http.StatusServiceUnavailable)
}

// TestInternalErrorOpaqueDeploymentRecord covers a deployment path (500).
func TestInternalErrorOpaqueDeploymentRecord(t *testing.T) {
	s := New("secret")
	f := newDBFakeStore()
	f.getJobErr = errors.New(internalErrorTestSentinel)
	s.DB = f
	logs := captureInternalErrorLogs(s)
	const rid = "rid-deploy-1"
	w := doInternalErrorReq(t, s, http.MethodPost, "/api/v1/jobs/job-1/deployments", rid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	assertOpaqueBody(t, w, internalErrorTestSentinel, "internal server error")
	assertInternalErrorLog(t, logs, rid, http.MethodPost, "/api/v1/jobs/job-1/deployments", internalErrorTestSentinel, http.StatusInternalServerError)
}

// TestInternalErrorOpaqueRunGet covers a generic server.go 500 path.
func TestInternalErrorOpaqueRunGet(t *testing.T) {
	s := New("secret")
	f := newDBFakeStore()
	f.getRunErr = errors.New(internalErrorTestSentinel)
	s.DB = f
	logs := captureInternalErrorLogs(s)
	const rid = "rid-runs-1"
	w := doInternalErrorReq(t, s, http.MethodGet, "/api/v1/runs/run-1", rid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	assertOpaqueBody(t, w, internalErrorTestSentinel, "internal server error")
	assertInternalErrorLog(t, logs, rid, http.MethodGet, "/api/v1/runs/run-1", internalErrorTestSentinel, http.StatusInternalServerError)
}

// raw5xxErrorBodyAllowlist lists file:line exceptions for raw 5xx error
// bodies that are deliberately client-visible. It is intentionally empty:
// every raw site was converted to s.internalError/s.serverError, so any new
// occurrence fails the scan and must be justified here.
var raw5xxErrorBodyAllowlist = map[string]string{}

var (
	httpErrorCallRE = regexp.MustCompile(`http\.Error\(w,`)
	errorBodyRE     = regexp.MustCompile(`\.Error\(\)|fmt\.Sprint`)
	status5xxRE     = regexp.MustCompile(`,\s*(500|502|503|http\.StatusInternalServerError|http\.StatusServiceUnavailable|http\.StatusBadGateway)\)`)
)

// TestInternalErrorNoRaw5xxErrorBodies is the grep-assert for the sweep:
// no non-test file in the package may pass an error's text to http.Error
// with a 5xx status (4xx validation bodies are allowed and untouched).
func TestInternalErrorNoRaw5xxErrorBodies(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			scanned++
			if !httpErrorCallRE.MatchString(line) || !errorBodyRE.MatchString(line) || !status5xxRE.MatchString(line) {
				continue
			}
			key := file + ":" + strconv.Itoa(i+1)
			if _, ok := raw5xxErrorBodyAllowlist[key]; ok {
				continue
			}
			t.Errorf("%s: raw 5xx error body would leak internal detail: %s", key, strings.TrimSpace(line))
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no source lines; the glob is not looking at the package")
	}
}

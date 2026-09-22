package server

// Multiple simultaneous credentials for one identity, composed with the real
// middleware+router: one request matrix is parametrized over both halves of a
// rotation pair and every entry must produce a byte-identical outcome, while
// a weaker second token for the same subject is rejected at add. The control
// credential (the runner token) is included so a matrix that trivially denies
// or trivially allows everything cannot pass.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// composeAuthOutcome is one recorded authorization outcome: status, body and
// every response header the router produced.
type composeAuthOutcome struct {
	Status int
	Body   string
	Header http.Header
}

func composeCapture(t *testing.T, s *Server, method, path, bearer, body string) composeAuthOutcome {
	t.Helper()
	w := doJSON(t, s, method, path, bearer, body)
	header := w.Header().Clone()
	// Every header must match byte for byte EXCEPT the per-request
	// correlation id, which is minted per request by design.
	header.Del("X-Kiwi-Request-Id")
	return composeAuthOutcome{Status: w.Code, Body: w.Body.String(), Header: header}
}

// composeMatrixCase is one entry of the shared request matrix.
type composeMatrixCase struct {
	name   string
	method string
	path   string
	body   string
	// want is the expected status for the rotation pair under test.
	want int
}

func composeRotationMatrix(t *testing.T) []composeMatrixCase {
	t.Helper()
	return []composeMatrixCase{
		{"runs collection", http.MethodGet, "/api/v1/runs", "", http.StatusOK},
		{"runs collection page", http.MethodGet, "/api/v1/runs?limit=1", "", http.StatusOK},
		{"run visible", http.MethodGet, "/api/v1/runs/run-a", "", http.StatusOK},
		{"run invisible", http.MethodGet, "/api/v1/runs/run-b", "", http.StatusForbidden},
		{"submit run", http.MethodPost, "/api/v1/runs", string(composeSubmitBody(t, "https://github.com/o/repo-a.git", "o/repo-a")), http.StatusForbidden},
		{"snapshot listing visible", http.MethodGet, "/api/v1/runs/run-a/snapshots", "", http.StatusForbidden},
		{"snapshot listing invisible", http.MethodGet, "/api/v1/runs/run-b/snapshots", "", http.StatusForbidden},
		{"snapshot download visible", http.MethodGet, "/api/v1/runs/run-a/snapshots/snap-a", "", http.StatusForbidden},
		{"snapshot download invisible", http.MethodGet, "/api/v1/runs/run-b/snapshots/snap-b", "", http.StatusForbidden},
		{"runner registration", http.MethodPost, "/api/v1/runners/register", `{"name":"r","protocol_min":3,"protocol_max":3}`, http.StatusUnauthorized},
		{"test-intelligence visible", http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "", http.StatusOK},
		{"test-intelligence invisible", http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-b", "", http.StatusForbidden},
	}
}

// composeAdminRotationMatrix is the same matrix for an admin-role rotation
// pair: every read surface (including the snapshot routes) is allowed and
// only the runner-tier registration stays closed, because a store principal is
// not a runner credential.
func composeAdminRotationMatrix() []composeMatrixCase {
	return []composeMatrixCase{
		{"runs collection", http.MethodGet, "/api/v1/runs", "", http.StatusOK},
		{"runs collection page", http.MethodGet, "/api/v1/runs?limit=1", "", http.StatusOK},
		{"run visible", http.MethodGet, "/api/v1/runs/run-a", "", http.StatusOK},
		{"run invisible", http.MethodGet, "/api/v1/runs/run-b", "", http.StatusOK},
		{"snapshot listing visible", http.MethodGet, "/api/v1/runs/run-a/snapshots", "", http.StatusOK},
		{"snapshot listing invisible", http.MethodGet, "/api/v1/runs/run-b/snapshots", "", http.StatusOK},
		{"snapshot download visible", http.MethodGet, "/api/v1/runs/run-a/snapshots/snap-a", "", http.StatusOK},
		{"snapshot download invisible", http.MethodGet, "/api/v1/runs/run-b/snapshots/snap-b", "", http.StatusOK},
		{"runner registration", http.MethodPost, "/api/v1/runners/register", `{"name":"r","protocol_min":3,"protocol_max":3}`, http.StatusUnauthorized},
		{"test-intelligence visible", http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "", http.StatusOK},
		{"test-intelligence invisible", http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-b", "", http.StatusOK},
	}
}

// composeSubmitBody renders a submission that binds to the given repository.
func composeSubmitBody(t *testing.T, repoURL, fullName string) []byte {
	t.Helper()
	b, err := json.Marshal(SubmitRun{
		RepoURL:      repoURL,
		RepoFullName: fullName,
		Ref:          "refs/heads/main",
		SHA:          "abc123",
		Event:        "push",
		Pipeline:     smokePipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// composeSeedSnapshot writes a real archive file and installs the matching
// in-memory snapshot record for the run.
func composeSeedSnapshot(t *testing.T, s *Server, id, runID string, body []byte) model.SnapshotRecord {
	t.Helper()
	path := filepath.Join(t.TempDir(), id+".tar.gz")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	rec := model.SnapshotRecord{
		ID: id, RunID: runID, JobID: "job-" + runID, JobKey: "build", Path: path,
		Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	s.snapshots[id] = rec
	s.mu.Unlock()
	return rec
}

// composeRotationMatrixServer installs a rotation pair (read on repo-a only)
// and seeds one run per repository plus one snapshot record per run.
func composeRotationMatrixServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.runs["run-a"] = model.Run{ID: "run-a", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusSuccess, CreatedAt: now}
	s.runs["run-b"] = model.Run{ID: "run-b", Repo: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b", Status: model.StatusSuccess, CreatedAt: now}
	s.mu.Unlock()
	composeSeedSnapshot(t, s, "snap-a", "run-a", []byte("archive-a"))
	composeSeedSnapshot(t, s, "snap-b", "run-b", []byte("archive-b"))
	return s
}

// TestComposeRotationIdenticalAuthorizationMatrixMemory runs the request
// matrix over both halves of a repository-scoped rotation pair and asserts
// byte-identical outcomes on every entry, plus the expected authorization
// verdict, plus the runner-token control on the runner-tier entry.
func TestComposeRotationIdenticalAuthorizationMatrixMemory(t *testing.T) {
	s := composeRotationMatrixServer(t)
	for raw, p := range map[string]auth.Principal{
		"rot-a": {Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}}},
		"rot-b": {Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}}},
	} {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range composeRotationMatrix(t) {
		a := composeCapture(t, s, tc.method, tc.path, "rot-a", tc.body)
		b := composeCapture(t, s, tc.method, tc.path, "rot-b", tc.body)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: outcomes differ:\nrot-a: %d %q %v\nrot-b: %d %q %v",
				tc.name, a.Status, a.Body, a.Header, b.Status, b.Body, b.Header)
		}
		if a.Status != tc.want {
			t.Fatalf("%s = %d, want %d: %s", tc.name, a.Status, tc.want, a.Body)
		}
	}

	// Control: the runner token clears the runner-tier registration entry the
	// store principals are refused, so the matrix is not trivially denying.
	control := composeCapture(t, s, http.MethodPost, "/api/v1/runners/register", "runner-tok", `{"name":"r","protocol_min":3,"protocol_max":3}`)
	if control.Status != http.StatusOK {
		t.Fatalf("runner-token registration = %d, want 200: %s", control.Status, control.Body)
	}
	// The 200s are real answers, not empty pages: the visible run is served
	// and the invisible one is absent, for both halves.
	for _, tok := range []string{"rot-a", "rot-b"} {
		body := composeCapture(t, s, http.MethodGet, "/api/v1/runs", tok, "").Body
		if !strings.Contains(body, `"run-a"`) || strings.Contains(body, `"run-b"`) {
			t.Fatalf("%s runs collection body = %s", tok, body)
		}
	}

	// A weaker token for the same subject is rejected at add, and the
	// surviving pair still produces identical outcomes.
	weak := auth.Principal{Subject: "svc-rotation", Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true, ArtifactRead: true}}}
	if err := s.AuthStore.AddToken("weak", weak); err == nil {
		t.Fatal("weaker same-subject token was accepted")
	}
	if _, ok := s.AuthStore.Authenticate("weak"); ok {
		t.Fatal("rejected weaker token authenticates")
	}
	a := composeCapture(t, s, http.MethodGet, "/api/v1/runs", "rot-a", "")
	b := composeCapture(t, s, http.MethodGet, "/api/v1/runs", "rot-b", "")
	if !reflect.DeepEqual(a, b) || a.Status != http.StatusOK {
		t.Fatalf("pair after rejected add: %d/%d", a.Status, b.Status)
	}
}

// TestComposeAdminRotationIdenticalAuthorizationMatrixMemory is the admin
// counterpart: both halves of an admin-role rotation pair receive the same
// 200s on every read surface and the same 401 on the runner-tier entry.
func TestComposeAdminRotationIdenticalAuthorizationMatrixMemory(t *testing.T) {
	s := composeRotationMatrixServer(t)
	admin := auth.Principal{Subject: "svc-admin-rotation", Roles: []auth.Role{auth.RoleAdmin}}
	for _, raw := range []string{"adm-1", "adm-2"} {
		if err := s.AuthStore.AddToken(raw, admin); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range composeAdminRotationMatrix() {
		a := composeCapture(t, s, tc.method, tc.path, "adm-1", tc.body)
		b := composeCapture(t, s, tc.method, tc.path, "adm-2", tc.body)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: outcomes differ:\nadm-1: %d %q %v\nadm-2: %d %q %v",
				tc.name, a.Status, a.Body, a.Header, b.Status, b.Body, b.Header)
		}
		if a.Status != tc.want {
			t.Fatalf("%s = %d, want %d: %s", tc.name, a.Status, tc.want, a.Body)
		}
	}
	// The admin pair really did receive the snapshot archives, not an empty
	// 200: the download body is the seeded archive.
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-a/snapshots/snap-a", "adm-1", "")
	if w.Code != http.StatusOK || w.Body.String() != "archive-a" {
		t.Fatalf("admin snapshot download = %d %q", w.Code, w.Body.String())
	}
}

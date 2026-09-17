package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// profileLabelJob submits a run whose single job requires the given runner
// label and container runtime.
func profileLabelJob(t *testing.T, s *Server, repo, label string) {
	t.Helper()
	run := SubmitRun{RepoURL: repo, Ref: "main", Pipeline: `version: 1
jobs:
  build:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    placement:
      labels: [` + label + `]
    steps:
      - run: echo hi
`}
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runs", run, "admin-tok", nil); w.Code != http.StatusAccepted {
		t.Fatalf("submit run for label %q: %d %s", label, w.Code, w.Body.String())
	}
}

// registerProfiled registers a runner through the HTTP API (optionally
// carrying a TLS peer certificate) and returns the stored record.
func registerProfiled(t *testing.T, s *Server, body map[string]any, peer *x509.Certificate) model.Runner {
	t.Helper()
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register", body, "runner-tok", peer)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	return ri
}

// TestProfileBindingFourCombinations pins the profile binding matrix:
// {mTLS, bearer} × {profile bound, no profile}. The profile is selected
// only by the certificate serial the request is ACTUALLY authenticated
// with, and a mismatch never leaks another runner's profile.
func TestProfileBindingFourCombinations(t *testing.T) {
	ca, err := runnerpki.NewCA("matrix ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("mtls with profile", func(t *testing.T) {
		s := adminProfileServer(t)
		s.RunnerCA = ca
		createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 2})
		_, certA := pkiSignRunner(t, ca, "runner-a")
		bindSerial(t, s, "p", certA.SerialNumber.Text(16))
		ri := registerProfiled(t, s, map[string]any{"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3, "labels": []string{"spoofed"}, "cert_serial": "0deadbeef"}, certA)
		if len(ri.Labels) != 1 || ri.Labels[0] != "container" || ri.Capacity != 2 || ri.CertSerial != certA.SerialNumber.Text(16) {
			t.Fatalf("mTLS profile binding wrong: %+v", ri)
		}
	})
	t.Run("mtls without profile", func(t *testing.T) {
		s := adminProfileServer(t)
		s.RunnerCA = ca
		_, certA := pkiSignRunner(t, ca, "runner-a")
		ri := registerProfiled(t, s, map[string]any{"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3, "labels": []string{"self"}}, certA)
		if len(ri.Labels) != 0 || ri.Capacity != 0 {
			t.Fatalf("unprofiled mTLS runner must register empty: %+v", ri)
		}
		_ = certA
	})
	t.Run("mtls serial mismatch never selects another profile", func(t *testing.T) {
		s := adminProfileServer(t)
		s.RunnerCA = ca
		createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 2})
		_, certA := pkiSignRunner(t, ca, "runner-a")
		_, certB := pkiSignRunner(t, ca, "runner-b")
		bindSerial(t, s, "p", certB.SerialNumber.Text(16))
		// Runner A presents B's serial in the payload: the peer cert
		// serial must win, so no profile is applied.
		ri := registerProfiled(t, s, map[string]any{"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3, "cert_serial": certB.SerialNumber.Text(16)}, certA)
		if len(ri.Labels) != 0 || ri.Capacity != 0 || ri.CertSerial != certA.SerialNumber.Text(16) {
			t.Fatalf("payload serial overrode the peer certificate serial: %+v", ri)
		}
	})
	t.Run("bearer with profile", func(t *testing.T) {
		s := adminProfileServer(t)
		createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 2})
		bindSerial(t, s, "p", "0abc")
		ri := registerProfiled(t, s, map[string]any{"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3, "cert_serial": "0abc", "labels": []string{"spoofed"}}, nil)
		if len(ri.Labels) != 1 || ri.Labels[0] != "container" || ri.Capacity != 2 || ri.CertSerial != "0abc" {
			t.Fatalf("bearer profile binding wrong: %+v", ri)
		}
	})
	t.Run("bearer without profile", func(t *testing.T) {
		s := adminProfileServer(t)
		ri := registerProfiled(t, s, map[string]any{"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3, "cert_serial": "0nope", "labels": []string{"self"}}, nil)
		// The serial is stored as the (currently unbound) profile key, but
		// it grants nothing: no labels, no capacity, no rates.
		if len(ri.Labels) != 0 || ri.Capacity != 0 || ri.CertSerial != "0nope" {
			t.Fatalf("unbound bearer serial must register empty: %+v", ri)
		}
	})
	t.Run("bearer serial owned by another runner is not honored", func(t *testing.T) {
		s := adminProfileServer(t)
		s.LoadRunnerTokens(map[string]string{
			"runner-a": auth.TokenDigest("token-a"),
			"runner-b": auth.TokenDigest("token-b"),
		})
		createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 2})
		bindSerial(t, s, "p", "0owned")
		// Runner B legitimately claims the serial first.
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
			map[string]any{"id": "runner-b", "name": "rb", "protocol_min": 3, "protocol_max": 3, "cert_serial": "0owned"}, "token-b", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("runner-b register: %d %s", w.Code, w.Body.String())
		}
		var rb model.Runner
		if err := json.Unmarshal(w.Body.Bytes(), &rb); err != nil {
			t.Fatal(err)
		}
		if len(rb.Labels) != 1 || rb.CertSerial != "0owned" {
			t.Fatalf("runner-b profile not applied: %+v", rb)
		}
		// Runner A presents B's serial: must NOT inherit the profile.
		w = pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
			map[string]any{"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3, "cert_serial": "0owned"}, "token-a", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("runner-a register: %d %s", w.Code, w.Body.String())
		}
		var ra model.Runner
		if err := json.Unmarshal(w.Body.Bytes(), &ra); err != nil {
			t.Fatal(err)
		}
		if len(ra.Labels) != 0 || ra.Capacity != 0 || ra.CertSerial != "" {
			t.Fatalf("runner-a stole runner-b's profile through the serial: %+v", ra)
		}
		// B's ownership is untouched.
		rbo, err := s.getRunnerForTest("runner-b")
		if err != nil || rbo.CertSerial != "0owned" {
			t.Fatalf("runner-b serial ownership changed: %+v err=%v", rbo, err)
		}
	})
}

// TestProfileEditShrinksLeaseAuthorizationMemory proves a profile edit is
// live at the NEXT lease decision (labels, capabilities and capacity), and
// that a deleted profile fails closed.
func TestProfileEditShrinksLeaseAuthorizationMemory(t *testing.T) {
	s := adminProfileServer(t)
	createProfile(t, s, model.RunnerProfile{
		ID: "p", Labels: []string{"container"}, Capabilities: []string{"native", "container"},
		MaxCapacity: 3,
	})
	bindSerial(t, s, "p", "0live")
	ri := registerProfiled(t, s, map[string]any{"id": "runner-live", "name": "rl", "protocol_min": 3, "protocol_max": 3, "cert_serial": "0live", "capabilities": []string{"native", "container"}}, nil)
	if ri.Capacity != 3 {
		t.Fatalf("registration capacity = %d", ri.Capacity)
	}

	// Baseline: a container job with the profile label leases.
	profileLabelJob(t, s, "https://github.com/o/r.git", "container")
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/runner-live/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusOK {
		t.Fatalf("baseline lease: %d %s", w.Code, w.Body.String())
	}

	// Shrink: labels change and container is withdrawn.
	updated := model.RunnerProfile{
		ID: "p", Labels: []string{"other"}, Capabilities: []string{"tart"},
		MaxCapacity: 3,
	}
	body, err := json.Marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/p", "admin-tok", string(body)); w.Code != http.StatusOK {
		t.Fatalf("update profile: %d %s", w.Code, w.Body.String())
	}

	// A new container job with the OLD label must no longer lease.
	profileLabelJob(t, s, "https://github.com/o/r2.git", "container")
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/runner-live/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusNoContent {
		t.Fatalf("shrunken label still leased: %d %s", w.Code, w.Body.String())
	}
	// A job with the NEW label but container runtime must not lease: the
	// capability was withdrawn too.
	profileLabelJob(t, s, "https://github.com/o/r3.git", "other")
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/runner-live/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusNoContent {
		t.Fatalf("withdrawn container capability still leased: %d %s", w.Code, w.Body.String())
	}
	// Deleted profile: fail closed with capacity 0 (no lease at all).
	s.mu.Lock()
	delete(s.profiles, "p")
	s.mu.Unlock()
	profileLabelJob(t, s, "https://github.com/o/r4.git", "other")
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/runner-live/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusNoContent {
		t.Fatalf("deleted profile still leased: %d %s", w.Code, w.Body.String())
	}
}

// TestProfileEditShrinksLeaseAuthorizationDB is the DB-mode twin: the same
// edit must be reflected by the durable lease predicate, and a deleted
// profile row must deny capacity.
func TestProfileEditShrinksLeaseAuthorizationDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	s.RequireProfiles = true
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	createProfile(t, s, model.RunnerProfile{
		ID: "p", Labels: []string{"container"}, Capabilities: []string{"container"},
		MaxCapacity: 2,
	})
	bindSerial(t, s, "p", "0db")
	registerProfiled(t, s, map[string]any{"id": "runner-db", "name": "rd", "protocol_min": 3, "protocol_max": 3, "cert_serial": "0db", "capabilities": []string{"container"}}, nil)

	profileLabelJob(t, s, "https://github.com/o/db1.git", "container")
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/runner-db/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusOK {
		t.Fatalf("baseline DB lease: %d %s", w.Code, w.Body.String())
	}
	// Shrink the live profile row: label changes.
	updated := model.RunnerProfile{ID: "p", Labels: []string{"other"}, Capabilities: []string{"container"}, MaxCapacity: 2}
	if err := s.upsertProfile(t.Context(), updated); err != nil {
		t.Fatal(err)
	}
	profileLabelJob(t, s, "https://github.com/o/db2.git", "container")
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/runner-db/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusNoContent {
		t.Fatalf("DB shrunken label still leased: %d %s", w.Code, w.Body.String())
	}
	// Delete the profile row entirely: capacity 0, still nothing leasable
	// even with the new label matching the registered snapshot.
	profileLabelJob(t, s, "https://github.com/o/db3.git", "other")
	f.mu.Lock()
	delete(f.profiles, "p")
	f.mu.Unlock()
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/runner-db/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusNoContent {
		t.Fatalf("deleted DB profile still leased: %d %s", w.Code, w.Body.String())
	}
}

// getRunnerForTest resolves a runner from the memory map or the store.
func (s *Server) getRunnerForTest(id string) (model.Runner, error) {
	if s.DB != nil {
		return s.DB.GetRunner(context.Background(), id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ri, ok := s.runners[id]
	if !ok {
		return model.Runner{}, errNotFoundForTest
	}
	return ri, nil
}

var errNotFoundForTest = &testNotFoundError{}

type testNotFoundError struct{}

func (*testNotFoundError) Error() string { return "not found" }

// listErrStore injects a ListRunners failure while satisfying the base
// storage contract.
type listErrStore struct {
	*dbFakeStore
}

func (listErrStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	return nil, errListRunnersForTest
}

var errListRunnersForTest = errors.New("list runners down")

// TestBearerSerialOwnershipLookupFailsClosed proves the profile binding is
// only granted when serial ownership can be POSITIVELY verified as absent
// or self: a store that cannot answer the ownership question yields no
// profile instead of trusting the client-asserted serial.
func TestBearerSerialOwnershipLookupFailsClosed(t *testing.T) {
	f := newDBFakeStore()
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	s.RequireProfiles = true
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 2})
	bindSerial(t, s, "p", "0owned2")
	if err := s.ProvisionRunnerTokensDB(context.Background(), map[string]string{"runner-a": auth.TokenDigest("token-a")}); err != nil {
		t.Fatal(err)
	}
	// Swap in a store that can still resolve tokens but fails the
	// ownership scan.
	s.DB = listErrStore{dbFakeStore: f}

	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3, "cert_serial": "0owned2"}, "token-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register with ownership lookup outage = %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if len(ri.Labels) != 0 || ri.Capacity != 0 || ri.CertSerial != "" {
		t.Fatalf("ownership outage granted the profile: %+v", ri)
	}
}

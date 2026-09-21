package server

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// idcovStoreOnly hides the optional ProfileStore methods of the fake store:
// embedding the storage.Store interface exposes only the base contract, so
// the profile helpers see a store without profile support.
type idcovStoreOnly struct{ storage.Store }

// TestIDCovValidateRunnerProfile walks the profile validator.
func TestIDCovValidateRunnerProfile(t *testing.T) {
	valid := &model.RunnerProfile{
		ID:           "macos-builders",
		Labels:       []string{"container", "macos-14"},
		Region:       "eu.west-1",
		MaxCapacity:  4,
		Capabilities: []string{"native", "container", "tart"},
		Repositories: []string{"github.com/acme/service"},
		CostPerHour:  1.5,
		PowerWatts:   42,
	}
	if err := validateRunnerProfile(valid); err != nil {
		t.Fatalf("valid profile = %v", err)
	}
	cases := []struct {
		name string
		p    *model.RunnerProfile
		want string
	}{
		{"nil", nil, "runner profile is required"},
		{"empty id", &model.RunnerProfile{}, "invalid profile id"},
		{"dot-leading id", &model.RunnerProfile{ID: ".bad"}, "invalid profile id"},
		{"overlong id", &model.RunnerProfile{ID: strings.Repeat("a", 65)}, "invalid profile id"},
		{"bad label", &model.RunnerProfile{ID: "p", Labels: []string{"bad label"}}, "invalid runner label"},
		{"bad region", &model.RunnerProfile{ID: "p", Region: "bad region"}, "invalid runner region"},
		{"negative capacity", &model.RunnerProfile{ID: "p", MaxCapacity: -1}, "max_capacity must be in"},
		{"over capacity", &model.RunnerProfile{ID: "p", MaxCapacity: maxRunnerCapacity + 1}, "max_capacity must be in"},
		{"negative max cpu", &model.RunnerProfile{ID: "p", MaxCPU: -0.5}, "max_cpu must not be negative"},
		{"negative max memory", &model.RunnerProfile{ID: "p", MaxMemory: -1}, "max_memory must not be negative"},
		{"negative max disk", &model.RunnerProfile{ID: "p", MaxDisk: -1}, "max_disk must not be negative"},
		{"negative max pids", &model.RunnerProfile{ID: "p", MaxPIDs: -1}, "max_pids must not be negative"},
		{"bad capability", &model.RunnerProfile{ID: "p", Capabilities: []string{"gpu"}}, "invalid runner capability"},
		{"empty repository", &model.RunnerProfile{ID: "p", Repositories: []string{"  "}}, "invalid empty repository"},
		{"nan cost", &model.RunnerProfile{ID: "p", CostPerHour: math.NaN()}, "cost_per_hour"},
		{"inf cost", &model.RunnerProfile{ID: "p", CostPerHour: math.Inf(1)}, "cost_per_hour"},
		{"negative cost", &model.RunnerProfile{ID: "p", CostPerHour: -0.1}, "cost_per_hour"},
		{"nan power", &model.RunnerProfile{ID: "p", PowerWatts: math.NaN()}, "power_watts"},
		{"negative power", &model.RunnerProfile{ID: "p", PowerWatts: -1}, "power_watts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRunnerProfile(tc.p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateRunnerProfile = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestIDCovProfileStoreMemoryPaths covers the in-memory profile CRUD,
// including nil-map initialization, not-found and the serial binding.
func TestIDCovProfileStoreMemoryPaths(t *testing.T) {
	ctx := context.Background()
	s := &Server{}
	if _, err := s.getProfile(ctx, "missing"); err == nil {
		t.Fatal("getProfile on empty server = nil error")
	}
	if _, err := s.listProfiles(ctx); err != nil {
		t.Fatalf("listProfiles on empty server = %v", err)
	}
	p := model.RunnerProfile{ID: "p1", MaxCapacity: 1}
	if err := s.upsertProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	if s.profiles == nil {
		t.Fatal("upsertProfile did not initialize the map")
	}
	got, err := s.getProfile(ctx, "p1")
	if err != nil || got.ID != "p1" {
		t.Fatalf("getProfile = %+v, %v", got, err)
	}
	list, err := s.listProfiles(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("listProfiles = %v, %v", list, err)
	}
	if err := s.bindCertProfile(ctx, "serial-1", "missing"); err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("bind to unknown profile = %v", err)
	}
	if err := s.bindCertProfile(ctx, "serial-1", "p1"); err != nil {
		t.Fatal(err)
	}
	if s.certProfiles == nil {
		t.Fatal("bindCertProfile did not initialize the link map")
	}
	bound, ok, err := s.profileForSerial(ctx, "serial-1")
	if err != nil || !ok || bound.ID != "p1" {
		t.Fatalf("profileForSerial = %+v %v %v", bound, ok, err)
	}
	if _, ok, err := s.profileForSerial(ctx, ""); err != nil || ok {
		t.Fatalf("empty serial = ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.profileForSerial(ctx, "unbound"); err != nil || ok {
		t.Fatalf("unbound serial = ok=%v err=%v", ok, err)
	}
	// A link whose profile vanished resolves as unbound.
	s.mu.Lock()
	s.certProfiles["dangling"] = "gone"
	s.mu.Unlock()
	if _, ok, err := s.profileForSerial(ctx, "dangling"); err != nil || ok {
		t.Fatalf("dangling link = ok=%v err=%v", ok, err)
	}
}

// TestIDCovProfileStoreUnsupported covers every refusal when the DB does not
// implement storage.ProfileStore.
func TestIDCovProfileStoreUnsupported(t *testing.T) {
	ctx := context.Background()
	s := New("t")
	s.DB = idcovStoreOnly{Store: newDBFakeStore()}
	if err := s.upsertProfile(ctx, model.RunnerProfile{ID: "p"}); err == nil {
		t.Fatal("upsertProfile without ProfileStore = nil error")
	}
	if _, err := s.getProfile(ctx, "p"); err == nil {
		t.Fatal("getProfile without ProfileStore = nil error")
	}
	if _, err := s.listProfiles(ctx); err == nil {
		t.Fatal("listProfiles without ProfileStore = nil error")
	}
	if _, ok, err := s.profileForSerial(ctx, "serial"); err != nil || ok {
		t.Fatalf("profileForSerial without ProfileStore = ok=%v err=%v", ok, err)
	}
	s.mu.Lock()
	s.profiles["p"] = model.RunnerProfile{ID: "p"}
	s.mu.Unlock()
	if err := s.bindCertProfile(ctx, "serial", "p"); err == nil {
		t.Fatal("bindCertProfile without ProfileStore = nil error")
	}
	// A profile lookup error other than not-found is propagated unchanged.
	if err := s.bindCertProfile(ctx, "serial", "absent"); err == nil {
		t.Fatal("bindCertProfile to unknown profile = nil error")
	}
}

// TestIDCovProfileHandlersHTTP covers the profile HTTP handlers: auth
// refusals, malformed bodies, not-found, validation and success paths.
func TestIDCovProfileHandlersHTTP(t *testing.T) {
	// A read-role principal may not manage profiles.
	restricted := storeServer(t, "", map[string]auth.Principal{
		"read-token": {Subject: "reader", Roles: []auth.Role{auth.RoleRead}},
	})
	c := newTestClient(t, restricted.Handler(), "read-token")
	if w := c.do(http.MethodPost, "/api/v1/runner-profiles", map[string]any{"id": "p"}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("create without policy_manage = %d, want 403", w.Code)
	}
	if w := c.do(http.MethodGet, "/api/v1/runner-profiles/p", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("get without policy_manage = %d, want 403", w.Code)
	}
	if w := c.do(http.MethodGet, "/api/v1/runner-profiles", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("list without policy_manage = %d, want 403", w.Code)
	}
	if w := c.do(http.MethodPut, "/api/v1/runner-profiles/p", map[string]any{"id": "p"}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("update without policy_manage = %d, want 403", w.Code)
	}
	if w := c.do(http.MethodPut, "/api/v1/runner-profiles/p/cert/s1", map[string]any{}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("bind without policy_manage = %d, want 403", w.Code)
	}

	s := New("admin")
	// Malformed JSON.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "admin", `{`); w.Code != http.StatusBadRequest {
		t.Fatalf("create bad json = %d", w.Code)
	}
	// Validation failure.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "admin", `{"id":"bad id"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("create invalid profile = %d", w.Code)
	}
	// Minted ID when none is supplied.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "admin", `{"max_capacity":2}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create minted = %d: %s", w.Code, w.Body.String())
	}
	var created model.RunnerProfile
	decodeJSONBody(t, w, &created)
	if created.ID == "" {
		t.Fatal("create did not mint an id")
	}
	// Lookup, list, update.
	if got := doJSON(t, s, http.MethodGet, "/api/v1/runner-profiles/"+created.ID, "admin", ""); got.Code != http.StatusOK {
		t.Fatalf("get = %d", got.Code)
	}
	if got := doJSON(t, s, http.MethodGet, "/api/v1/runner-profiles", "admin", ""); got.Code != http.StatusOK {
		t.Fatalf("list = %d", got.Code)
	}
	if got := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/"+created.ID, "admin", `{"max_capacity":3}`); got.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", got.Code, got.Body.String())
	}
	if got := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/"+created.ID, "admin", `{"max_capacity":-1}`); got.Code != http.StatusBadRequest {
		t.Fatalf("update invalid = %d", got.Code)
	}
	// Unknown profile: GET/PUT are 404, bind is 400.
	if got := doJSON(t, s, http.MethodGet, "/api/v1/runner-profiles/ghost", "admin", ""); got.Code != http.StatusNotFound {
		t.Fatalf("get unknown = %d", got.Code)
	}
	if got := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/ghost", "admin", `{"max_capacity":1}`); got.Code != http.StatusNotFound {
		t.Fatalf("update unknown = %d", got.Code)
	}
	if got := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/ghost/cert/s1", "admin", ""); got.Code != http.StatusBadRequest {
		t.Fatalf("bind unknown profile = %d", got.Code)
	}
	// Binding an existing profile succeeds.
	if got := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/"+created.ID+"/cert/serial-9", "admin", ""); got.Code != http.StatusOK {
		t.Fatalf("bind = %d: %s", got.Code, got.Body.String())
	}

	// Direct handler calls cover the path-value guards the mux cannot reach.
	empty := httptest.NewRequest(http.MethodPut, "/api/v1/runner-profiles/", strings.NewReader("{}"))
	empty.SetPathValue("id", "")
	w2 := httptest.NewRecorder()
	s.updateRunnerProfile(w2, empty)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("update with empty id = %d, want 400", w2.Code)
	}
	noserial := httptest.NewRequest(http.MethodPut, "/api/v1/runner-profiles/p/cert/", nil)
	noserial.SetPathValue("id", created.ID)
	noserial.SetPathValue("serial", "  ")
	w3 := httptest.NewRecorder()
	s.bindRunnerProfileCert(w3, noserial)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("bind with empty serial = %d, want 400", w3.Code)
	}
}

// TestIDCovProfileHandlerStoreFailures covers the 500 branches of the
// profile handlers when the store rejects the operation.
func TestIDCovProfileHandlerStoreFailures(t *testing.T) {
	s := New("admin")
	s.DB = idcovStoreOnly{Store: newDBFakeStore()}
	h := s.Handler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/runner-profiles", strings.NewReader(`{"id":"p1"}`))
	r.Header.Set("Authorization", "Bearer admin")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("create with unsupported store = %d, want 500", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runner-profiles/p1", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("get with unsupported store = %d, want 500", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runner-profiles", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("list with unsupported store = %d, want 500", w.Code)
	}
	// Update first resolves the profile, which fails with the unsupported
	// store before validation.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/p1", "admin", `{"max_capacity":1}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("update with unsupported store = %d, want 500", w.Code)
	}
}

// TestIDCovProfileDBRoundTrip covers the ProfileStore-backed branches with
// the fake store.
func TestIDCovProfileDBRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("admin")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	p := model.RunnerProfile{ID: "dbp", MaxCapacity: 2}
	if err := s.upsertProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.getProfile(ctx, "dbp"); err != nil {
		t.Fatal(err)
	}
	if list, err := s.listProfiles(ctx); err != nil || len(list) != 1 {
		t.Fatalf("listProfiles = %v, %v", list, err)
	}
	if err := s.bindCertProfile(ctx, "db-serial", "dbp"); err != nil {
		t.Fatal(err)
	}
	if bound, ok, err := s.profileForSerial(ctx, "db-serial"); err != nil || !ok || bound.ID != "dbp" {
		t.Fatalf("profileForSerial = %+v %v %v", bound, ok, err)
	}
	if _, ok, err := s.profileForSerial(ctx, "unbound-db"); err != nil || ok {
		t.Fatalf("unbound serial = ok=%v err=%v", ok, err)
	}
}

// decodeJSONBody decodes a recorder body into v, failing the test on error.
func decodeJSONBody(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := jsonUnmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode body: %v (%s)", err, w.Body.String())
	}
}

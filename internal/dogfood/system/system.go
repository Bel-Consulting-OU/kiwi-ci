package system

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runner"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// SystemConfig configures one System launch. Tokens are distinct so the
// harness proves the admin/runner tier split instead of collapsing every
// principal onto one shared secret.
type SystemConfig struct {
	// RunnerToken authenticates runner-tier routes (register/next/complete).
	RunnerToken string
	// AdminToken authenticates admin-tier routes (submit, run/job queries,
	// attestation). Defaults to RunnerToken when empty.
	AdminToken string
	// DataDir is the durable store root passed to server.NewPersistent.
	// A restart on the same DataDir is the DF-BOOT-001 recovery arm.
	DataDir string
	// Extra PersistentOptions are forwarded to server.NewPersistent.
	Extra []server.PersistentOption
}

// System is one live production-path dogfood installation: a persistent
// server on a real loopback listener, a running Maintain loop (the outbox
// dispatcher that emits execution attestations), and optional real runners.
type System struct {
	AdminToken  string
	RunnerToken string
	BaseURL     string
	DataDir     string
	Server      *server.Server

	http     *httptest.Server
	client   *http.Client
	maintain context.CancelFunc
	// maintainDone is closed when Maintain returns, so Close can join it.
	maintainDone chan struct{}

	runnerMu     sync.Mutex
	runnerCancel context.CancelFunc
	runnerDone   chan struct{}
	runnerErr    error
	runnerID     string

	// trusted ingress (webhook stand-in); nil when not enabled.
	trustedForge    *trustedForge
	trustedSecret   string
	trustedRepo     string
	trustedCloneURL string
}

// Start launches a System on a fresh t.TempDir() data directory. Callers
// that need a specific DataDir (restart proofs) use Launch and Close. The
// signed GitHub webhook trusted ingress is enabled by default so success
// scenarios can run trusted native workloads on hosts without rootless
// Docker (see trusted_ingress.go).
func Start(t testingT) *System {
	t.Helper()
	s, err := Launch(SystemConfig{
		RunnerToken: "sys-runner-token",
		AdminToken:  "sys-admin-token",
		DataDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("system.Launch: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.EnableTrustedWebhook(TrustedWebhookConfig{}); err != nil {
		t.Fatalf("system.EnableTrustedWebhook: %v", err)
	}
	return s
}

// testingT is the subset of *testing.T the helpers need, so non-test
// callers can drive the same launch path.
type testingT interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
	TempDir() string
}

// Attach builds a client-only System against an already-running control
// plane (a packaged binary, an N-1 binary, or any other out-of-process
// server). It never constructs a server.Server: BaseURL and the tokens are
// the only authority, so every request the harness issues is the real HTTP
// surface of that binary. runnerWorkRoot is the harness-local directory for
// runner workspaces/identity/cache — it is NOT the server's --data-dir.
func Attach(baseURL, adminToken, runnerToken, runnerWorkRoot string) (*System, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("system.Attach: baseURL is required")
	}
	if runnerToken == "" {
		return nil, fmt.Errorf("system.Attach: runnerToken is required")
	}
	if adminToken == "" {
		adminToken = runnerToken
	}
	if runnerWorkRoot == "" {
		return nil, fmt.Errorf("system.Attach: runnerWorkRoot is required")
	}
	return &System{
		AdminToken:   adminToken,
		RunnerToken:  runnerToken,
		BaseURL:      strings.TrimRight(baseURL, "/"),
		DataDir:      runnerWorkRoot,
		client:       &http.Client{Timeout: 30 * time.Second},
		maintainDone: make(chan struct{}),
	}, nil
}

// Launch builds a persistent server on cfg.DataDir and serves Handler() on
// 127.0.0.1. The Maintain loop is started immediately: without it the
// completion outbox never dispatches execution attestations.
func Launch(cfg SystemConfig) (*System, error) {
	if cfg.RunnerToken == "" {
		return nil, fmt.Errorf("system: RunnerToken is required")
	}
	if cfg.AdminToken == "" {
		cfg.AdminToken = cfg.RunnerToken
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("system: DataDir is required")
	}
	srv, err := server.NewPersistent(cfg.RunnerToken, cfg.AdminToken, cfg.DataDir, cfg.Extra...)
	if err != nil {
		return nil, fmt.Errorf("NewPersistent: %w", err)
	}
	hs := httptest.NewServer(srv.Handler())
	sys := &System{
		AdminToken:   cfg.AdminToken,
		RunnerToken:  cfg.RunnerToken,
		BaseURL:      hs.URL,
		DataDir:      cfg.DataDir,
		Server:       srv,
		http:         hs,
		client:       &http.Client{Timeout: 30 * time.Second},
		maintainDone: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	sys.maintain = cancel
	go func() {
		defer close(sys.maintainDone)
		srv.Maintain(ctx)
	}()
	return sys, nil
}

// Close stops the runner, Maintain loop, HTTP listener and staging budget.
// The durable DataDir is left intact so a later Launch on the same directory
// is a real restart over persisted state.
func (s *System) Close() error {
	if s == nil {
		return nil
	}
	s.stopRunner()
	s.closeTrustedForge()
	if s.maintain != nil {
		s.maintain()
		<-s.maintainDone
		s.maintain = nil
	}
	if s.http != nil {
		s.http.Close()
		s.http = nil
	}
	// Release the staging-directory ownership lock so a successor Launch on
	// the same DataDir can take it (same-process registry would otherwise
	// hand back this budget after it is closed).
	if s.Server != nil && s.Server.Staging != nil {
		_ = s.Server.Staging.Close()
	}
	return nil
}

// SubmitOpts are the client-visible fields of POST /api/v1/runs. Direct API
// submissions are always untrusted; the server derives repository identity
// from RepoURL.
type SubmitOpts struct {
	RepoURL      string
	RepoFullName string
	Ref          string
	SHA          string
	Event        string
	Metadata     map[string]string
}

// SubmitPipeline enqueues one run over real HTTP and returns the run ID.
func (s *System) SubmitPipeline(ctx context.Context, pipelineYAML string, opts SubmitOpts) (string, error) {
	if opts.RepoURL == "" {
		opts.RepoURL = "https://github.com/kiwi-dogfood/system.git"
	}
	if opts.Ref == "" {
		opts.Ref = "refs/heads/main"
	}
	if opts.Event == "" {
		opts.Event = "push"
	}
	body := map[string]any{
		"repo_url": opts.RepoURL,
		"ref":      opts.Ref,
		"pipeline": pipelineYAML,
		"event":    opts.Event,
	}
	if opts.RepoFullName != "" {
		body["repo_full_name"] = opts.RepoFullName
	}
	if opts.SHA != "" {
		body["sha"] = opts.SHA
	}
	if opts.Metadata != nil {
		body["metadata"] = opts.Metadata
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/api/v1/runs", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("submit: %s: %s", resp.Status, strings.TrimSpace(string(payload)))
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &run); err != nil {
		return "", fmt.Errorf("submit decode: %w", err)
	}
	if run.ID == "" {
		return "", fmt.Errorf("submit: empty run id in %s", payload)
	}
	return run.ID, nil
}

// RunView is the public GET /api/v1/runs/{id} shape this harness reads.
type RunView struct {
	ID     string       `json:"id"`
	Status model.Status `json:"status"`
	Ref    string       `json:"ref"`
	SHA    string       `json:"sha"`
	Repo   string       `json:"repo"`
}

// JobView is the public GET /api/v1/runs/{id}/jobs shape this harness reads.
type JobView struct {
	ID              string       `json:"id"`
	Key             string       `json:"key"`
	Status          model.Status `json:"status"`
	Error           string       `json:"error,omitempty"`
	LeaseGeneration int64        `json:"lease_generation,omitempty"`
	LeaseRunnerID   string       `json:"lease_runner_id,omitempty"`
	AttemptRunnerID string       `json:"attempt_runner_id,omitempty"`
	Trusted         bool         `json:"trusted"`
}

// QueryRun fetches one run via the public API.
func (s *System) QueryRun(ctx context.Context, runID string) (RunView, error) {
	var out RunView
	if err := s.getJSON(ctx, s.AdminToken, "/api/v1/runs/"+runID, &out); err != nil {
		return RunView{}, err
	}
	return out, nil
}

// QueryJobs lists a run's jobs via the public API.
func (s *System) QueryJobs(ctx context.Context, runID string) ([]JobView, error) {
	var out []JobView
	if err := s.getJSON(ctx, s.AdminToken, "/api/v1/runs/"+runID+"/jobs", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// JobByKey returns the job with the given pipeline key.
func (s *System) JobByKey(ctx context.Context, runID, jobKey string) (JobView, error) {
	jobs, err := s.QueryJobs(ctx, runID)
	if err != nil {
		return JobView{}, err
	}
	for _, j := range jobs {
		if j.Key == jobKey {
			return j, nil
		}
	}
	return JobView{}, fmt.Errorf("job %q not found in run %s", jobKey, runID)
}

// WaitJobTerminal polls the public jobs endpoint until the named job reaches
// a terminal status or ctx ends.
func (s *System) WaitJobTerminal(ctx context.Context, runID, jobKey string) (model.Status, error) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	var last model.Status
	var lastErr string
	for {
		j, err := s.JobByKey(ctx, runID, jobKey)
		if err == nil {
			last = j.Status
			lastErr = j.Error
			if j.Status.Terminal() {
				return j.Status, nil
			}
		}
		select {
		case <-ctx.Done():
			return last, fmt.Errorf("wait job %q in run %s: last status %q error %q: %w", jobKey, runID, last, lastErr, ctx.Err())
		case <-tick.C:
		}
	}
}

// FetchEvidence downloads the signed execution attestation envelope for one
// attempt over the public API (GET /api/v1/jobs/{id}/attestation). It polls
// because the envelope is produced by the completion outbox after Maintain
// dispatches the execution_attest intent.
func (s *System) FetchEvidence(ctx context.Context, jobID string, generation int64) ([]byte, error) {
	path := fmt.Sprintf("/api/v1/jobs/%s/attestation?generation=%d", jobID, generation)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var lastStatus string
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+s.AdminToken)
		resp, err := s.client.Do(req)
		if err == nil {
			payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return payload, nil
			}
			lastStatus = resp.Status + " " + strings.TrimSpace(string(payload))
		} else {
			lastStatus = err.Error()
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("fetch attestation for %s gen %d (last %s): %w", jobID, generation, lastStatus, ctx.Err())
		case <-tick.C:
		}
	}
}

// JWKSResolver builds a kid → public key resolver from the server's public
// JWKS endpoint (the same discovery path `kiwi verify` uses). Evidence is
// never verified against an in-process key peek.
func (s *System) JWKSResolver(ctx context.Context) (func(kid string) (ed25519.PublicKey, bool), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+"/api/v1/oidc/jwks", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: %s: %s", resp.Status, payload)
	}
	var body struct {
		Keys []struct {
			KID string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}
	byKid := make(map[string]ed25519.PublicKey, len(body.Keys))
	for _, k := range body.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		byKid[k.KID] = ed25519.PublicKey(raw)
	}
	if len(byKid) == 0 {
		return nil, fmt.Errorf("jwks: no usable Ed25519 keys")
	}
	return func(kid string) (ed25519.PublicKey, bool) {
		pub, ok := byKid[kid]
		return pub, ok
	}, nil
}

// VerifyEvidence verifies a fetched envelope through provenance.VerifyWith
// (JWKS-resolved trusted key) and the execution-attestation consistency
// rules. It returns the verified statement.
func (s *System) VerifyEvidence(ctx context.Context, envBytes []byte) (provenance.Statement, error) {
	resolver, err := s.JWKSResolver(ctx)
	if err != nil {
		return provenance.Statement{}, err
	}
	st, err := provenance.VerifyWith(envBytes, resolver, provenance.VerifyOptions{})
	if err != nil {
		return provenance.Statement{}, fmt.Errorf("VerifyWith: %w", err)
	}
	if err := provenance.VerifyExecutionAttestation(st); err != nil {
		return provenance.Statement{}, fmt.Errorf("VerifyExecutionAttestation: %w", err)
	}
	return st, nil
}

// StartRunner launches a real runner.Runner against BaseURL in a goroutine.
// The runner polls with a short interval so system tests finish inside the
// dogfood timeout. Checkout is provisioned through runner.Config.CheckoutFn
// (the documented custom-workspace seam): system dogfood here targets the
// control-plane path (submit → lease → native execute → complete → evidence),
// not forge clone fidelity. Everything after workspace provisioning is the
// production runner path.
//
// ExtraLabels are appended to the runner's scheduling labels (e.g. "container"
// so a container-runtime job can be leased on a host without Docker for the
// pre-checkout quota gate).
func (s *System) StartRunner(name string, extraLabels []string) error {
	if s.runnerCancel != nil {
		return fmt.Errorf("system: runner already started")
	}
	root := filepath.Join(s.DataDir, "sys-runner", name)
	for _, sub := range []string{"work", "identity", "cache", "staging"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o700); err != nil {
			return err
		}
	}
	cfg := runner.Config{
		Server:           s.BaseURL,
		Token:            s.RunnerToken,
		Name:             name,
		Labels:           append([]string{}, extraLabels...),
		Poll:             50 * time.Millisecond,
		Heartbeat:        time.Second,
		Concurrency:      1,
		WorkDir:          filepath.Join(root, "work"),
		IdentityDir:      filepath.Join(root, "identity"),
		CacheRoot:        filepath.Join(root, "cache"),
		StagingDir:       filepath.Join(root, "staging"),
		PrewarmStateFile: filepath.Join(root, "prewarm.json"),
		SingleRunnerHost: true,
		CheckoutFn: func(_ context.Context, _ model.Job, dir string) error {
			return os.WriteFile(filepath.Join(dir, ".kiwi-system-checkout"), []byte("system dogfood workspace\n"), 0o644)
		},
	}
	r := &runner.Runner{Cfg: cfg}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.runnerMu.Lock()
	s.runnerCancel = cancel
	s.runnerDone = done
	s.runnerMu.Unlock()
	go func() {
		defer close(done)
		err := r.Run(ctx)
		s.runnerMu.Lock()
		s.runnerErr = err
		s.runnerMu.Unlock()
	}()
	// Registration is part of Run. Observe it through the PUBLIC API (never
	// by reading r.ID from this goroutine — Runner.Run writes that field and
	// the race detector rightly flags it).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if id := s.registeredRunnerID(name); id != "" {
			s.runnerMu.Lock()
			s.runnerID = id
			s.runnerMu.Unlock()
			return nil
		}
		select {
		case <-done:
			s.runnerMu.Lock()
			rerr := s.runnerErr
			s.runnerMu.Unlock()
			if rerr != nil {
				return fmt.Errorf("runner exited during start: %w", rerr)
			}
			return fmt.Errorf("runner exited during start")
		case <-time.After(10 * time.Millisecond):
		}
	}
	return fmt.Errorf("runner %q did not register within 5s", name)
}

// registeredRunnerID returns the server-side runner id for name via the
// public runners API ("" when not yet registered).
func (s *System) registeredRunnerID(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := s.getJSON(ctx, s.AdminToken, "/api/v1/runners", &out); err != nil {
		return ""
	}
	for _, r := range out {
		if r.Name == name {
			return r.ID
		}
	}
	return ""
}

// RunnerID returns the live runner's registered identity ("" before register).
func (s *System) RunnerID() string {
	s.runnerMu.Lock()
	defer s.runnerMu.Unlock()
	return s.runnerID
}

// stopRunner cancels the runner and joins it. Safe when no runner is live.
func (s *System) stopRunner() {
	s.runnerMu.Lock()
	cancel, done := s.runnerCancel, s.runnerDone
	s.runnerCancel, s.runnerDone = nil, nil
	s.runnerMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// StopRunner exposes the join for tests that need the runner gone before a
// restart or a deterministic lease window.
func (s *System) StopRunner() {
	s.stopRunner()
}

// RegisterRunner registers a synthetic runner over the runner-tier API and
// returns its id. Used by lease-fencing scenarios that drive complete
// directly instead of through a live runner.Run.
func (s *System) RegisterRunner(ctx context.Context, name string, labels []string) (string, error) {
	body := map[string]any{
		"name":             name,
		"labels":           labels,
		"capacity":         1,
		"protocol_version": model.RunnerProtocolVersion,
		"protocol_min":     3,
		"protocol_max":     3,
	}
	raw, _ := json.Marshal(body)
	var out struct {
		ID string `json:"id"`
	}
	if err := s.doJSON(ctx, s.RunnerToken, http.MethodPost, "/api/v1/runners/register", raw, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("register: empty runner id")
	}
	return out.ID, nil
}

// LeaseTask is the runner-tier next-poll answer this harness uses.
type LeaseTask struct {
	JobID           string
	JobKey          string
	RunnerID        string
	LeaseToken      string
	LeaseGeneration int64
}

// Next leases one task for runnerID (204 when the queue is empty).
func (s *System) Next(ctx context.Context, runnerID string) (LeaseTask, bool, error) {
	var task struct {
		Job struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"job"`
		LeaseToken      string `json:"lease_token"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	code, err := s.doJSONStatus(ctx, s.RunnerToken, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", []byte("{}"), &task)
	if err != nil {
		return LeaseTask{}, false, err
	}
	if code == http.StatusNoContent {
		return LeaseTask{}, false, nil
	}
	if code != http.StatusOK {
		return LeaseTask{}, false, fmt.Errorf("next: HTTP %d", code)
	}
	return LeaseTask{
		JobID:           task.Job.ID,
		JobKey:          task.Job.Key,
		RunnerID:        runnerID,
		LeaseToken:      task.LeaseToken,
		LeaseGeneration: task.LeaseGeneration,
	}, true, nil
}

// Complete posts a terminal completion for one leased attempt. The HTTP
// status is returned so a stale-generation rejection (409) is observable
// without string-matching error bodies.
func (s *System) Complete(ctx context.Context, t LeaseTask, status model.Status, errMsg string) (int, error) {
	body := map[string]any{
		"runner_id":        t.RunnerID,
		"lease_token":      t.LeaseToken,
		"lease_generation": t.LeaseGeneration,
		"status":           status,
	}
	if errMsg != "" {
		body["error"] = errMsg
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/api/v1/jobs/"+t.JobID+"/complete", bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+s.RunnerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}

// getJSON performs an authenticated GET and decodes the JSON body into out.
func (s *System) getJSON(ctx context.Context, token, path string, out any) error {
	return s.doJSON(ctx, token, http.MethodGet, path, nil, out)
}

func (s *System) doJSON(ctx context.Context, token, method, path string, body []byte, out any) error {
	_, err := s.doJSONStatus(ctx, token, method, path, body, out)
	return err
}

func (s *System) doJSONStatus(ctx context.Context, token, method, path string, body []byte, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.BaseURL+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(payload)))
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s decode: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

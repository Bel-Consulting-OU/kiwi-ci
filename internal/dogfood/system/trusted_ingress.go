package system

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Trusted ingress product paths (webhook + trusted schedule). Direct API
// submissions can never set Trusted — server.submit force-clears the flag —
// so a SYSTEM-species success that needs trusted capabilities (native host
// execution on a host without rootless Docker) must arrive through one of
// these real control-plane ingresses. Nothing here mutates the store.

// DefaultTrustedRepo is the repository identity the trusted webhook
// stand-in presents. It matches SubmitOpts' default clone URL.
const (
	DefaultTrustedRepo       = "kiwi-dogfood/system"
	DefaultTrustedRepoURL    = "https://github.com/kiwi-dogfood/system.git"
	defaultPipelinePath      = ".kiwi/pipeline.yaml"
	defaultTrustedWebhookSec = "sys-trusted-webhook-secret"
)

// TrustedWebhookConfig configures the signed GitHub webhook trusted ingress.
type TrustedWebhookConfig struct {
	// Secret is the HMAC-SHA256 shared secret (X-Hub-Signature-256).
	// Defaults to a harness-owned value when empty.
	Secret string
	// PipelineYAML is served as the repository's .kiwi/pipeline.yaml by the
	// forge stand-in. DeliverTrustedPush may replace it per delivery.
	PipelineYAML string
	// RepoFullName / RepoCloneURL identify the repository the push event
	// names. Defaults: DefaultTrustedRepo / DefaultTrustedRepoURL.
	RepoFullName string
	RepoCloneURL string
}

// trustedForge is a minimal GitHub API stand-in: the webhook handler's
// pipeline fetch (GET /repos/{full}/contents/{path}) and the compare API
// used for changed files. Status/check publications are accepted and
// dropped so the completion outbox does not spin on a missing endpoint.
type trustedForge struct {
	mu       sync.Mutex
	pipeline []byte
	repo     string
	srv      *httptest.Server
}

func (f *trustedForge) setPipeline(yaml string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pipeline = []byte(yaml)
}

func (f *trustedForge) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && strings.Contains(path, "/contents/"):
			// Only the pipeline path is served; any other path (e.g.
			// .kiwi/lock.json) is a genuine 404 — the real forge does not
			// return the pipeline body for unknown files.
			if !strings.Contains(path, "pipeline.yaml") {
				http.NotFound(w, r)
				return
			}
			f.mu.Lock()
			body := append([]byte(nil), f.pipeline...)
			f.mu.Unlock()
			if len(body) == 0 {
				http.Error(w, "no pipeline", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"name":     "pipeline.yaml",
				"path":     defaultPipelinePath,
				"encoding": "base64",
				"content":  base64.StdEncoding.EncodeToString(body),
			})
		case r.Method == http.MethodGet && strings.Contains(path, "/compare/"):
			// Empty but complete diff: path-less triggers stay admissible.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []any{}})
		case r.Method == http.MethodGet && strings.Contains(path, "/check-runs"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"check_runs": []any{}})
		case r.Method == http.MethodGet && strings.Contains(path, "/commits/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodPost || r.Method == http.MethodPatch:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "node_id": "dogfood-1"})
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	})
}

// EnableTrustedWebhook starts the forge stand-in and points the live server
// at it (webhook secret + GitHub API base) so POST /hooks/github accepts a
// signed push and enqueues a TRUSTED run through the real product handler.
// Safe to call once per System, after Launch.
func (s *System) EnableTrustedWebhook(cfg TrustedWebhookConfig) error {
	if s == nil || s.Server == nil {
		return fmt.Errorf("system: not launched")
	}
	if s.trustedForge != nil {
		return fmt.Errorf("system: trusted webhook ingress already enabled")
	}
	if cfg.Secret == "" {
		cfg.Secret = defaultTrustedWebhookSec
	}
	if cfg.RepoFullName == "" {
		cfg.RepoFullName = DefaultTrustedRepo
	}
	if cfg.RepoCloneURL == "" {
		cfg.RepoCloneURL = DefaultTrustedRepoURL
	}
	f := &trustedForge{repo: cfg.RepoFullName, pipeline: []byte(cfg.PipelineYAML)}
	f.srv = httptest.NewServer(f.handler())
	s.trustedForge = f
	s.trustedSecret = cfg.Secret
	s.trustedRepo = cfg.RepoFullName
	s.trustedCloneURL = cfg.RepoCloneURL
	s.Server.GitHubWebhookSecret = cfg.Secret
	s.Server.SetGitHubAPIBase(f.srv.URL)
	return nil
}

// TrustedWebhookEnabled reports whether the signed webhook ingress is live.
func (s *System) TrustedWebhookEnabled() bool {
	return s != nil && s.trustedForge != nil
}

// DeliverTrustedPush posts one signed GitHub push delivery to the real
// /hooks/github handler and returns the enqueued run ID. When pipelineYAML
// is non-empty it replaces the forge stand-in's served pipeline first, so
// each scenario can pin its own workload. The delivery is the product
// trusted ingress: parsePush marks push events Trusted and the webhook
// handler copies that onto SubmitRun.
func (s *System) DeliverTrustedPush(ctx context.Context, deliveryID, pipelineYAML string) (string, error) {
	if !s.TrustedWebhookEnabled() {
		return "", fmt.Errorf("system: trusted webhook ingress not enabled")
	}
	if pipelineYAML != "" {
		s.trustedForge.setPipeline(pipelineYAML)
	}
	if deliveryID == "" {
		return "", fmt.Errorf("system: delivery id is required")
	}
	headSHA := fmt.Sprintf("%040x", sha256.Sum256([]byte(deliveryID)))
	payload := map[string]any{
		"ref":     "refs/heads/main",
		"before":  "",
		"after":   headSHA,
		"deleted": false,
		"repository": map[string]any{
			"id":             1,
			"full_name":      s.trustedRepo,
			"clone_url":      s.trustedCloneURL,
			"default_branch": "main",
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(s.trustedSecret))
	mac.Write(raw)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/hooks/github", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", deliveryID)
	req.Header.Set("X-Hub-Signature-256", sig)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("trusted push %s: %s: %s", deliveryID, resp.Status, strings.TrimSpace(string(body)))
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &run); err != nil {
		return "", fmt.Errorf("trusted push decode: %w", err)
	}
	if run.ID == "" {
		return "", fmt.Errorf("trusted push: empty run id in %s", body)
	}
	return run.ID, nil
}

// scheduleTrigger wraps a pipeline so the schedule ingress can fire it.
// A spec that already declares on.schedule.cron is returned unchanged.
func scheduleTrigger(pipelineYAML string) string {
	if strings.Contains(pipelineYAML, "schedule:") && strings.Contains(pipelineYAML, "cron:") {
		return pipelineYAML
	}
	if strings.HasPrefix(pipelineYAML, "version:") {
		return "on:\n  schedule:\n    cron: \"* * * * *\"\n" + pipelineYAML
	}
	return "version: 1\non:\n  schedule:\n    cron: \"* * * * *\"\n" + pipelineYAML
}

// SubmitTrustedSchedule creates a TRUSTED schedule over the product API
// (PUT /api/v1/schedules with trusted=true; the admin principal holds
// trusted_run) and fires it immediately (POST .../trigger). fireSchedule
// copies the stored Trusted flag onto the run — a real product trusted
// ingress that never mutates the store. Returns the fired run ID.
func (s *System) SubmitTrustedSchedule(ctx context.Context, pipelineYAML string, opts SubmitOpts) (string, error) {
	if opts.RepoURL == "" {
		opts.RepoURL = DefaultTrustedRepoURL
	}
	if opts.RepoFullName == "" {
		opts.RepoFullName = DefaultTrustedRepo
	}
	body := map[string]any{
		"repository": opts.RepoFullName,
		"repo_url":   opts.RepoURL,
		"spec":       scheduleTrigger(pipelineYAML),
		"trusted":    true,
		"enabled":    true,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	var sc struct {
		ID string `json:"id"`
	}
	if err := s.doJSON(ctx, s.AdminToken, http.MethodPut, "/api/v1/schedules", raw, &sc); err != nil {
		return "", fmt.Errorf("trusted schedule upsert: %w", err)
	}
	if sc.ID == "" {
		return "", fmt.Errorf("trusted schedule upsert: empty schedule id")
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := s.doJSON(ctx, s.AdminToken, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", []byte("{}"), &run); err != nil {
		return "", fmt.Errorf("trusted schedule trigger: %w", err)
	}
	if run.ID == "" {
		return "", fmt.Errorf("trusted schedule trigger: empty run id")
	}
	return run.ID, nil
}

// SubmitTrustedNative enqueues a trusted run through a real product trusted
// ingress and returns the run ID. Preference order:
//
//  1. signed GitHub webhook (EnableTrustedWebhook) — the forge-derived
//     Trusted path;
//  2. trusted schedule (admin trusted_run) — the non-forge trusted path.
//
// Direct API submit is never used: it force-clears Trusted.
func (s *System) SubmitTrustedNative(ctx context.Context, pipelineYAML string) (string, error) {
	if s.TrustedWebhookEnabled() {
		id := fmt.Sprintf("sys-trusted-%d", time.Now().UnixNano())
		return s.DeliverTrustedPush(ctx, id, pipelineYAML)
	}
	return s.SubmitTrustedSchedule(ctx, pipelineYAML, SubmitOpts{})
}

// closeTrustedForge stops the forge stand-in, if any.
func (s *System) closeTrustedForge() {
	if s.trustedForge != nil && s.trustedForge.srv != nil {
		s.trustedForge.srv.Close()
		s.trustedForge.srv = nil
	}
}

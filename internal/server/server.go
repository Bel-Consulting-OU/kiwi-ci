package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kiwici/kiwi/internal/model"
	"github.com/kiwici/kiwi/internal/pipeline"
	"github.com/kiwici/kiwi/internal/policy"
	"github.com/kiwici/kiwi/internal/secretbroker"
	"github.com/kiwici/kiwi/internal/storage"
)

const (
	defaultLeaseDuration  = 45 * time.Second
	maxCompletionReceipts = 4096
)

type Server struct {
	// Token remains for source compatibility; RunnerToken/AdminToken are authoritative.
	Token                string
	RunnerToken          string
	AdminToken           string
	GitHubWebhookSecret  string
	GitHubToken          string
	GitHubAppID          int64
	GitHubAppPrivateKey  string
	GitLabWebhookSecret  string
	GitLabToken          string
	ForgejoWebhookSecret string
	ForgejoToken         string
	PipelinePath         string
	ExternalURL          string
	LeaseDuration        time.Duration
	// SecretBroker resolves declared secrets for trusted jobs holding an
	// active lease. A nil broker disables the secrets endpoint (503).
	SecretBroker secretbroker.Broker

	mu          sync.Mutex
	runs        map[string]model.Run
	jobs        map[string]model.Job
	runners     map[string]model.Runner
	artifacts   map[string]model.ArtifactRecord
	reports     map[string]model.TestReport
	deliveries  map[string]string
	completions map[string]model.CompletionReceipt
	leaseKey    []byte
	logSeq      int64
	store       *storage.Repository
	oidc        *oidcSigner
	outbox      *Outbox

	// Forge API base overrides, used by tests to point adapters at local
	// HTTP servers; empty means the public API endpoints.
	gitHubAPIBase  string
	gitLabAPIBase  string
	forgejoAPIBase string
}

func New(token string) *Server {
	key, err := newLeaseKey()
	if err != nil {
		// A fresh lease key is security-critical state; without entropy the
		// control plane must not start.
		panic("kiwi server: failed to generate lease key: " + err.Error())
	}
	return &Server{
		Token: token, RunnerToken: token, AdminToken: token,
		LeaseDuration: defaultLeaseDuration,
		runs:          map[string]model.Run{}, jobs: map[string]model.Job{}, runners: map[string]model.Runner{}, artifacts: map[string]model.ArtifactRecord{}, reports: map[string]model.TestReport{}, deliveries: map[string]string{}, completions: map[string]model.CompletionReceipt{}, leaseKey: key, oidc: newOIDCSigner(),
		outbox: NewOutbox(nil),
	}
}

// newLeaseKey generates a 32-byte lease HMAC key from crypto/rand.
func newLeaseKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// loadLeaseKey loads the persisted lease HMAC key from dataDir, generating and
// persisting a fresh one on first use. The key is what lets lease tokens
// survive control-plane restarts: only their HMAC is stored in job state.
func loadLeaseKey(root string) ([]byte, error) {
	path := filepath.Join(root, "lease.key")
	if b, err := os.ReadFile(path); err == nil {
		raw, er := hex.DecodeString(strings.TrimSpace(string(b)))
		if er != nil {
			return nil, er
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("invalid lease key size")
		}
		return raw, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := newLeaseKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return key, nil
}

func NewPersistent(runnerToken, adminToken, dataDir string) (*Server, error) {
	if adminToken == "" {
		adminToken = runnerToken
	}
	s := New(runnerToken)
	s.AdminToken = adminToken
	s.store = storage.New(dataDir)
	s.outbox = NewOutbox(s.store)
	if signer, err := loadOIDCSigner(dataDir); err != nil {
		return nil, err
	} else {
		s.oidc = signer
	}
	key, err := loadLeaseKey(dataDir)
	if err != nil {
		return nil, err
	}
	s.leaseKey = key
	snap, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	s.runs, s.jobs, s.runners, s.artifacts, s.reports = snap.Runs, snap.Jobs, snap.Runners, snap.Artifacts, snap.Reports
	if seq, err := s.store.MaxLogSeq(); err != nil {
		return nil, err
	} else {
		s.logSeq = seq
	}
	for id, run := range s.runs {
		for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
			if delivery := strings.TrimSpace(run.Metadata[key]); delivery != "" {
				s.deliveries[delivery] = id
			}
		}
	}
	for id, a := range s.artifacts {
		a.Path = filepath.Join(dataDir, "artifacts", a.RunID, a.JobID, id+".tar.gz")
		if a.ProvenanceSHA256 != "" {
			a.ProvenancePath = a.Path + ".intoto.json"
		}
		s.artifacts[id] = a
	}
	// A restarted control plane must not blindly assume an old process is
	// still polling, but it also must not duplicate jobs whose leases are
	// still valid: rebuild each runner's ActiveJobs from the jobs whose
	// unexpired running leases it actually still holds.
	now := time.Now().UTC()
	for id, r := range s.runners {
		var active []string
		for _, j := range s.jobs {
			if j.LeaseRunnerID == id && j.Status == model.StatusRunning && j.LeaseExpiresAt != nil && j.LeaseExpiresAt.After(now) {
				active = append(active, j.ID)
			}
		}
		if r.Capacity < 1 {
			r.Capacity = 1
		}
		r.ActiveJobs = active
		r.Busy = len(active) >= r.Capacity
		r.CurrentJob = ""
		if len(active) > 0 {
			r.CurrentJob = active[0]
		}
		s.runners[id] = r
	}
	s.mu.Lock()
	s.recoverLeasesLocked(now, true)
	err = s.persistLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.ui)
	mux.HandleFunc("POST /hooks/github", s.githubWebhook)
	mux.HandleFunc("POST /hooks/gitlab", s.gitlabWebhook)
	mux.HandleFunc("POST /hooks/forgejo", s.forgejoWebhook)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.oidcConfiguration)
	mux.HandleFunc("GET /api/v1/oidc/jwks", s.oidcJWKS)
	mux.HandleFunc("POST /api/v1/jobs/{id}/oidc", s.issueOIDC)
	mux.HandleFunc("POST /api/v1/jobs/{id}/secrets", s.issueSecret)
	mux.HandleFunc("GET /api/v1/runs", s.listRuns)
	mux.HandleFunc("POST /api/v1/runs", s.submit)
	mux.HandleFunc("GET /api/v1/runs/{id}", s.getRun)
	mux.HandleFunc("POST /api/v1/runs/{id}/cancel", s.cancelRun)
	mux.HandleFunc("POST /api/v1/runs/{id}/rerun", s.rerunRun)
	mux.HandleFunc("GET /api/v1/runs/{id}/jobs", s.listJobs)
	mux.HandleFunc("GET /api/v1/runs/{id}/logs", s.getLogs)
	mux.HandleFunc("GET /api/v1/runs/{id}/artifacts", s.listArtifacts)
	mux.HandleFunc("GET /api/v1/runs/{id}/tests", s.listTestReports)
	mux.HandleFunc("GET /api/v1/test-intelligence", s.testIntelligence)
	mux.HandleFunc("POST /api/v1/jobs/{id}/tests", s.uploadTestReport)
	mux.HandleFunc("GET /api/v1/artifacts/{id}", s.downloadArtifact)
	mux.HandleFunc("GET /api/v1/artifacts/{id}/provenance", s.downloadProvenance)
	mux.HandleFunc("PUT /api/v1/jobs/{id}/artifacts/{name}", s.uploadArtifact)
	mux.HandleFunc("GET /api/v1/cache/{key}", s.downloadCache)
	mux.HandleFunc("PUT /api/v1/cache/{key}", s.uploadCache)
	mux.HandleFunc("POST /api/v1/jobs/{id}/approve", s.approveJob)
	mux.HandleFunc("POST /api/v1/jobs/{id}/heartbeat", s.heartbeat)
	mux.HandleFunc("POST /api/v1/jobs/{id}/log", s.log)
	mux.HandleFunc("POST /api/v1/jobs/{id}/complete", s.complete)
	mux.HandleFunc("POST /api/v1/runners/register", s.register)
	mux.HandleFunc("POST /api/v1/runners/{id}/next", s.next)
	mux.HandleFunc("GET /api/v1/runners", s.listRunners)
	mux.HandleFunc("GET /api/v1/audit", s.listAudit)
	return requestID(recoverer(statusLogger(s.auth(mux))))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/hooks/") || path == "/" || path == "/.well-known/openid-configuration" || path == "/api/v1/oidc/jwks" || (r.Method == http.MethodPost && strings.HasSuffix(path, "/oidc")) {
			next.ServeHTTP(w, r)
			return
		}
		runnerOnly := strings.HasPrefix(path, "/api/v1/runners/") || path == "/api/v1/runners/register" || strings.HasPrefix(path, "/api/v1/cache/") || (strings.HasPrefix(path, "/api/v1/jobs/") && (strings.Contains(path, "/artifacts/") || strings.HasSuffix(path, "/heartbeat") || strings.HasSuffix(path, "/log") || strings.HasSuffix(path, "/complete") || strings.HasSuffix(path, "/tests") || strings.HasSuffix(path, "/secrets")))
		sharedRead := r.Method == http.MethodGet && (strings.HasPrefix(path, "/api/v1/artifacts/") || (strings.HasPrefix(path, "/api/v1/runs/") && strings.HasSuffix(path, "/artifacts")))
		if sharedRead {
			if s.AdminToken != "" && !bearerOK(r.Header.Get("Authorization"), s.AdminToken) && !bearerOK(r.Header.Get("Authorization"), s.RunnerToken) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		want := s.AdminToken
		if runnerOnly {
			want = s.RunnerToken
		}
		if want != "" && !bearerOK(r.Header.Get("Authorization"), want) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerOK(header, want string) bool {
	got := strings.TrimPrefix(header, "Bearer ")
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	var in SubmitRun
	if !decode(w, r, &in) {
		return
	}
	// Direct API submissions are never trusted; only the forge webhook path
	// (and internal reruns of previously trusted runs) set Trusted. The
	// `trusted` field is not accepted from client JSON (json:"-").
	in.Trusted = false
	run, err := s.enqueue(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) enqueue(in SubmitRun) (model.Run, error) {
	spec, err := pipeline.Parse([]byte(in.Pipeline))
	if err != nil {
		return model.Run{}, err
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		return model.Run{}, err
	}
	caps := policy.DefaultUntrustedCapabilities()
	if in.Trusted {
		caps = policy.DefaultTrustedCapabilities()
	}
	// The hard trust floor is applied after defaults; repository/org policy
	// compilation lands in a later phase and will Intersect on top of these.
	caps = caps.Effective(in.Trusted)
	if err = policy.ValidateAdmissionWithCapabilities(spec, caps); err != nil {
		return model.Run{}, err
	}
	oidcAudiences := policy.OIDCFromCapabilities(caps).AllowedAudiences
	now := time.Now().UTC()
	runID, err := newID()
	if err != nil {
		return model.Run{}, fmt.Errorf("generate run id: %w", err)
	}
	group := expandConcurrency(spec.Concurrency.Group, in)
	run := model.Run{ID: runID, Repo: in.RepoURL, RepoFullName: in.RepoFullName, Ref: in.Ref, SHA: in.SHA, Event: in.Event,
		Status: model.StatusQueued, Trusted: in.Trusted, ConcurrencyGroup: group, CreatedAt: now, Metadata: cloneMap(in.Metadata)}

	jobIDs := make(map[string]string, len(g.Jobs))
	for key := range g.Jobs {
		id, idErr := newID()
		if idErr != nil {
			return model.Run{}, fmt.Errorf("generate job id: %w", idErr)
		}
		jobIDs[key] = id
	}
	created := make(map[string]model.Job, len(g.Jobs))
	for key, cj := range g.Jobs {
		needs := make([]string, 0, len(cj.Needs))
		for _, dep := range cj.Needs {
			needs = append(needs, jobIDs[dep])
		}
		env := cj.Job.Environment.Name
		infraRetries := cj.Job.InfraRetries
		if infraRetries <= 0 {
			infraRetries = 2
		}
		effectiveNetwork := cj.Job.Network
		if effectiveNetwork == "" {
			effectiveNetwork = "bridge"
		}
		if !in.Trusted && cj.Job.Runtime == "container" {
			effectiveNetwork = "none"
		}
		created[jobIDs[key]] = model.Job{
			ID: jobIDs[key], RunID: runID, Key: key, BaseKey: cj.BaseID, RepoURL: in.RepoURL, Ref: in.Ref, SHA: in.SHA,
			Event: in.Event, Condition: cj.Job.If, DependencyStatus: model.StatusSuccess, Pipeline: in.Pipeline, Trusted: in.Trusted, ChangedFiles: append([]string{}, in.ChangedFiles...), Needs: needs,
			RequiredLabels: labelsForJob(cj.Job), Network: effectiveNetwork, Environment: env, ApprovalRequired: cj.Job.Environment.Approval, EnvironmentBranches: append([]string{}, cj.Job.Environment.Branches...), EnvironmentConcurrency: cj.Job.Environment.Concurrency, OIDCAllowed: cj.Job.Permissions.IDToken, OIDCAudiences: cloneStrings(oidcAudiences),
			DeclaredSecrets: declaredSecrets(spec, cj.Job),
			Status:          model.StatusQueued, Priority: downstreamDepth(g, key), MaxInfraRetries: infraRetries, CreatedAt: now,
		}
	}

	s.mu.Lock()
	// Webhook dedupe: forge retries reuse the delivery ID, so a second
	// submission for the same delivery returns the original run instead of
	// enqueueing a duplicate. Checked under the run lock to close the race
	// between the handler fast path and concurrent deliveries.
	if delivery, ok := webhookDelivery(in.Metadata); ok {
		if existing, ok := s.deliveries[delivery]; ok {
			if prior, ok := s.runs[existing]; ok && prior.RepoFullName == in.RepoFullName {
				s.mu.Unlock()
				return prior, nil
			}
		}
	}
	if group != "" && spec.Concurrency.CancelInProgress {
		for id, old := range s.runs {
			if old.ID != runID && old.Repo == in.RepoURL && old.ConcurrencyGroup == group && !old.Status.Terminal() {
				s.cancelRunLocked(id, "superseded by run "+runID, "scheduler")
			}
		}
	}
	s.runs[runID] = run
	for id, j := range created {
		s.jobs[id] = j
	}
	s.auditLocked("run.queued", "scheduler", runID, "", "run queued", map[string]string{"event": in.Event})
	s.scheduleStateLocked()
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		return model.Run{}, err
	}
	run = s.runs[runID]
	for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
		if delivery := in.Metadata[key]; delivery != "" {
			if _, exists := s.deliveries[delivery]; !exists {
				s.deliveries[delivery] = runID
			}
		}
	}
	s.mu.Unlock()
	s.publishGitHubStatus(run)
	return run, nil
}

// webhookDelivery extracts the forge delivery ID from submit metadata, if
// any. The keys are recorded on the run's Metadata so a restarted control
// plane can rebuild its deliveries map from persisted runs.
func webhookDelivery(meta map[string]string) (string, bool) {
	for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
		if v := strings.TrimSpace(meta[key]); v != "" {
			return v, true
		}
	}
	return "", false
}

func labelsForJob(j pipeline.Job) []string {
	set := map[string]bool{}
	rt := j.Runtime
	if rt == "" {
		rt = "native"
	}
	set[rt] = true
	if rt == "tart" {
		set["os:darwin"] = true
	}
	for _, l := range j.Runner {
		if l != "" {
			set[l] = true
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func downstreamDepth(g *pipeline.Graph, key string) int {
	memo := map[string]int{}
	var visit func(string) int
	visit = func(k string) int {
		if v, ok := memo[k]; ok {
			return v
		}
		best := 0
		for child, cj := range g.Jobs {
			for _, dep := range cj.Needs {
				if dep == k {
					if d := 1 + visit(child); d > best {
						best = d
					}
				}
			}
		}
		memo[k] = best
		return best
	}
	return visit(key)
}

func expandConcurrency(v string, in SubmitRun) string {
	r := strings.NewReplacer("${{ ref }}", in.Ref, "${{ref}}", in.Ref, "${{ event }}", in.Event, "${{event}}", in.Event, "${{ sha }}", in.SHA, "${{sha}}", in.SHA)
	return strings.TrimSpace(r.Replace(v))
}

func (s *Server) listRuns(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Run, 0, len(s.runs))
	for _, v := range s.runs {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}
func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	v, ok := s.runs[id]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[runID]; !ok {
		http.NotFound(w, r)
		return
	}
	out := make([]model.Job, 0)
	for _, j := range s.jobs {
		if j.RunID == runID {
			out = append(out, redactJob(j))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	writeJSON(w, http.StatusOK, out)
}
func redactJob(j model.Job) model.Job { j.Pipeline = ""; j.LeaseTokenHash = nil; return j }

func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if s.store != nil {
		v, err := s.store.ReadLogs(id, after, limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, http.StatusOK, v)
		return
	}
	// In-memory servers keep no historical log buffer by design; tests/dev can still stream stdout.
	writeJSON(w, http.StatusOK, []model.LogEntry{})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in model.Runner
	if !decode(w, r, &in) {
		return
	}
	if in.ID == "" {
		id, err := newID()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		in.ID = id
	}
	if in.Name == "" {
		in.Name = in.ID
	}
	now := time.Now().UTC()
	s.mu.Lock()
	old := s.runners[in.ID]
	if old.Registered.IsZero() {
		in.Registered = now
	} else {
		in.Registered = old.Registered
		in.Completed = old.Completed
		in.Failed = old.Failed
	}
	if in.Capacity < 1 {
		in.Capacity = 1
	}
	in.LastSeen = now
	in.ActiveJobs = append([]string{}, old.ActiveJobs...)
	// Migrate persisted pre-capacity state without losing an active lease.
	if len(in.ActiveJobs) == 0 && old.CurrentJob != "" {
		in.ActiveJobs = []string{old.CurrentJob}
	}
	in.Busy = len(in.ActiveJobs) >= in.Capacity
	if len(in.ActiveJobs) > 0 {
		in.CurrentJob = in.ActiveJobs[0]
	}
	s.runners[in.ID] = in
	s.auditLocked("runner.register", in.Name, "", "", "runner registered", nil)
	_ = s.persistLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, in)
}
func (s *Server) listRunners(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Runner, 0, len(s.runners))
	for _, x := range s.runners {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) next(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoverLeasesLocked(now, false)
	s.scheduleStateLocked()
	ri, ok := s.runners[id]
	if !ok {
		http.Error(w, "runner not registered", http.StatusNotFound)
		return
	}
	ri.LastSeen = now
	if ri.Capacity < 1 {
		ri.Capacity = 1
	}
	if len(ri.ActiveJobs) >= ri.Capacity {
		ri.Busy = true
		s.runners[id] = ri
		_ = s.persistLocked()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	candidates := make([]model.Job, 0)
	for _, j := range s.jobs {
		if j.Status != model.StatusQueued || !depsReadyLocked(j, s.jobs) {
			continue
		}
		if !labelsSatisfied(ri.Labels, j.RequiredLabels) {
			continue
		}
		if environmentAtCapacity(j, s.jobs) {
			continue
		}
		candidates = append(candidates, j)
	}
	if len(candidates) == 0 {
		s.runners[id] = ri
		_ = s.persistLocked()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	j := candidates[0]
	j.NeedsOutputs = collectServerNeedsOutputs(j, s.jobs)
	exp := now.Add(s.leaseDuration())
	t1, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	t2, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	rawToken := t1 + t2
	j.Status = model.StatusRunning
	j.Attempts++
	j.LeaseRunnerID = id
	j.LeaseTokenHash = hashLeaseToken(s.leaseKey, rawToken)
	j.LeaseGeneration++
	j.LeaseExpiresAt = &exp
	if j.StartedAt == nil {
		j.StartedAt = &now
	}
	s.jobs[j.ID] = j
	ri.ActiveJobs = appendUnique(ri.ActiveJobs, j.ID)
	ri.Busy = len(ri.ActiveJobs) >= ri.Capacity
	if len(ri.ActiveJobs) > 0 {
		ri.CurrentJob = ri.ActiveJobs[0]
	}
	ri.LastSeen = now
	s.runners[id] = ri
	s.refreshRunLocked(j.RunID)
	s.auditLocked("job.leased", ri.Name, j.RunID, j.ID, "job leased", map[string]string{"job": j.Key, "generation": strconv.FormatInt(j.LeaseGeneration, 10)})
	_ = s.persistLocked()
	// The raw token travels on the wire once; the hash is not needed by the
	// runner and is stripped from the task job.
	taskJob := j
	taskJob.LeaseTokenHash = nil
	task := Task{Job: taskJob, LeaseToken: rawToken, LeaseGeneration: j.LeaseGeneration, LeaseExpiresAt: exp}
	writeJSON(w, http.StatusOK, task)
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in Heartbeat
	if !decode(w, r, &in) {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if j.Status == model.StatusCancelled {
		writeJSON(w, http.StatusOK, HeartbeatResponse{Cancel: true})
		return
	}
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	exp := now.Add(s.leaseDuration())
	j.LeaseExpiresAt = &exp
	s.jobs[jobID] = j
	if ri, ok := s.runners[in.RunnerID]; ok {
		ri.LastSeen = now
		s.runners[in.RunnerID] = ri
	}
	_ = s.persistLocked()
	writeJSON(w, http.StatusOK, HeartbeatResponse{LeaseExpiresAt: exp})
}

func (s *Server) log(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in LogLine
	if !decodeLimit(w, r, &in, 1<<20) {
		return
	}
	if len(in.Step) > 128 || len(in.Line) > 1<<20 || len(in.JobKey) > 512 {
		http.Error(w, "log line exceeds size limits", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	// Strict: a cancelled (or otherwise non-running) job no longer accepts
	// log lines. The runner logs cancellation locally before completing, so
	// no final flush grace window is needed.
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		s.mu.Unlock()
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	s.logSeq++
	e := model.LogEntry{Seq: s.logSeq, RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Step: in.Step, Line: in.Line, CreatedAt: time.Now().UTC()}
	s.mu.Unlock()
	if s.store != nil {
		if err := s.store.AppendLog(e); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) complete(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in Complete
	if !decode(w, r, &in) {
		return
	}
	if len(in.Error) > 64<<10 {
		http.Error(w, "error message exceeds 64 KiB", http.StatusBadRequest)
		return
	}
	hash, err := completionResultHash(in.Status, in.Error, in.Outputs)
	if err != nil {
		http.Error(w, "invalid outputs payload", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	// Completion is idempotent for the active generation. A previous
	// completion may already have made the job terminal and cleared its
	// lease; a duplicate delivery of the same result is acknowledged from
	// the receipt instead of being rejected.
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		if rec, has := s.completions[completionReceiptKey(jobID, in.LeaseGeneration, in.RunnerID)]; has && rec.ResultHash == hash {
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.mu.Unlock()
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	if !j.Status.Terminal() {
		st := in.Status
		if st != model.StatusSuccess && st != model.StatusFailure && st != model.StatusCancelled && st != model.StatusSkipped {
			st = model.StatusFailure
		}
		j.Status = st
		j.Error = in.Error
		if validJobOutputs(in.Outputs) {
			j.Outputs = cloneMap(in.Outputs)
		} else {
			j.Status = model.StatusFailure
			j.Error = "runner returned invalid or oversized job outputs"
		}
		j.FinishedAt = &now
	}
	// The lease is spent: clear all lease state so nothing can reuse it,
	// then dedupe future retries of this exact completion via the receipt.
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	s.recordCompletionReceiptLocked(jobID, in.LeaseGeneration, in.RunnerID, hash)
	runID := j.RunID
	s.jobs[jobID] = j
	s.releaseRunnerLocked(in.RunnerID, j.ID, j.Status)
	s.auditLocked("job.completed", in.RunnerID, runID, j.ID, string(j.Status), map[string]string{"job": j.Key})
	s.scheduleStateLocked()
	s.refreshRunLocked(runID)
	run := s.runs[runID]
	_ = s.persistLocked()
	s.mu.Unlock()
	if run.Status.Terminal() {
		s.publishGitHubStatus(run)
	}
	w.WriteHeader(http.StatusNoContent)
}

// completionResultHash canonicalizes a completion payload so identical
// retries can be recognized. encoding/json sorts map keys, making outputs
// deterministic.
func completionResultHash(status model.Status, errMsg string, outputs map[string]string) (string, error) {
	outJSON, err := json.Marshal(outputs)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(status))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(errMsg))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(outJSON)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func completionReceiptKey(jobID string, generation int64, runnerID string) string {
	return jobID + "|" + strconv.FormatInt(generation, 10) + "|" + runnerID
}

// recordCompletionReceiptLocked keeps a bounded in-memory dedupe record.
// Receipts are intentionally not persisted in the filesystem snapshot; the
// PostgreSQL phase will store them durably. The bound keeps memory flat and
// evicts an arbitrary oldest entry when full.
func (s *Server) recordCompletionReceiptLocked(jobID string, generation int64, runnerID, resultHash string) {
	if len(s.completions) >= maxCompletionReceipts {
		for k := range s.completions {
			delete(s.completions, k)
			break
		}
	}
	s.completions[completionReceiptKey(jobID, generation, runnerID)] = model.CompletionReceipt{JobID: jobID, Generation: generation, RunnerID: runnerID, ResultHash: resultHash}
}

// hashLeaseToken computes the HMAC-SHA256 of a raw lease token under the
// server lease key. Only this digest is ever persisted or compared.
func hashLeaseToken(key []byte, raw string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(raw))
	return mac.Sum(nil)
}

// validActiveLease authorizes a runner action against a job's live lease:
// the job must be running, the lease unexpired, the runner and generation
// must match, and the presented token must hash to the stored digest.
func (s *Server) validActiveLease(j model.Job, runnerID, token string, generation int64, now time.Time) bool {
	if j.Status != model.StatusRunning || j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(now) {
		return false
	}
	if j.LeaseRunnerID != runnerID || j.LeaseGeneration != generation || len(j.LeaseTokenHash) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(hashLeaseToken(s.leaseKey, token), j.LeaseTokenHash) == 1
}

func (s *Server) approveJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	actor := strings.TrimSpace(r.Header.Get("X-Kiwi-Actor"))
	if actor == "" {
		actor = "api"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !j.ApprovalRequired {
		http.Error(w, "job does not require approval", http.StatusConflict)
		return
	}
	if j.Status.Terminal() {
		http.Error(w, "job is already terminal", http.StatusConflict)
		return
	}
	j.ApprovedBy = actor
	if j.Status == model.StatusWaitingApproval {
		j.Status = model.StatusQueued
	}
	s.jobs[jobID] = j
	s.auditLocked("job.approved", actor, j.RunID, j.ID, "environment approved", map[string]string{"environment": j.Environment})
	s.scheduleStateLocked()
	s.refreshRunLocked(j.RunID)
	_ = s.persistLocked()
	writeJSON(w, http.StatusOK, redactJob(j))
}

func (s *Server) rerunRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	old, ok := s.runs[id]
	var pipelineText string
	if ok {
		for _, j := range s.jobs {
			if j.RunID == id {
				pipelineText = j.Pipeline
				break
			}
		}
	}
	s.mu.Unlock()
	if !ok || pipelineText == "" {
		http.NotFound(w, r)
		return
	}
	meta := cloneMap(old.Metadata)
	if meta == nil {
		meta = map[string]string{}
	}
	// A rerun is a new webhook-independent submission: drop the forge
	// delivery IDs so it cannot be confused with the original delivery.
	for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
		delete(meta, key)
	}
	meta["rerun_of"] = id
	run, err := s.enqueue(SubmitRun{RepoURL: old.Repo, RepoFullName: old.RepoFullName, Ref: old.Ref, SHA: old.SHA, Event: old.Event, Pipeline: pipelineText, Trusted: old.Trusted, Metadata: meta})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := strings.TrimSpace(r.Header.Get("X-Kiwi-Actor"))
	if actor == "" {
		actor = "api"
	}
	s.mu.Lock()
	if _, ok := s.runs[id]; !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	s.cancelRunLocked(id, "cancelled by "+actor, actor)
	run := s.runs[id]
	_ = s.persistLocked()
	s.mu.Unlock()
	s.publishGitHubStatus(run)
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) cancelRunLocked(runID, reason, actor string) {
	now := time.Now().UTC()
	for id, j := range s.jobs {
		if j.RunID != runID || j.Status.Terminal() {
			continue
		}
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		// Cancellation immediately voids the lease so the runner's next
		// heartbeat learns the job is cancelled and any stale token is dead.
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		s.jobs[id] = j
	}
	run, ok := s.runs[runID]
	if ok && !run.Status.Terminal() {
		run.Status = model.StatusCancelled
		run.FinishedAt = &now
		s.runs[runID] = run
	}
	s.auditLocked("run.cancelled", actor, runID, "", reason, nil)
}

func (s *Server) scheduleStateLocked() {
	changed := true
	for changed {
		changed = false
		for id, j := range s.jobs {
			if j.Status != model.StatusQueued && j.Status != model.StatusWaitingApproval {
				continue
			}
			ready, depStatus := dependencyOutcomeLocked(j, s.jobs)
			if !ready {
				continue
			}
			j.DependencyStatus = depStatus
			if depStatus != model.StatusSuccess && !dependencyConditionAllows(j.Condition, depStatus) {
				now := time.Now().UTC()
				j.Status = model.StatusBlocked
				j.Error = "dependency failed"
				j.FinishedAt = &now
				s.jobs[id] = j
				changed = true
				continue
			}
			s.jobs[id] = j
			if len(j.EnvironmentBranches) > 0 && !environmentBranchAllowed(s.runs[j.RunID].Ref, j.EnvironmentBranches) {
				now := time.Now().UTC()
				j.Status = model.StatusBlocked
				j.Error = "ref is not allowed to deploy to environment " + j.Environment
				j.FinishedAt = &now
				s.jobs[id] = j
				changed = true
				continue
			}
			if j.ApprovalRequired && j.ApprovedBy == "" {
				if j.Status != model.StatusWaitingApproval {
					j.Status = model.StatusWaitingApproval
					s.jobs[id] = j
					changed = true
				}
			} else if j.Status == model.StatusWaitingApproval {
				j.Status = model.StatusQueued
				s.jobs[id] = j
				changed = true
			}
		}
	}
	for runID := range s.runs {
		s.refreshRunLocked(runID)
	}
}

func dependencyOutcomeLocked(j model.Job, jobs map[string]model.Job) (bool, model.Status) {
	outcome := model.StatusSuccess
	for _, depID := range j.Needs {
		d, ok := jobs[depID]
		if !ok {
			return true, model.StatusFailure
		}
		if !d.Status.Terminal() {
			return false, model.StatusPending
		}
		switch d.Status {
		case model.StatusFailure, model.StatusBlocked:
			outcome = model.StatusFailure
		case model.StatusCancelled:
			if outcome != model.StatusFailure {
				outcome = model.StatusCancelled
			}
		}
	}
	return true, outcome
}

func dependencyConditionAllows(expr string, status model.Status) bool {
	switch strings.TrimSpace(expr) {
	case "always()":
		return true
	case "failure()":
		return status == model.StatusFailure
	case "cancelled()":
		return status == model.StatusCancelled
	default:
		return false
	}
}

func depsReadyLocked(j model.Job, jobs map[string]model.Job) bool {
	ready, status := dependencyOutcomeLocked(j, jobs)
	return ready && (status == model.StatusSuccess || dependencyConditionAllows(j.Condition, status))
}

func (s *Server) refreshRunLocked(runID string) {
	run, ok := s.runs[runID]
	if !ok {
		return
	}
	var total, terminal int
	var anyRunning, anyFailure, anyCancelled, anyWaiting bool
	var firstStart *time.Time
	var lastFinish *time.Time
	for _, j := range s.jobs {
		if j.RunID != runID {
			continue
		}
		total++
		if j.StartedAt != nil && (firstStart == nil || j.StartedAt.Before(*firstStart)) {
			t := *j.StartedAt
			firstStart = &t
		}
		if j.Status.Terminal() {
			terminal++
			if j.FinishedAt != nil && (lastFinish == nil || j.FinishedAt.After(*lastFinish)) {
				t := *j.FinishedAt
				lastFinish = &t
			}
		}
		if j.Status == model.StatusRunning {
			anyRunning = true
		}
		if j.Status == model.StatusFailure || j.Status == model.StatusBlocked {
			anyFailure = true
		}
		if j.Status == model.StatusCancelled {
			anyCancelled = true
		}
		if j.Status == model.StatusWaitingApproval {
			anyWaiting = true
		}
	}
	if total == 0 {
		return
	}
	if run.Status == model.StatusCancelled {
		return
	}
	switch {
	case terminal == total:
		if anyFailure {
			run.Status = model.StatusFailure
		} else if anyCancelled {
			run.Status = model.StatusCancelled
		} else {
			run.Status = model.StatusSuccess
		}
		run.FinishedAt = lastFinish
		if run.FinishedAt == nil {
			n := time.Now().UTC()
			run.FinishedAt = &n
		}
	case anyRunning:
		run.Status = model.StatusRunning
	case anyWaiting:
		run.Status = model.StatusWaitingApproval
	default:
		run.Status = model.StatusQueued
	}
	if run.StartedAt == nil && firstStart != nil {
		run.StartedAt = firstStart
	}
	s.runs[runID] = run
}

func (s *Server) recoverLeasesLocked(now time.Time, startup bool) {
	_ = startup // Signature kept for call-site stability; startup no longer forces expiry: unexpired leases survive restart.
	for id, j := range s.jobs {
		if j.Status != model.StatusRunning {
			continue
		}
		expired := j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(now)
		if !expired {
			continue
		}
		runnerID := j.LeaseRunnerID
		if j.Attempts <= j.MaxInfraRetries {
			j.Status = model.StatusQueued
			j.Error = "runner lease expired; retrying"
			j.LeaseRunnerID = ""
			j.LeaseTokenHash = nil
			j.LeaseExpiresAt = nil
			s.auditLocked("job.lease_expired", "scheduler", j.RunID, j.ID, "job requeued after lost runner", map[string]string{"job": j.Key})
		} else {
			j.Status = model.StatusFailure
			j.Error = "runner lease expired and infrastructure retry budget exhausted"
			j.FinishedAt = &now
			j.LeaseRunnerID = ""
			j.LeaseTokenHash = nil
			j.LeaseExpiresAt = nil
			s.auditLocked("job.lost_runner", "scheduler", j.RunID, j.ID, j.Error, map[string]string{"job": j.Key})
		}
		s.jobs[id] = j
		s.releaseRunnerLocked(runnerID, j.ID, model.StatusFailure)
	}
	s.scheduleStateLocked()
}

func (s *Server) releaseRunnerLocked(runnerID, jobID string, status model.Status) {
	ri, ok := s.runners[runnerID]
	if !ok {
		return
	}
	ri.ActiveJobs = removeString(ri.ActiveJobs, jobID)
	if ri.Capacity < 1 {
		ri.Capacity = 1
	}
	ri.Busy = len(ri.ActiveJobs) >= ri.Capacity
	ri.CurrentJob = ""
	if len(ri.ActiveJobs) > 0 {
		ri.CurrentJob = ri.ActiveJobs[0]
	}
	ri.LastSeen = time.Now().UTC()
	if status == model.StatusSuccess {
		ri.Completed++
	} else if status == model.StatusFailure {
		ri.Failed++
	}
	s.runners[runnerID] = ri
}

func (s *Server) auditLocked(action, actor, runID, jobID, msg string, meta map[string]string) {
	if s.store == nil {
		return
	}
	id, err := newID()
	if err != nil {
		log.Printf("audit: dropping %q event: %v", action, err)
		return
	}
	e := model.AuditEvent{ID: id, Action: action, Actor: actor, RunID: runID, JobID: jobID, Message: msg, Metadata: meta, CreatedAt: time.Now().UTC()}
	_ = s.store.AppendAudit(e)
}
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, 200, []model.AuditEvent{})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, err := s.store.ReadAudit(limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) persistLocked() error {
	if s.store == nil {
		return nil
	}
	return s.store.Save(storage.Snapshot{Version: 1, Runs: s.runs, Jobs: s.jobs, Runners: s.runners, Artifacts: s.artifacts, Reports: s.reports})
}
func (s *Server) leaseDuration() time.Duration {
	if s.LeaseDuration <= 0 {
		return defaultLeaseDuration
	}
	return s.LeaseDuration
}

func environmentBranchAllowed(ref string, patterns []string) bool {
	branch := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/")
	for _, ptn := range patterns {
		ptn = strings.TrimSpace(ptn)
		if ptn == "" {
			continue
		}
		if ptn == branch || ptn == ref {
			return true
		}
		if ok, _ := path.Match(ptn, branch); ok {
			return true
		}
	}
	return false
}

func environmentAtCapacity(j model.Job, jobs map[string]model.Job) bool {
	if j.Environment == "" || j.EnvironmentConcurrency <= 0 {
		return false
	}
	active := 0
	for _, other := range jobs {
		if other.ID == j.ID || other.Environment != j.Environment || other.Status != model.StatusRunning {
			continue
		}
		active++
		if active >= j.EnvironmentConcurrency {
			return true
		}
	}
	return false
}

func labelsSatisfied(have, need []string) bool {
	m := map[string]bool{}
	for _, x := range have {
		m[x] = true
	}
	for _, x := range need {
		if !m[x] {
			return false
		}
	}
	return true
}
func collectServerNeedsOutputs(j model.Job, jobs map[string]model.Job) map[string]map[string]string {
	out := map[string]map[string]string{}
	baseCount := map[string]int{}
	for _, id := range j.Needs {
		if d, ok := jobs[id]; ok {
			baseCount[d.BaseKey]++
		}
	}
	for _, id := range j.Needs {
		d, ok := jobs[id]
		if !ok || len(d.Outputs) == 0 {
			continue
		}
		out[d.Key] = cloneMap(d.Outputs)
		if baseCount[d.BaseKey] == 1 {
			out[d.BaseKey] = cloneMap(d.Outputs)
		}
	}
	return out
}

func validJobOutputs(in map[string]string) bool {
	if len(in) > 256 {
		return false
	}
	total := 0
	for k, v := range in {
		if len(k) == 0 || len(k) > 128 || len(v) > 64<<10 {
			return false
		}
		total += len(k) + len(v)
		if total > 1<<20 {
			return false
		}
	}
	return true
}

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

func removeString(in []string, v string) []string {
	out := in[:0]
	for _, x := range in {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := map[model.Status]int{}
	for _, r := range s.runs {
		counts[r.Status]++
	}
	jobs := map[model.Status]int{}
	for _, j := range s.jobs {
		jobs[j.Status]++
	}
	busy := 0
	capacity := 0
	for _, r := range s.runners {
		busy += len(r.ActiveJobs)
		c := r.Capacity
		if c < 1 {
			c = 1
		}
		capacity += c
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "# HELP kiwi_runs Number of CI runs by status")
	fmt.Fprintln(w, "# TYPE kiwi_runs gauge")
	for st, n := range counts {
		fmt.Fprintf(w, "kiwi_runs{status=%q} %d\n", st, n)
	}
	fmt.Fprintln(w, "# HELP kiwi_jobs Number of CI jobs by status")
	fmt.Fprintln(w, "# TYPE kiwi_jobs gauge")
	for st, n := range jobs {
		fmt.Fprintf(w, "kiwi_jobs{status=%q} %d\n", st, n)
	}
	fmt.Fprintf(w, "kiwi_runners %d\nkiwi_runner_slots %d\nkiwi_runner_slots_busy %d\n", len(s.runners), capacity, busy)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimit(w, r, v, 8<<20)
}

// decodeLimit strictly decodes one JSON object from the request body,
// rejecting unknown fields and trailing data. Endpoints with tighter
// integrity budgets pass a smaller max.
func decodeLimit(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "bad json: trailing data", http.StatusBadRequest)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// newID returns a 128-bit crypto/rand identifier hex-encoded.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// requestID is the outermost middleware: it accepts a client-supplied
// X-Kiwi-Request-ID (bounded, safe charset) or mints one, echoes it on the
// response, and stores it in the request context for error logging.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Kiwi-Request-ID")
		if !validRequestID(id) {
			gen, err := newID()
			if err != nil {
				// Entropy failure is unrecoverable; leave the ID empty so
				// error responses still render.
				gen = ""
			}
			id = gen
		}
		w.Header().Set("X-Kiwi-Request-ID", id)
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, id))
		next.ServeHTTP(w, r)
	})
}

type requestIDContextKey struct{}

func requestIDFrom(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDContextKey{}).(string); ok {
		return id
	}
	return ""
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// statusLogger logs server-side errors (500+) with the request ID.
func statusLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status >= 500 {
			log.Printf("request_id=%s %s %s -> %d", requestIDFrom(r), r.Method, r.URL.Path, rec.status)
		}
	})
}

// recoverer converts panics into opaque 500 responses: the panic text and
// stack stay in the server log and never reach clients.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if x := recover(); x != nil {
				id := requestIDFrom(r)
				log.Printf("panic serving %s %s (request_id=%s): %v\n%s", r.Method, r.URL.Path, id, x, debug.Stack())
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error", "request_id": id})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Maintain performs control-plane housekeeping independent of runner polling.
// It recovers expired leases, advances dependency/approval state, persists the
// result, and publishes forge status changes caused by lost runners.
func (s *Server) Maintain(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			before := map[string]model.Status{}
			for id, r := range s.runs {
				before[id] = r.Status
			}
			s.recoverLeasesLocked(now.UTC(), false)
			s.cleanupExpiredArtifactsLocked(now.UTC())
			_ = s.persistLocked()
			var changed []model.Run
			for id, r := range s.runs {
				if before[id] != r.Status {
					changed = append(changed, r)
				}
			}
			s.mu.Unlock()
			for _, r := range changed {
				s.publishGitHubStatus(r)
			}
			s.flushOutbox()
		}
	}
}

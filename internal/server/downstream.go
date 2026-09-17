package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// downstreamPayload is the durable outbox payload for one cross-repo
// downstream dispatch intent. The DownstreamLink row (parent job, target
// repo, target ref) is the exactly-once launch claim; this payload carries
// the remaining launch arguments.
type downstreamPayload struct {
	ParentJobID string            `json:"parent_job_id"`
	ParentRunID string            `json:"parent_run_id"`
	TargetRepo  string            `json:"target_repo"`
	TargetRef   string            `json:"target_ref"`
	LaunchToken string            `json:"launch_token"`
	Event       string            `json:"event,omitempty"`
	Wait        bool              `json:"wait,omitempty"`
	Inputs      map[string]string `json:"inputs,omitempty"`
	Forge       string            `json:"forge,omitempty"`
	Trusted     bool              `json:"trusted,omitempty"`
}

// recordDownstreamIntents resolves a successfully completed job's
// downstream declaration into a durable launch claim and an outbox intent.
// Idempotent: the claim row (or fs-mode snapshot entry) is only created
// once, and the dispatch is exactly-once via the reservation. The link
// carries the forge identity coordinates (forge kind, API base URL
// override, repo ID) so dispatch never re-derives hosts from hard-coded
// public endpoints. Persistence failures are returned — never
// log-and-continue — so the completion response can fail and the
// idempotent replay can re-attempt the recording.
func (s *Server) recordDownstreamIntents(ctx context.Context, j model.Job, run model.Run) error {
	cj, ok := compileJobFromPipeline(j)
	if !ok {
		return nil
	}
	d := cj.Job.Downstream
	if strings.TrimSpace(d.Repository) == "" {
		return nil
	}
	targetRepo := strings.TrimSpace(d.Repository)
	targetRef := strings.TrimSpace(d.Ref)
	if targetRef == "" {
		targetRef = run.Ref
	}
	event := strings.TrimSpace(d.Event)
	if event == "" {
		event = "upstream"
	}
	token, err := newID()
	if err != nil {
		return err
	}
	forgeKind := forgeKindForHost(repoHost(repoIDForRun(run)))
	baseURL := s.forgeBaseURL(forgeKind)
	link := storage.DownstreamLink{
		ParentJobID: j.ID,
		TargetRepo:  targetRepo,
		TargetRef:   targetRef,
		LaunchToken: token,
		TargetForge: forgeKind,
		// The persisted target RepoID is the canonical identity of the
		// child repository under the target forge/host; dispatch uses it
		// for authorization and for the child run's RepoID, never
		// re-deriving from a bare name.
		TargetBaseURL: baseURL,
		TargetRepoID:  auth.CanonicalRepoID(downstreamForgeHost(forgeKind, baseURL), targetRepo),
		// The stable launch key is derived at record time so every launch
		// of this link reuses the SAME child run ID.
		StableChildID: downstreamStableKey(j.ID, targetRepo, targetRef),
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.insertDownstreamLink(ctx, link); err != nil {
		return fmt.Errorf("downstream: link insert failed: %w", err)
	}
	payload := downstreamPayload{
		ParentJobID: j.ID,
		ParentRunID: run.ID,
		TargetRepo:  targetRepo,
		TargetRef:   targetRef,
		LaunchToken: token,
		Event:       event,
		Wait:        d.Wait,
		Inputs:      cloneMap(d.Inputs),
		Forge:       forgeKind,
		Trusted:     downstreamChildTrusted(j),
	}
	raw, err := jsonMarshal(payload)
	if err != nil {
		return err
	}
	item := forge.OutboxItem{Kind: forge.OutboxKindDownstream, Payload: raw, CreatedAt: time.Now().UTC()}
	if err := s.outbox.Enqueue(item); err != nil {
		return fmt.Errorf("downstream: outbox enqueue failed: %w", err)
	}
	return nil
}

// recordDownstreamIntentsForCompleted re-applies the downstream intent
// recording for an already-completed job. It is the recovery path for a
// completion whose durable commit succeeded but whose intent recording
// failed: the idempotent completion replay calls it before acknowledging.
func (s *Server) recordDownstreamIntentsForCompleted(ctx context.Context, jobID string) error {
	if s.DB != nil {
		j, err := s.DB.GetJob(ctx, jobID)
		if err != nil {
			return err
		}
		if j.Status != model.StatusSuccess {
			return nil
		}
		run, err := s.DB.GetRun(ctx, j.RunID)
		if err != nil {
			return err
		}
		return s.recordDownstreamIntents(ctx, j, run)
	}
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	run, runOK := s.runs[j.RunID]
	s.mu.Unlock()
	if !ok || !runOK || j.Status != model.StatusSuccess {
		return nil
	}
	return s.recordDownstreamIntents(ctx, j, run)
}

// forgeBaseURL returns the configured API base URL override for a forge
// kind (empty means the forge's public endpoint).
func (s *Server) forgeBaseURL(forgeKind string) string {
	switch forgeKind {
	case "github":
		return s.gitHubAPIBase
	case "gitlab":
		return s.gitLabAPIBase
	case "forgejo":
		return s.forgejoAPIBase
	}
	return ""
}

// SetForgeBaseURL overrides the API base URL for one forge adapter (the
// production wiring sets it for self-hosted Forgejo/GitLab instances).
func (s *Server) SetForgeBaseURL(forgeName, baseURL string) {
	switch forgeName {
	case "github":
		s.gitHubAPIBase = baseURL
	case "gitlab":
		s.gitLabAPIBase = baseURL
	case "forgejo":
		s.forgejoAPIBase = baseURL
	}
}

// downstreamChildTrusted reports whether the child run may inherit the
// parent's trust: only when the parent was trusted AND its effective
// capabilities carried the cross_repo_trigger grant.
func downstreamChildTrusted(j model.Job) bool {
	if !j.Trusted {
		return false
	}
	caps, ok := effectiveCapsOf(j)
	if !ok {
		return false
	}
	return caps.CrossRepoTrigger
}

// effectiveCapsOf decodes the job's stored effective policy into a
// capability set. The stored value is `any` (json.RawMessage on write,
// decoded JSON after a store round-trip), so it is re-marshaled first.
func effectiveCapsOf(j model.Job) (policy.Capabilities, bool) {
	if j.CompiledJobPayload == nil || j.CompiledJobPayload.EffectivePolicy == nil {
		return policy.Capabilities{}, false
	}
	b, err := jsonMarshal(j.CompiledJobPayload.EffectivePolicy)
	if err != nil {
		return policy.Capabilities{}, false
	}
	var caps policy.Capabilities
	if err := json.Unmarshal(b, &caps); err != nil {
		return policy.Capabilities{}, false
	}
	return caps, true
}

// downstreamStore resolves the durable downstream claim store in DB mode.
func (s *Server) downstreamStore() (storage.DownstreamStore, bool) {
	if s.DB == nil {
		return nil, false
	}
	ds, ok := s.DB.(storage.DownstreamStore)
	return ds, ok
}

// insertDownstreamLink records the launch claim idempotently: through the
// DownstreamStore in DB mode, in the fs-mode snapshot map otherwise.
func (s *Server) insertDownstreamLink(ctx context.Context, l storage.DownstreamLink) error {
	if ds, ok := s.downstreamStore(); ok {
		return ds.InsertDownstreamLink(ctx, l)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := downstreamLinkKey(l.ParentJobID, l.TargetRepo, l.TargetRef)
	if _, exists := s.downstreamLinks[key]; exists {
		return nil
	}
	s.downstreamLinks[key] = l
	return s.persistLocked()
}

// getDownstreamLink reads the launch claim.
func (s *Server) getDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (storage.DownstreamLink, bool, error) {
	if ds, ok := s.downstreamStore(); ok {
		return ds.GetDownstreamLink(ctx, parentJobID, targetRepo, targetRef)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.downstreamLinks[downstreamLinkKey(parentJobID, targetRepo, targetRef)]
	return l, ok, nil
}

func downstreamLinkKey(parentJobID, targetRepo, targetRef string) string {
	return parentJobID + "\x00" + targetRepo + "\x00" + targetRef
}

// dispatchDownstream processes one downstream outbox intent with the
// reserve-first flow: the link reservation is claimed atomically BEFORE the
// child run is enqueued, so concurrent flushers (and restarts) can never
// launch the same child twice. The child run ID is the STABLE launch key
// derived from (parent_job, target_repo, target_ref): the child run and the
// link update (ChildRunID + stable key) commit in ONE transaction inside
// the enqueue, so a crash between the reservation and the child launch
// leaves a reserved-but-unlaunched link that recovery re-dispatches with
// the SAME stable child ID (never a duplicate). A failed fetch/enqueue
// releases the reservation so the next flush can retry.
func (s *Server) dispatchDownstream(ctx context.Context, item forge.OutboxItem) error {
	var p downstreamPayload
	if err := json.Unmarshal(item.Payload, &p); err != nil {
		return err
	}
	if p.ParentJobID == "" || p.TargetRepo == "" || p.TargetRef == "" {
		return fmt.Errorf("downstream: incomplete intent payload")
	}
	// The stable launch key: deterministic across replays and restarts.
	stableKey := downstreamStableKey(p.ParentJobID, p.TargetRepo, p.TargetRef)
	stableChildID := downstreamStableChildRunID(stableKey)
	// The persisted link carries the forge identity coordinates; a replay
	// that dropped the in-memory copy falls back to the payload.
	link, ok, err := s.getDownstreamLink(ctx, p.ParentJobID, p.TargetRepo, p.TargetRef)
	if err != nil {
		return err
	}
	forgeKind := p.Forge
	baseURL := ""
	if ok {
		if link.ChildRunID != "" {
			s.metricAdd("kiwi_downstream_skips_total", 1, nil)
			return nil
		}
		if link.TargetForge != "" {
			forgeKind = link.TargetForge
		}
		baseURL = link.TargetBaseURL
	}
	// The target's canonical identity: the persisted RepoID when the link
	// recorded one, otherwise derived from the target forge host. Bare
	// target names are only the human-readable coordinate.
	var targetRepoID string
	if id := strings.TrimSpace(link.TargetRepoID); id != "" && id != strings.TrimSpace(p.TargetRepo) {
		targetRepoID = id
	} else {
		targetRepoID = auth.CanonicalRepoID(downstreamForgeHost(forgeKind, baseURL), p.TargetRepo)
	}
	// Bilateral authorization: the TARGET repository's policy must consent
	// to the dispatch. Without an allowlist entry for the target's canonical
	// identity (or, as an explicitly configured alias, its bare name —
	// default deny) the intent is refused with an audit event and dropped (a
	// nil error acks the outbox item, removing it from the queue).
	if !s.downstreamAllowed(ctx, p, targetRepoID) {
		s.metricAdd("kiwi_downstream_skips_total", 1, nil)
		s.auditLocked("downstream.refused", "scheduler", p.ParentRunID, p.ParentJobID, "downstream dispatch refused: target policy does not allow this source repository", map[string]string{"target_repo": targetRepoID, "target_ref": p.TargetRef})
		return nil
	}
	// Reserve FIRST: the reservation is the exactly-once claim. Exactly one
	// concurrent flusher wins; the others skip.
	won, err := s.reserveDownstreamLaunch(ctx, p.ParentJobID, p.TargetRepo, p.TargetRef, p.LaunchToken)
	if err != nil {
		return err
	}
	if !won {
		s.metricAdd("kiwi_downstream_skips_total", 1, nil)
		return nil
	}

	content, err := s.fetchDownstreamPipeline(ctx, forgeKind, baseURL, p.TargetRepo, p.TargetRef)
	if err != nil {
		s.releaseDownstreamReservation(ctx, p.ParentJobID, p.TargetRepo, p.TargetRef)
		return fmt.Errorf("downstream: fetch pipeline for %s@%s: %w", p.TargetRepo, p.TargetRef, err)
	}

	meta := map[string]string{
		"downstream_of":    p.ParentRunID,
		"downstream_job":   p.ParentJobID,
		"downstream_token": p.LaunchToken,
	}
	for k, v := range p.Inputs {
		meta["input."+k] = v
	}
	// Trust ingress: the child inherits the parent's trust only when the
	// target repository's policy explicitly grants trusted ingress; every
	// other target receives an untrusted child.
	trusted := p.Trusted && s.downstreamTrustedIngress(targetRepoID, p.TargetRepo)
	// The child enqueue carries the downstream launch claim: the child run
	// (ID = the stable child ID) and the link update commit atomically.
	// A replayed dispatch whose link is already launched with the same
	// stable ID returns the existing child run.
	child, err := s.enqueueID(SubmitRun{
		RepoID:       targetRepoID,
		RepoURL:      downstreamCloneURL(forgeKind, baseURL, p.TargetRepo),
		RepoFullName: p.TargetRepo,
		Ref:          p.TargetRef,
		Event:        p.Event,
		Pipeline:     content,
		Trusted:      trusted,
		Metadata:     meta,
		DownstreamLaunch: &storage.DownstreamLaunchClaim{
			LinkKey:       downstreamLinkKey(p.ParentJobID, p.TargetRepo, p.TargetRef),
			StableChildID: stableKey,
		},
	}, stableChildID)
	if err != nil {
		s.releaseDownstreamReservation(ctx, p.ParentJobID, p.TargetRepo, p.TargetRef)
		return fmt.Errorf("downstream: enqueue child run: %w", err)
	}
	if p.Wait {
		s.appendDownstreamRun(ctx, p.ParentRunID, child.ID)
	}
	s.metricAdd("kiwi_downstream_launches_total", 1, nil)
	s.auditLocked("downstream.launched", "scheduler", p.ParentRunID, p.ParentJobID, "downstream run launched", map[string]string{"target_repo": p.TargetRepo, "target_ref": p.TargetRef, "child_run": child.ID})
	return nil
}

// downstreamStableKey derives the launch idempotency key for one
// downstream link: the sha256 hex of (parent_job, target_repo, target_ref).
// It is deterministic across replays, restarts and replicas, so every
// launch attempt of a link targets the SAME child run.
func downstreamStableKey(parentJobID, targetRepo, targetRef string) string {
	sum := sha256.Sum256([]byte(parentJobID + "\x00" + targetRepo + "\x00" + targetRef))
	return hex.EncodeToString(sum[:])
}

// downstreamStableChildRunID derives the child run ID from the stable
// launch key: the first 32 hex chars (the canonical 128-bit run-ID
// format), so recovery re-launches reuse the identical child ID.
func downstreamStableChildRunID(stableKey string) string {
	if len(stableKey) < 32 {
		return stableKey
	}
	return stableKey[:32]
}

// downstreamTrustedIngress resolves the trusted-ingress switch for a target:
// the canonical RepoID key wins; a bare name in the map is an EXPLICIT
// legacy alias.
func (s *Server) downstreamTrustedIngress(targetRepoID, bare string) bool {
	if v, ok := s.DownstreamTrustedIngress[targetRepoID]; ok {
		return v
	}
	return s.DownstreamTrustedIngress[bare]
}

// downstreamAllowed enforces the target repository's policy consent for one
// dispatch intent. Allowlist keys are canonical repository IDs
// ("<host>/<owner>/<name>"); a bare "owner/name" key is an EXPLICIT legacy
// alias applying to every forge presenting that name. A target without an
// entry refuses every source (default deny); an entry with an empty/nil
// source list allows any source; otherwise only the listed source
// repositories are allowed — compared by canonical identity, with a bare
// source entry an explicit alias. A parent run that cannot be resolved
// refuses the dispatch (fail closed).
func (s *Server) downstreamAllowed(ctx context.Context, p downstreamPayload, targetRepoID string) bool {
	sources, ok := s.DownstreamAllowlist[targetRepoID]
	if !ok {
		sources, ok = s.DownstreamAllowlist[p.TargetRepo]
	}
	if !ok {
		return false
	}
	if len(sources) == 0 {
		return true
	}
	var run model.Run
	if s.DB != nil {
		r, err := s.DB.GetRun(ctx, p.ParentRunID)
		if err != nil {
			return false
		}
		run = r
	} else {
		s.mu.Lock()
		r, rok := s.runs[p.ParentRunID]
		s.mu.Unlock()
		if !rok {
			return false
		}
		run = r
	}
	source := repoIDForRun(run)
	if source == "" {
		source = strings.TrimSpace(run.RepoFullName)
	}
	for _, allowed := range sources {
		// Canonical identity first; a bare full name in the allowlist is an
		// explicitly configured alias.
		if allowed == source || (run.RepoFullName != "" && allowed == run.RepoFullName) {
			return true
		}
	}
	return false
}

// reserveDownstreamLaunch claims the link reservation through the store
// (DB mode) or the fs-mode map.
func (s *Server) reserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	if ds, ok := s.downstreamStore(); ok {
		return ds.ReserveDownstreamLaunch(ctx, parentJobID, targetRepo, targetRef, launchToken)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := downstreamLinkKey(parentJobID, targetRepo, targetRef)
	l, exists := s.downstreamLinks[key]
	if !exists {
		now := time.Now().UTC()
		s.downstreamLinks[key] = storage.DownstreamLink{ParentJobID: parentJobID, TargetRepo: targetRepo, TargetRef: targetRef, LaunchToken: launchToken, Reserved: true, ReservedAt: &now, CreatedAt: now}
		return true, s.persistLocked()
	}
	if l.ChildRunID != "" || l.Reserved {
		return false, nil
	}
	now := time.Now().UTC()
	l.Reserved = true
	l.ReservedAt = &now
	if l.LaunchToken == "" {
		l.LaunchToken = launchToken
	}
	s.downstreamLinks[key] = l
	if err := s.persistLocked(); err != nil {
		l.Reserved = false
		l.ReservedAt = nil
		s.downstreamLinks[key] = l
		return false, err
	}
	return true, nil
}

// releaseDownstreamReservation clears a reservation whose launch failed.
func (s *Server) releaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) {
	if ds, ok := s.downstreamStore(); ok {
		if err := ds.ReleaseDownstreamReservation(ctx, parentJobID, targetRepo, targetRef); err != nil {
			s.logError("downstream: release reservation failed", "error", err.Error())
		}
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := downstreamLinkKey(parentJobID, targetRepo, targetRef)
	l, ok := s.downstreamLinks[key]
	if !ok || l.ChildRunID != "" {
		return
	}
	l.Reserved = false
	l.ReservedAt = nil
	s.downstreamLinks[key] = l
	_ = s.persistLocked()
}

// recoverDownstreamReservations expires reservations older than one hour
// whose child never launched (crash between reserve and enqueue) so a
// replayed dispatch can re-reserve and launch them. Leader-only in DB mode.
func (s *Server) recoverDownstreamReservations(ctx context.Context, now time.Time) {
	if ds, ok := s.downstreamStore(); ok {
		if n, err := ds.ExpireDownstreamReservations(ctx, now.Add(-time.Hour)); err != nil {
			s.logError("downstream: reservation expiry failed", "error", err.Error())
		} else if n > 0 {
			s.logInfo("downstream: expired reserved-but-unlaunched links", "count", n)
		}
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for key, l := range s.downstreamLinks {
		if !l.Reserved || l.ChildRunID != "" {
			continue
		}
		if l.ReservedAt == nil || l.ReservedAt.Before(now.Add(-time.Hour)) {
			l.Reserved = false
			l.ReservedAt = nil
			s.downstreamLinks[key] = l
			changed = true
		}
	}
	if changed {
		_ = s.persistLocked()
	}
}

// appendDownstreamRun records the child run on the parent run for wait=true
// aggregation and refreshes the parent's status.
func (s *Server) appendDownstreamRun(ctx context.Context, parentRunID, childRunID string) {
	if s.DB != nil {
		if rs, ok := s.DB.(storage.RunDownstreamStore); ok {
			if err := rs.AppendDownstreamRun(ctx, parentRunID, childRunID); err != nil {
				s.logError("downstream: append child run failed", "run", parentRunID, "error", err.Error())
			}
		}
		s.adjustRunForChildrenDB(ctx, parentRunID)
		return
	}
	s.mu.Lock()
	run, ok := s.runs[parentRunID]
	if !ok {
		s.mu.Unlock()
		return
	}
	if !stringSliceContains(run.DownstreamRuns, childRunID) {
		run.DownstreamRuns = append(run.DownstreamRuns, childRunID)
		s.runs[parentRunID] = run
	}
	s.refreshRunLocked(parentRunID)
	_ = s.persistLocked()
	s.mu.Unlock()
}

// fetchDownstreamPipeline resolves the target pipeline text: the injected
// test seam wins; otherwise the forge adapter named by the persisted forge
// coordinates fetches the configured pipeline file at the target ref. The
// baseURL override (persisted on the link) replaces the API host for
// self-hosted Forgejo/GitLab instances — no host heuristics from
// hard-coded public endpoints.
func (s *Server) fetchDownstreamPipeline(ctx context.Context, forgeKind, baseURL, targetRepo, targetRef string) (string, error) {
	if s.DownstreamPipelineFetcher != nil {
		return s.DownstreamPipelineFetcher(ctx, targetRepo, targetRef)
	}
	path := s.pipelinePath()
	switch forgeKind {
	case "github":
		f := s.gitHubForge()
		if baseURL != "" {
			f.BaseURL = baseURL
		}
		return f.FetchFile(ctx, targetRepo, path, targetRef)
	case "gitlab":
		f := s.gitLabForge()
		if baseURL != "" {
			f.BaseURL = baseURL
		}
		return f.FetchFile(ctx, targetRepo, path, targetRef)
	case "forgejo":
		f := s.forgejoForge()
		if baseURL != "" {
			f.BaseURL = baseURL
		}
		return f.FetchFile(ctx, targetRepo, path, targetRef)
	default:
		// Unknown forge: try the adapters in order; the first success wins.
		var lastErr error
		for _, f := range []forge.Forge{s.gitHubForge(), s.gitLabForge(), s.forgejoForge()} {
			content, err := f.FetchFile(ctx, targetRepo, path, targetRef)
			if err == nil {
				return content, nil
			}
			lastErr = err
		}
		return "", lastErr
	}
}

// forgeKindForHost maps a repository host to its forge adapter kind. This
// runs once at record time; dispatch uses the persisted coordinates.
func forgeKindForHost(host string) string {
	switch {
	case host == "github.com" || strings.HasSuffix(host, ".github.com"):
		return "github"
	case host == "gitlab.com" || strings.HasSuffix(host, ".gitlab.com"):
		return "gitlab"
	case strings.Contains(host, "forgejo") || strings.Contains(host, "codeberg"):
		return "forgejo"
	default:
		return ""
	}
}

// downstreamCloneURL reconstructs the child run's clone URL from the
// persisted forge coordinates: the base URL override (self-hosted) wins,
// otherwise the forge's public host.
func downstreamCloneURL(forgeKind, baseURL, repo string) string {
	return "https://" + downstreamForgeHost(forgeKind, baseURL) + "/" + repo
}

// downstreamForgeHost resolves the target forge host of a downstream child
// from the persisted coordinates: the configured/self-hosted base URL host
// wins, otherwise the forge's public host. The child run's RepoID derives
// its host from here, so it is stable across replays.
func downstreamForgeHost(forgeKind, baseURL string) string {
	if h := repoHost(baseURL); h != "" {
		return h
	}
	return publicForgeHost(forgeKind)
}

// refreshDownstreamParentsLocked re-aggregates every parent run that waits
// on childRunID (memory mode).
func (s *Server) refreshDownstreamParentsLocked(childRunID string) {
	for id, run := range s.runs {
		if stringSliceContains(run.DownstreamRuns, childRunID) {
			s.refreshRunLocked(id)
		}
	}
}

// refreshDownstreamParentsDB re-aggregates every parent run that waits on
// childRunID (DB mode).
func (s *Server) refreshDownstreamParentsDB(ctx context.Context, childRunID string) {
	runs, err := s.DB.ListRuns(ctx, 10000)
	if err != nil {
		return
	}
	for _, run := range runs {
		if stringSliceContains(run.DownstreamRuns, childRunID) {
			s.adjustRunForChildrenDB(ctx, run.ID)
		}
	}
}

// adjustRunForChildrenDB applies the wait=true aggregation over one run's
// downstream children in DB mode. It is called when a child is appended and
// when a child run completes; the run row is reopened while any child is
// still in flight and finalized from the child outcomes when they finish.
func (s *Server) adjustRunForChildrenDB(ctx context.Context, runID string) {
	run, err := s.DB.GetRun(ctx, runID)
	if errors.Is(err, storage.ErrNotFound) || err != nil {
		return
	}
	if len(run.DownstreamRuns) == 0 {
		return
	}
	if run.Status.Terminal() && run.Status != model.StatusSuccess {
		return
	}
	jobs, err := s.DB.ListJobsByRun(ctx, runID)
	if err != nil {
		return
	}
	ownAllTerminal := true
	ownFailure := false
	ownCancelled := false
	for _, j := range jobs {
		if !j.Status.Terminal() {
			ownAllTerminal = false
		}
		if j.Status == model.StatusFailure || j.Status == model.StatusBlocked {
			ownFailure = true
		}
		if j.Status == model.StatusCancelled {
			ownCancelled = true
		}
	}
	if !ownAllTerminal {
		return
	}
	allTerminal := true
	anyFailure := false
	anyCancelled := false
	for _, childID := range run.DownstreamRuns {
		child, cerr := s.DB.GetRun(ctx, childID)
		if errors.Is(cerr, storage.ErrNotFound) {
			continue
		}
		if cerr != nil {
			continue
		}
		if !child.Status.Terminal() {
			allTerminal = false
		}
		if child.Status == model.StatusFailure || child.Status == model.StatusBlocked {
			anyFailure = true
		}
		if child.Status == model.StatusCancelled {
			anyCancelled = true
		}
	}
	switch {
	case ownFailure:
		return
	case ownCancelled:
		return
	case !allTerminal:
		if run.Status != model.StatusRunning {
			if rs, ok := s.DB.(storage.RunDownstreamStore); ok {
				_ = rs.ReopenRunForChildren(ctx, runID)
			}
		}
		return
	case anyFailure:
		fin := time.Now().UTC()
		if err := s.DB.UpdateRunStatus(ctx, runID, model.StatusFailure, nil, &fin); err != nil {
			s.logError("downstream: finalize parent failure failed", "run", runID, "error", err.Error())
		}
	case anyCancelled:
		fin := time.Now().UTC()
		if err := s.DB.UpdateRunStatus(ctx, runID, model.StatusCancelled, nil, &fin); err != nil {
			s.logError("downstream: finalize parent cancelled failed", "run", runID, "error", err.Error())
		}
	}
}

func stringSliceContains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// applyDownstreamChildrenLocked aggregates wait=true downstream children
// into a run's status (memory mode; caller holds s.mu and passes the run's
// own-job aggregation). A run whose own jobs all succeeded stays running
// while any child is in flight, and inherits child failures/cancellations
// once every child is terminal.
func (s *Server) applyDownstreamChildrenLocked(runID string, run *model.Run) {
	if len(run.DownstreamRuns) == 0 {
		return
	}
	if run.Status != model.StatusSuccess {
		return
	}
	allTerminal := true
	anyFailure := false
	anyCancelled := false
	for _, childID := range run.DownstreamRuns {
		child, ok := s.runs[childID]
		if !ok {
			continue
		}
		if !child.Status.Terminal() {
			allTerminal = false
		}
		if child.Status == model.StatusFailure || child.Status == model.StatusBlocked {
			anyFailure = true
		}
		if child.Status == model.StatusCancelled {
			anyCancelled = true
		}
	}
	if !allTerminal {
		run.Status = model.StatusRunning
		run.FinishedAt = nil
		return
	}
	switch {
	case anyFailure:
		run.Status = model.StatusFailure
	case anyCancelled:
		run.Status = model.StatusCancelled
	}
}

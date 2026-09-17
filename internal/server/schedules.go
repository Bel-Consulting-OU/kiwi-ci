package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"gopkg.in/yaml.v3"
)

const schedulesFile = "schedules.json"

// schedulesFileJSON is the fs-mode persistence format for schedules and
// their claimed occurrences.
type schedulesFileJSON struct {
	Schedules   []storage.Schedule          `json:"schedules"`
	Occurrences map[string]map[int64]string `json:"occurrences"`
}

// scheduleRequest is the PUT /api/v1/schedules body. Repository is the
// human-readable repository name (owner/name); RepoURL is the clone URL the
// canonical identity and the forge kind are derived from; Trusted requests
// a trusted schedule (requires the repo-scoped trusted_run grant on top of
// policy_manage). The canonical RepoID and the Forge kind are derived
// server-side from (RepoURL, Repository) and REQUIRED on create, so
// automatic firing uses the immutable stored identity — never the request
// context. A bare repository name without a forge host is rejected: two
// forges presenting the same bare name must never share a schedule identity.
type scheduleRequest struct {
	ID         string `json:"id,omitempty"`
	Repository string `json:"repository"`
	RepoURL    string `json:"repo_url,omitempty"`
	Spec       string `json:"spec"`
	Enabled    *bool  `json:"enabled,omitempty"`
	Trusted    bool   `json:"trusted,omitempty"`
}

// scheduleRepoID resolves the stored canonical repository identity of a
// schedule: the RepoID field when present (authoritative), otherwise derived
// from the stored identity fields at load. Legacy rows stored the clone URL
// as both identity and clone URL, so a URL-shaped Repository is first
// reduced to its forge-native owner/name before canonicalization.
func scheduleRepoID(sc storage.Schedule) string {
	if id := strings.TrimSpace(sc.RepoID); id != "" {
		return id
	}
	fullName := strings.TrimSpace(sc.Repository)
	repoURL := strings.TrimSpace(scheduleRepoURL(sc))
	if fullName == repoURL {
		// Legacy row: repository carried its own identity, possibly the
		// clone URL itself.
		fullName = repoFullNameFromCloneURL(fullName)
	}
	return auth.CanonicalRepoID(repoHost(repoURL), fullName)
}

// scheduleRepoFullName resolves the human-readable repository name of a
// schedule (display only; legacy rows may still carry the clone URL).
func scheduleRepoFullName(sc storage.Schedule) string {
	return strings.TrimSpace(sc.Repository)
}

// scheduleRepoURL resolves the stored clone URL of a schedule: the RepoURL
// field when present, otherwise the legacy Repository value.
func scheduleRepoURL(sc storage.Schedule) string {
	if sc.RepoURL != "" {
		return sc.RepoURL
	}
	return sc.Repository
}

// parseScheduleSpec validates a schedule's pipeline text with the SAME
// strict parser used for every pipeline admission (pipeline.Parse) and
// extracts the cron expression plus the optional default branch from
// spec.On["schedule"]. The strict parse rejects malformed specs with line
// numbers before the cron is ever read; the schedule trigger is stripped
// before the spec is enqueued (sanitizeScheduleSpec).
func parseScheduleSpec(specText string) (cronSchedule, string, error) {
	spec, err := pipeline.Parse([]byte(specText))
	if err != nil {
		return cronSchedule{}, "", err
	}
	if len(spec.Jobs) == 0 {
		return cronSchedule{}, "", errors.New("schedule spec must declare at least one job")
	}
	sc := spec.On["schedule"]
	if len(sc.Cron) == 0 || sc.Cron[0].Cron == "" {
		return cronSchedule{}, "", errors.New("schedule spec must declare on.schedule.cron")
	}
	cron, err := ParseCron(sc.Cron[0].Cron)
	if err != nil {
		return cronSchedule{}, "", err
	}
	ref := ""
	if len(sc.Cron[0].Branches) > 0 {
		ref = strings.TrimSpace(sc.Cron[0].Branches[0])
		if !strings.HasPrefix(ref, "refs/") {
			ref = "refs/heads/" + ref
		}
	}
	return cron, ref, nil
}

// sanitizeScheduleSpec strips the on.schedule trigger from a schedule's
// pipeline text before enqueueing, so the admitted spec passes the strict
// pipeline schema while the schedule declaration stays in the stored spec.
func sanitizeScheduleSpec(specText string) string {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(specText), &doc); err != nil {
		return specText
	}
	if on, ok := doc["on"].(map[string]any); ok {
		delete(on, "schedule")
		if len(on) == 0 {
			delete(doc, "on")
		}
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return specText
	}
	return string(out)
}

// scheduleStore reports whether the server has a durable schedule store
// (SQL in DB mode, the in-memory+file store otherwise).
func (s *Server) scheduleStoreDB() (storage.ScheduleStore, bool) {
	if s.DB == nil {
		return nil, false
	}
	ss, ok := s.DB.(storage.ScheduleStore)
	return ss, ok
}

// loadSchedules restores fs-mode schedules from dataDir/schedules.json.
func (s *Server) loadSchedules(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	b, err := readFileIfExists(dataDir, schedulesFile)
	if err != nil {
		return err
	}
	if b == nil {
		return nil
	}
	var f schedulesFileJSON
	if err := jsonUnmarshal(b, &f); err != nil {
		return err
	}
	for _, sc := range f.Schedules {
		s.schedules[sc.ID] = sc
	}
	for id, occ := range f.Occurrences {
		s.occurrences[id] = occ
	}
	return nil
}

// reloadSchedulesDB loads schedules from the SQL store into memory.
func (s *Server) reloadSchedulesDB(ctx context.Context) error {
	ss, ok := s.scheduleStoreDB()
	if !ok {
		return nil
	}
	list, err := ss.ListSchedules(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	for _, sc := range list {
		s.schedules[sc.ID] = sc
	}
	s.mu.Unlock()
	return nil
}

// persistSchedulesLocked atomically writes fs-mode schedules. Callers hold
// s.mu. DB mode schedules live in the SQL store; the fs file is untouched.
func (s *Server) persistSchedulesLocked() error {
	if s.dataDir == "" || s.DB != nil {
		return nil
	}
	f := schedulesFileJSON{
		Schedules:   make([]storage.Schedule, 0, len(s.schedules)),
		Occurrences: s.occurrences,
	}
	for _, sc := range s.schedules {
		f.Schedules = append(f.Schedules, sc)
	}
	sort.Slice(f.Schedules, func(i, j int) bool { return f.Schedules[i].ID < f.Schedules[j].ID })
	return marshalJSONFile(joinDataDir(s.dataDir, schedulesFile), f)
}

// listSchedules implements GET /api/v1/schedules. Authorization requires
// the policy-manage role (or admin).
func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionPolicyManage, "", false) {
		return
	}
	if ss, ok := s.scheduleStoreDB(); ok {
		out, err := ss.ListSchedules(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
		writeJSON(w, http.StatusOK, out)
		return
	}
	s.mu.Lock()
	out := make([]storage.Schedule, 0, len(s.schedules))
	for _, sc := range s.schedules {
		out = append(out, sc)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

// upsertSchedule implements PUT /api/v1/schedules. Authorization requires
// the policy-manage role (or admin). The spec is the full pipeline text;
// its on.schedule.cron drives firing.
func (s *Server) upsertSchedule(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionPolicyManage, "", false) {
		return
	}
	var in scheduleRequest
	if !decode(w, r, &in) {
		return
	}
	actor := actorFrom(r)
	in.Repository = strings.TrimSpace(in.Repository)
	if in.Repository == "" {
		http.Error(w, "repository is required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.Spec) == "" {
		http.Error(w, "spec is required", http.StatusBadRequest)
		return
	}
	if _, _, err := parseScheduleSpec(in.Spec); err != nil {
		http.Error(w, "invalid schedule spec: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Identity derivation: Repository is the human-readable name, RepoURL
	// the clone URL. The canonical RepoID and the Forge kind are derived
	// once and stored, so automatic firing uses the immutable stored
	// identity. A URL-shaped Repository (the legacy form that stored the
	// clone URL as identity) is reduced to its forge-native owner/name; the
	// canonical identity is REQUIRED: a repository without a forge host
	// cannot be scheduled, because a bare name is shared across forges.
	repoURL := strings.TrimSpace(in.RepoURL)
	if repoURL == "" {
		repoURL = in.Repository
	}
	repoID := auth.CanonicalRepoID(repoHost(repoURL), in.Repository)
	if u, err := url.Parse(in.Repository); err == nil && u.Host != "" {
		fullName := repoFullNameFromCloneURL(in.Repository)
		if fullName == "" {
			http.Error(w, "repository URL names no repository path", http.StatusBadRequest)
			return
		}
		repoID = auth.CanonicalRepoID(repoHost(in.Repository), fullName)
	}
	if strings.Count(repoID, "/") < 2 {
		http.Error(w, "repo_url is required to derive the canonical repository identity (host/owner/name)", http.StatusBadRequest)
		return
	}
	if in.Trusted {
		// A TRUSTED schedule fires with trusted capabilities: creating or
		// updating one requires the repo-scoped trusted_run grant for the
		// schedule's repository, in addition to policy_manage.
		if !s.requireAction(w, r, auth.ActionTrustedRun, repoID, true) {
			return
		}
	}
	now := time.Now().UTC()
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	var sc storage.Schedule
	var action string
	if ss, ok := s.scheduleStoreDB(); ok {
		if in.ID != "" {
			existing, err := ss.ListSchedules(r.Context())
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			for _, e := range existing {
				if e.ID == in.ID {
					sc = e
					break
				}
			}
			action = "schedule.updated"
			if sc.ID == "" {
				sc = storage.Schedule{ID: in.ID, CreatedAt: now}
				action = "schedule.created"
			}
		} else {
			id, err := newID()
			if err != nil {
				http.Error(w, "internal server error", 500)
				return
			}
			sc = storage.Schedule{ID: id, CreatedAt: now}
			action = "schedule.created"
		}
		sc.Repository = in.Repository
		sc.RepoID = repoID
		sc.RepoURL = repoURL
		sc.Forge = forgeKindForHost(repoHost(repoURL))
		sc.Trusted = in.Trusted
		sc.Spec = in.Spec
		sc.Enabled = enabled
		sc.CreatedBy = actorFrom(r)
		if err := ss.UpsertSchedule(r.Context(), sc); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.mu.Lock()
		s.schedules[sc.ID] = sc
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		if in.ID != "" {
			sc = s.schedules[in.ID]
			action = "schedule.updated"
			if sc.ID == "" {
				sc = storage.Schedule{ID: in.ID, CreatedAt: now}
				action = "schedule.created"
			}
		} else {
			id, err := newID()
			if err != nil {
				s.mu.Unlock()
				http.Error(w, "internal server error", 500)
				return
			}
			sc = storage.Schedule{ID: id, CreatedAt: now}
			action = "schedule.created"
		}
		sc.Repository = in.Repository
		sc.RepoID = repoID
		sc.RepoURL = repoURL
		sc.Forge = forgeKindForHost(repoHost(repoURL))
		sc.Trusted = in.Trusted
		sc.Spec = in.Spec
		sc.Enabled = enabled
		sc.CreatedBy = actorFrom(r)
		s.schedules[sc.ID] = sc
		persistErr := s.persistSchedulesLocked()
		s.mu.Unlock()
		if persistErr != nil {
			http.Error(w, persistErr.Error(), 500)
			return
		}
	}
	s.auditLocked(action, actor, "", "", action, map[string]string{"schedule": sc.ID, "repository": sc.Repository})
	writeJSON(w, http.StatusOK, sc)
}

// triggerSchedule implements POST /api/v1/schedules/{id}/trigger: it fires
// the schedule immediately for the current nominal minute. Authorization
// requires the policy-manage role (or admin).
func (s *Server) triggerSchedule(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionPolicyManage, "", false) {
		return
	}
	id := r.PathValue("id")
	actor := actorFrom(r)
	sc, err := s.scheduleByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	// Manual trigger re-checks the trusted_run grant for TRUSTED schedules:
	// a principal whose grant was revoked after creation must not be able
	// to fire the schedule manually. The re-check resolves the schedule's
	// STORED identity, never the request context.
	if sc.Trusted && !s.requireAction(w, r, auth.ActionTrustedRun, scheduleRepoID(sc), true) {
		return
	}
	nominal := time.Now().UTC().Truncate(time.Minute)
	run, fired, err := s.fireSchedule(r.Context(), sc, nominal)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !fired {
		http.Error(w, "schedule occurrence already fired for this nominal minute", http.StatusConflict)
		return
	}
	s.auditLocked("schedule.triggered", actor, run.ID, "", "schedule triggered manually", map[string]string{"schedule": sc.ID, "nominal": nominal.Format(time.RFC3339)})
	writeJSON(w, http.StatusAccepted, run)
}

// scheduleByID loads one schedule from the DB or memory store.
func (s *Server) scheduleByID(ctx context.Context, id string) (storage.Schedule, error) {
	if ss, ok := s.scheduleStoreDB(); ok {
		list, err := ss.ListSchedules(ctx)
		if err != nil {
			return storage.Schedule{}, err
		}
		for _, sc := range list {
			if sc.ID == id {
				return sc, nil
			}
		}
		return storage.Schedule{}, storage.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.schedules[id]
	if !ok {
		return storage.Schedule{}, storage.ErrNotFound
	}
	return sc, nil
}

// fireDueSchedules is the Maintain-tick entry point: it fires every
// due nominal occurrence. The occurrence claim rides INSIDE the enqueue
// transaction, so a failed enqueue leaves the nominal unclaimed and the
// next tick refires it; only successful enqueues (or occurrences claimed
// by another instance) advance LastRun.
func (s *Server) fireDueSchedules(ctx context.Context, now time.Time) {
	// Collect the due occurrences first (without advancing) so a failing
	// schedule cannot spin the tick loop or starve other schedules.
	type dueFire struct {
		sc      storage.Schedule
		nominal time.Time
	}
	seen := map[string]bool{}
	var dues []dueFire
	for i := 0; i < 100; i++ {
		sc, nominal, ok := s.nextDueScheduleFrom(now, seen)
		if !ok {
			break
		}
		key := sc.ID + "\x00" + nominal.UTC().Format(time.RFC3339Nano)
		seen[key] = true
		dues = append(dues, dueFire{sc, nominal})
	}
	for _, d := range dues {
		if _, fired, err := s.fireSchedule(ctx, d.sc, d.nominal); err != nil {
			if errors.Is(err, errScheduleUnauthorized) {
				// Trust revoked: skip this occurrence (already audited) and
				// advance, so the schedule does not spin retrying it.
				s.advanceSchedulePast(ctx, d.sc, d.nominal)
				continue
			}
			s.logError("schedule fire failed", "schedule", d.sc.ID, "error", err.Error())
			// The occurrence claim was rolled back with the failed
			// enqueue: leave LastRun so the next tick refires it.
			continue
		} else if !fired {
			// Another instance claimed this nominal; skip ahead.
			s.advanceSchedulePast(ctx, d.sc, d.nominal)
			continue
		}
	}
}

// errScheduleUnauthorized marks a trusted occurrence whose creator lost the
// trusted_run grant: the caller advances the schedule past the nominal so it
// does not retry forever, and the skip is audited.
var errScheduleUnauthorized = errors.New("schedule trust revoked")

// scheduleTrustStillGranted reports whether the stored creator principal
// still holds trusted_run for the schedule's repository. Legacy open mode
// (no principal store configured) preserves historical behavior.
func (s *Server) scheduleTrustStillGranted(sc storage.Schedule) bool {
	if s.AuthStore == nil || s.AuthStore.Empty() {
		// Open mode: no principal-based authorization is configured, so
		// creation-time trusted_run was vacuous too. Revocation applies
		// only once principals exist.
		return true
	}
	if sc.CreatedBy == "" {
		// Pre-migration rows have no creator: fail closed when a principal
		// store exists, because no one can be re-authorized.
		return false
	}
	p, ok := s.AuthStore.PrincipalBySubject(sc.CreatedBy)
	if !ok {
		return false
	}
	return auth.Authorize(p, auth.ActionTrustedRun, scheduleRepoID(sc), true)
}

// advanceSchedulePast moves the in-memory schedule's LastRun marker past a
// nominal that could not be (or was already) claimed, so the next tick
// evaluates the following occurrence instead of spinning.
func (s *Server) advanceSchedulePast(ctx context.Context, sc storage.Schedule, nominal time.Time) {
	if sc.LastRun == nil || sc.LastRun.Before(nominal) {
		sc.LastRun = &nominal
		s.mu.Lock()
		s.schedules[sc.ID] = sc
		s.mu.Unlock()
	}
}

// nextDueScheduleFrom returns the next enabled schedule with a due nominal
// occurrence not already in seen (the collection loop's skip set), or
// ok=false when nothing is due. Nominals are derived from LastRun/CreatedAt
// without advancing anything.
func (s *Server) nextDueScheduleFrom(now time.Time, seen map[string]bool) (storage.Schedule, time.Time, bool) {
	now = now.UTC()
	s.mu.Lock()
	ids := make([]string, 0, len(s.schedules))
	for id := range s.schedules {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	sort.Strings(ids)
	for _, id := range ids {
		s.mu.Lock()
		sc, ok := s.schedules[id]
		s.mu.Unlock()
		if !ok || !sc.Enabled {
			continue
		}
		cron, _, err := parseScheduleSpec(sc.Spec)
		if err != nil {
			continue
		}
		base := sc.CreatedAt
		if sc.LastRun != nil {
			base = *sc.LastRun
		}
		for i := 0; i < 64; i++ {
			next := cron.next(base)
			if next.IsZero() {
				break
			}
			if !next.After(now) {
				key := sc.ID + "\x00" + next.UTC().Format(time.RFC3339Nano)
				if !seen[key] {
					return sc, next, true
				}
				base = next
				continue
			}
			break
		}
	}
	return storage.Schedule{}, time.Time{}, false
}

// fireSchedule enqueues the scheduled run with its occurrence claim carried
// INSIDE the enqueue: in DB mode InsertCompiledRun inserts the occurrence
// row in the same transaction as the run (a failed enqueue leaves the
// occurrence unclaimed and the next tick refires it); in memory mode the
// claim lands under s.mu only after the run is committed. It reports
// fired=false when the nominal was already claimed by another run
// (duplicate trigger or another instance). The run is enqueued under the
// schedule's STORED immutable identity (RepoID, RepoURL, Trusted) — never
// the caller's request context.
func (s *Server) fireSchedule(ctx context.Context, sc storage.Schedule, nominal time.Time) (model.Run, bool, error) {
	// Trusted schedules are a REVOCABLE delegation: automatic firing
	// re-checks the creator principal's CURRENT grants (trusted_run for the
	// schedule's stored repository) when a principal store is configured.
	// A revoked creator stops producing trusted runs at the next
	// occurrence; the occurrence is skipped and audited, never downgraded
	// silently to an untrusted run.
	if sc.Trusted && !s.scheduleTrustStillGranted(sc) {
		s.auditLocked("schedule.unauthorized", "scheduler", "", "", "trusted schedule skipped: creator no longer holds trusted_run",
			map[string]string{"schedule": sc.ID, "creator": sc.CreatedBy, "repository": scheduleRepoID(sc)})
		return model.Run{}, false, errScheduleUnauthorized
	}
	preID, err := newID()
	if err != nil {
		return model.Run{}, false, err
	}
	_, ref, err := parseScheduleSpec(sc.Spec)
	if err != nil {
		return model.Run{}, false, err
	}
	in := SubmitRun{
		RepoID:       scheduleRepoID(sc),
		RepoURL:      scheduleRepoURL(sc),
		RepoFullName: scheduleRepoFullName(sc),
		Ref:          ref,
		Event:        "schedule",
		Pipeline:     sanitizeScheduleSpec(sc.Spec),
		Trusted:      sc.Trusted,
		Metadata:     map[string]string{"schedule_id": sc.ID, "schedule_nominal": nominal.Format(time.RFC3339)},
		// The occurrence claim commits atomically with the run.
		ScheduleClaim: &storage.ScheduleClaim{ScheduleID: sc.ID, Nominal: nominal},
	}
	run, err := s.enqueueID(in, preID)
	if err != nil {
		if errors.Is(err, storage.ErrScheduleClaimLost) {
			// Another instance claimed this nominal with a different run.
			return model.Run{}, false, nil
		}
		s.auditLocked("schedule.trigger_failed", "scheduler", "", "", "scheduled run rejected", map[string]string{"schedule": sc.ID, "error": err.Error()})
		return model.Run{}, false, err
	}
	nominalCopy := nominal
	sc.LastRun = &nominalCopy
	if ss, ok := s.scheduleStoreDB(); ok {
		if err := ss.UpsertSchedule(ctx, sc); err != nil {
			s.logError("schedule last_run update failed", "schedule", sc.ID, "error", err.Error())
		}
	}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	persistErr := s.persistSchedulesLocked()
	s.mu.Unlock()
	if persistErr != nil {
		s.logError("schedule persistence failed", "schedule", sc.ID, "error", persistErr.Error())
	}
	s.auditLocked("schedule.triggered", "scheduler", run.ID, "", "scheduled run enqueued", map[string]string{"schedule": sc.ID, "nominal": nominal.Format(time.RFC3339)})
	return run, true, nil
}

// claimScheduleOccurrenceLocked claims the (schedule, nominal) firing for
// runID under s.mu, reporting whether this call made the claim. A memory
// mode firing claims only after a successful in-memory enqueue.
func (s *Server) claimScheduleOccurrenceLocked(scheduleID string, nominal time.Time, runID string) bool {
	key := nominal.UTC().Unix()
	occ := s.occurrences[scheduleID]
	if occ == nil {
		occ = map[int64]string{}
		s.occurrences[scheduleID] = occ
	}
	if existing, ok := occ[key]; ok {
		return existing == runID
	}
	occ[key] = runID
	return true
}

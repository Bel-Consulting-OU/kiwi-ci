package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
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
// schedule: the RepoID field when present (authoritative, canonicalized so
// equivalent forge-host spellings agree), otherwise derived from the stored
// identity fields at load. Legacy rows stored the clone URL as both identity
// and clone URL, so a URL-shaped Repository is first reduced to its
// forge-native owner/name before canonicalization.
func scheduleRepoID(sc storage.Schedule) string {
	if id := strings.TrimSpace(sc.RepoID); id != "" {
		return auth.NormalizeRepoKey(id)
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

// bindScheduleRepoIdentity is the STRICT create/update binding for a
// schedule: repo_url is authoritative and the submitted Repository must
// canonicalize to the SAME repository path (and, when Repository is itself
// URL-shaped, the same host-scoped identity), case-insensitively with one
// ".git" suffix stripped. It returns the canonical forge host, the canonical
// RepoID, the clone URL to store and the normalized display name. The legacy
// form that carried the clone URL in Repository is still accepted, but the
// stored display name is normalized to the repository path.
func bindScheduleRepoIdentity(repository, repoURL string) (host, identity, cloneURL, display string, err error) {
	repo := strings.TrimSpace(repository)
	url := strings.TrimSpace(repoURL)
	if url == "" {
		// Legacy form: Repository itself carried the clone URL.
		url = repo
	}
	host, path, perr := parseCloneURL(url)
	if perr != nil {
		return "", "", "", "", fmt.Errorf("repo_url must be a clone URL naming a host and repository path: %w", perr)
	}
	identity = auth.CanonicalRepoID(host, path)
	if repo == "" {
		return "", "", "", "", errors.New("repository is required")
	}
	if dh, dp, derr := parseCloneURL(repo); derr == nil {
		if !strings.EqualFold(auth.CanonicalRepoID(dh, dp), identity) {
			return "", "", "", "", errors.New("repository URL does not match the host and repository path of repo_url")
		}
		display = dp
	} else {
		dp, ok := forgePathFromFullName(repo)
		if !ok || !strings.EqualFold(dp, path) {
			return "", "", "", "", fmt.Errorf("repository %q does not match the repository path %q of repo_url", repo, path)
		}
		display = dp
	}
	return host, identity, url, display, nil
}

// durableScheduleIdentity validates and normalizes one DURABLE schedule row
// (loaded from the SQL store or schedules.json). It returns a copy with the
// canonical RepoID/RepoURL/Forge populated, or an error describing why the
// stored identity cannot be trusted:
//
//   - the clone URL (RepoURL, or the legacy Repository-as-URL) must parse
//     through the strict parser;
//   - the stored Repository must name the same repository path — and, when
//     it is URL-shaped, the same host-scoped identity;
//   - a stored RepoID, when present, must equal the URL-derived canonical
//     identity (case-insensitively).
//
// A row with an EMPTY RepoID is the pre-RepoID legacy shape: it is accepted
// only when Repository/RepoURL agree, and the derived identity is filled in,
// so the row is migrated rather than grandfathered with an inconsistent one.
func durableScheduleIdentity(sc storage.Schedule) (storage.Schedule, error) {
	cloneURL := strings.TrimSpace(scheduleRepoURL(sc))
	if cloneURL == "" {
		return sc, errors.New("schedule has no clone URL")
	}
	host, path, err := parseCloneURL(cloneURL)
	if err != nil {
		return sc, fmt.Errorf("clone URL: %w", err)
	}
	identity := auth.CanonicalRepoID(host, path)
	display := strings.TrimSpace(sc.Repository)
	if display == "" {
		return sc, errors.New("schedule has no repository name")
	}
	displayPath, ok := forgePathFromFullName(display)
	if !ok || !strings.EqualFold(displayPath, path) {
		return sc, fmt.Errorf("repository %q does not match clone URL repository path %q", display, path)
	}
	if dh, dp, derr := parseCloneURL(display); derr == nil {
		if !strings.EqualFold(auth.CanonicalRepoID(dh, dp), identity) {
			return sc, fmt.Errorf("repository URL %q does not match repo_url %q", display, cloneURL)
		}
	}
	if stored := strings.TrimSpace(sc.RepoID); stored != "" {
		if !strings.EqualFold(auth.NormalizeRepoKey(stored), identity) {
			return sc, fmt.Errorf("stored repo_id %q does not match clone URL identity %q", stored, identity)
		}
	}
	sc.RepoID = identity
	if strings.TrimSpace(sc.RepoURL) == "" {
		sc.RepoURL = cloneURL
	}
	if sc.Forge == "" {
		sc.Forge = forgeKindForHost(host)
	}
	return sc, nil
}

// disabledSchedule is one durable schedule that failed load-time identity
// validation and was disabled (fail closed) with its reason.
type disabledSchedule struct {
	Schedule storage.Schedule
	Reason   string
}

// validateLoadedSchedules validates every durable schedule and DISABLES each
// one whose stored identity is inconsistent. Disabling is the policy for
// TRUSTED and UNTRUSTED rows alike (consistency; documented here): a durable
// row whose identity cannot be proven must never fire, and a disabled row is
// never silently re-enabled — fixing it requires an explicit API update,
// which re-runs the same binding checks. Kept rows carry the canonical
// identity fields.
func validateLoadedSchedules(list []storage.Schedule) (kept []storage.Schedule, disabled []disabledSchedule) {
	for _, sc := range list {
		valid, err := durableScheduleIdentity(sc)
		if err != nil {
			sc.Enabled = false
			kept = append(kept, sc)
			disabled = append(disabled, disabledSchedule{Schedule: sc, Reason: err.Error()})
			continue
		}
		kept = append(kept, valid)
	}
	return kept, disabled
}

// reportDisabledSchedules audits and logs every schedule disabled at load
// and persists the disabled state through the durable store (best effort;
// the in-memory row is already disabled, so the schedule never fires even if
// the write fails). Migration note: no schema change is required for this
// validation — it runs at load time, so a hand-crafted inconsistent row is
// quarantined on the next start.
func (s *Server) reportDisabledSchedules(ctx context.Context, disabled []disabledSchedule) {
	for _, d := range disabled {
		s.auditLocked("schedule.invalid_disabled", "scheduler", "", "", "durable schedule disabled at load: "+d.Reason,
			map[string]string{"schedule": d.Schedule.ID, "repository": d.Schedule.Repository, "repo_url": d.Schedule.RepoURL, "reason": d.Reason})
		s.logError("schedules: durable schedule disabled at load", "schedule", d.Schedule.ID, "repository", d.Schedule.Repository, "error", d.Reason)
	}
	if len(disabled) == 0 {
		return
	}
	if ss, ok := s.scheduleStoreDB(); ok {
		for _, d := range disabled {
			if err := ss.UpsertSchedule(ctx, d.Schedule); err != nil {
				s.logError("schedules: persist disabled schedule failed", "schedule", d.Schedule.ID, "error", err.Error())
			}
		}
		return
	}
	s.mu.Lock()
	err := s.persistSchedulesLocked()
	s.mu.Unlock()
	if err != nil {
		s.logError("schedules: persist disabled schedules failed", "error", err.Error())
	}
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
	// Reject an expression with no occurrence in the bounded horizon at
	// admission: the previous minute-by-minute scan spent ~1M iterations per
	// evaluation on such an expression and treated it as "never due", so a
	// set of doomed schedules could burn a maintenance tick indefinitely.
	// A zero next() within maxCronHorizonDays now means the expression is
	// genuinely unreachable (e.g. "0 0 31 2 *"), which is a schedule the
	// operator cannot have meant.
	if cron.next(time.Now().UTC()).IsZero() {
		return cronSchedule{}, "", fmt.Errorf("cron spec %q has no occurrence within %d days and is unreachable", sc.Cron[0].Cron, maxCronHorizonDays)
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

// reloadSchedulesFromStore replaces the in-memory schedule mirror with the
// authoritative durable rows, validating every one (invalid rows are
// disabled fail-closed, never grandfathered). Called on leadership
// promotion so a freshly promoted leader can never fire a stale copy.
func (s *Server) reloadSchedulesFromStore(ctx context.Context) error {
	ss, ok := s.scheduleStoreDB()
	if !ok {
		return nil
	}
	list, err := ss.ListSchedules(ctx)
	if err != nil {
		return err
	}
	kept, disabled := validateLoadedSchedules(list)
	for _, d := range disabled {
		s.auditLocked("schedule.invalid_disabled", "scheduler", "", "", "schedule disabled at reload: stored identity is inconsistent",
			map[string]string{"schedule": d.Schedule.ID, "reason": d.Reason})
		if err := ss.UpsertSchedule(ctx, d.Schedule); err != nil {
			s.logError("schedule disable persist failed", "schedule", d.Schedule.ID, "error", err.Error())
		}
	}
	s.mu.Lock()
	s.schedules = map[string]storage.Schedule{}
	for _, sc := range kept {
		s.schedules[sc.ID] = sc
	}
	s.mu.Unlock()
	return nil
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

// loadSchedules restores fs-mode schedules from dataDir/schedules.json. Every
// durable row is validated at load: a schedule whose stored
// Repository/RepoURL mismatch or whose stored RepoID disagrees with the URL
// is DISABLED (fail closed), audited and logged, and the disabled state is
// written back — it is never grandfathered into firing.
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
	kept, disabled := validateLoadedSchedules(f.Schedules)
	s.mu.Lock()
	for _, sc := range kept {
		s.schedules[sc.ID] = sc
	}
	for id, occ := range f.Occurrences {
		s.occurrences[id] = occ
	}
	s.mu.Unlock()
	s.reportDisabledSchedules(context.Background(), disabled)
	return nil
}

// reloadSchedulesDB loads schedules from the SQL store into memory, applying
// the SAME load-time identity validation as fs mode: inconsistent rows are
// disabled (fail closed) with an audit line, a load log and a persisted
// disabled state.
func (s *Server) reloadSchedulesDB(ctx context.Context) error {
	ss, ok := s.scheduleStoreDB()
	if !ok {
		return nil
	}
	list, err := ss.ListSchedules(ctx)
	if err != nil {
		return err
	}
	kept, disabled := validateLoadedSchedules(list)
	s.mu.Lock()
	for _, sc := range kept {
		s.schedules[sc.ID] = sc
	}
	s.mu.Unlock()
	s.reportDisabledSchedules(ctx, disabled)
	return nil
}

// writeSchedulesFile is a test-only seam over the schedules-file writer:
// production writes through storage.AtomicWriteFile (checked Sync/Close,
// atomic rename, parent-directory fsync), tests override it to fail a
// specific write and exercise the durable-first advancement and the
// best-effort post-fire marker persistence branches.
var writeSchedulesFile = writeSchedulesJSONFile

// writeSchedulesJSONFile marshals the schedules state and durably replaces
// the schedules file. The v parameter is any so the test seam keeps the
// shared json-file signature.
func writeSchedulesJSONFile(path string, v any) error {
	f, ok := v.(schedulesFileJSON)
	if !ok {
		return fmt.Errorf("schedules: unexpected payload type %T", v)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return storage.AtomicWriteFile(path, append(b, '\n'), 0o600)
}

// persistSchedulesLocked atomically writes fs-mode schedules. Callers hold
// s.mu. DB mode schedules live in the SQL store; the fs file is untouched.
func (s *Server) persistSchedulesLocked() error {
	return s.persistSchedulesWithLocked(nil)
}

// persistSchedulesWithLocked serializes the fs-mode schedules file with the
// given per-ID overrides applied WITHOUT mutating the in-memory maps: a
// durable-first advance can stage a candidate LastRun, write it, and only
// touch the mirror once the file write succeeded. Callers hold s.mu.
func (s *Server) persistSchedulesWithLocked(overrides map[string]storage.Schedule) error {
	if s.dataDir == "" || s.DB != nil {
		return nil
	}
	f := schedulesFileJSON{
		Schedules:   make([]storage.Schedule, 0, len(s.schedules)),
		Occurrences: s.occurrences,
	}
	for id, sc := range s.schedules {
		if o, ok := overrides[id]; ok {
			sc = o
		}
		f.Schedules = append(f.Schedules, sc)
	}
	sort.Slice(f.Schedules, func(i, j int) bool { return f.Schedules[i].ID < f.Schedules[j].ID })
	path := joinDataDir(s.dataDir, schedulesFile)
	err := writeSchedulesFile(path, f)
	// Fold the outcome into the per-directory uncertainty set: a pre-rename
	// failure leaves the set untouched (the previous file is intact), a
	// post-rename directory-fsync failure (fsutil.Renamed) arms the data
	// directory because the new schedules.json is visible but its crash
	// durability is uncertified, and success clears it (the directory was
	// fsynced).
	s.noteFilePersistResult(path, err)
	return err
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
			s.internalError(w, r, err, "")
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
	// Identity derivation and BINDING: repo_url is authoritative and the
	// submitted Repository must canonicalize to the SAME repository path
	// (and host identity when Repository is itself URL-shaped). This runs
	// BEFORE the trusted_run authorization below, so a mismatched request
	// can never obtain trusted execution for a repository it does not name.
	// The canonical RepoID, clone URL and Forge kind are stored, so
	// automatic firing uses the immutable stored identity.
	host, repoID, repoURL, display, bindErr := bindScheduleRepoIdentity(in.Repository, in.RepoURL)
	if bindErr != nil {
		http.Error(w, bindErr.Error(), http.StatusBadRequest)
		return
	}
	in.Repository = display
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
				s.internalError(w, r, err, "")
				return
			}
			for _, e := range existing {
				if e.ID == in.ID {
					sc = e
					break
				}
			}
			if sc.ID == "" && s.MaxSchedules > 0 && len(existing) >= s.MaxSchedules {
				http.Error(w, fmt.Sprintf("schedule limit (%d) reached", s.MaxSchedules), http.StatusConflict)
				return
			}
			action = "schedule.updated"
			if sc.ID == "" {
				sc = storage.Schedule{ID: in.ID, CreatedAt: now}
				action = "schedule.created"
			}
		} else {
			all, err := ss.ListSchedules(r.Context())
			if err != nil {
				s.internalError(w, r, err, "")
				return
			}
			if s.MaxSchedules > 0 && len(all) >= s.MaxSchedules {
				http.Error(w, fmt.Sprintf("schedule limit (%d) reached", s.MaxSchedules), http.StatusConflict)
				return
			}
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
		sc.Forge = forgeKindForHost(host)
		sc.Trusted = in.Trusted
		sc.Spec = in.Spec
		sc.Enabled = enabled
		sc.CreatedBy = actorFrom(r)
		if err := ss.UpsertSchedule(r.Context(), sc); err != nil {
			s.internalError(w, r, err, "")
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
		if action == "schedule.created" && s.MaxSchedules > 0 && len(s.schedules) >= s.MaxSchedules {
			s.mu.Unlock()
			http.Error(w, fmt.Sprintf("schedule limit (%d) reached", s.MaxSchedules), http.StatusConflict)
			return
		}
		sc.Repository = in.Repository
		sc.RepoID = repoID
		sc.RepoURL = repoURL
		sc.Forge = forgeKindForHost(host)
		sc.Trusted = in.Trusted
		sc.Spec = in.Spec
		sc.Enabled = enabled
		sc.CreatedBy = actorFrom(r)
		prev, had := s.schedules[sc.ID]
		s.schedules[sc.ID] = sc
		persistErr := s.persistSchedulesLocked()
		if persistErr != nil {
			// Durability failure, not a client error: answer 503 with the
			// fixed opaque body so the caller retries instead of treating the
			// schedule as invalid. A pre-rename failure means the journal
			// never changed: restore the previous row (or remove the fresh
			// entry) so the next successful write cannot commit a schedule the
			// client was told failed. A post-rename directory-fsync failure
			// (fsutil.Renamed) means schedules.json ALREADY carries the row:
			// retain it in memory (readiness armed by the persist) so memory
			// matches the visible file and a later persist cannot erase it.
			if !fsutil.Renamed(persistErr) {
				if had {
					s.schedules[sc.ID] = prev
				} else {
					delete(s.schedules, sc.ID)
				}
			}
			s.mu.Unlock()
			s.serverError(w, r, http.StatusServiceUnavailable, persistErr, "state not durable")
			return
		}
		s.mu.Unlock()
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
		s.internalError(w, r, err, "")
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
		// A non-durable enqueue is the same server-side condition as on every
		// other ingress: 503 + the fixed opaque "state not durable" body.
		// Any other fire error (invalid stored identity, ID generation, a
		// failed durable re-read) stays the generic 500.
		if s.respondNotDurableError(w, r, err) {
			return
		}
		s.internalError(w, r, err, "")
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
	// Due discovery runs on the AUTHORITATIVE rows in DB mode: a schedule
	// created or re-cadenced on another replica while this leader stays
	// stable would otherwise be invisible to its process-local mirror
	// indefinitely (fireSchedule's pre-fire re-read only helps for
	// schedules this mirror already knows). A durable read failure SKIPS
	// the tick rather than scheduling from stale state.
	if _, ok := s.scheduleStoreDB(); ok {
		if err := s.reloadSchedulesFromStore(ctx); err != nil {
			s.logError("schedule discovery refresh failed; skipping this tick", "error", err.Error())
			return
		}
	} else {
		// fs/memory mode: tie the run snapshot (state.json) and the
		// schedules journal (schedules.json) together BEFORE evaluating due
		// occurrences, so a committed run whose occurrence claim never
		// reached the journal is adopted at its nominal and never refired.
		s.reconcileScheduleOccurrences()
	}
	// Collect the due occurrences first (without advancing) so a failing
	// schedule cannot spin the tick loop or starve other schedules.
	type dueFire struct {
		sc      storage.Schedule
		nominal time.Time
	}
	seen := map[string]bool{}
	var dues []dueFire
	// One scan budget is shared by every due-discovery call in this tick, so
	// the total next-occurrence work stays bounded regardless of how many
	// schedules exist or how far behind their LastRun markers are.
	scanBudget := newCronScanBudget(maxCronScanDaysPerTick)
	for i := 0; i < 100; i++ {
		sc, nominal, ok := s.nextDueScheduleFromBudget(now, seen, scanBudget)
		if !ok {
			break
		}
		key := sc.ID + "\x00" + nominal.UTC().Format(time.RFC3339Nano)
		seen[key] = true
		dues = append(dues, dueFire{sc, nominal})
	}
	for _, d := range dues {
		if _, fired, err := s.fireSchedule(ctx, d.sc, d.nominal); err != nil {
			if errors.Is(err, errScheduleDisabled) || errors.Is(err, errScheduleGone) {
				// The durable row changed on another replica: skip this
				// occurrence (already audited) and advance durably so the
				// leader does not spin on a schedule it should not run.
				if aerr := s.advanceSchedulePast(ctx, d.sc, d.nominal); aerr != nil {
					s.logError("schedule advance failed", "schedule", d.sc.ID, "error", aerr.Error())
				}
				continue
			}
			if errors.Is(err, errScheduleUnauthorized) {
				// Trust revoked: skip this occurrence (already audited) and
				// advance durably, so the schedule does not spin retrying
				// it. A failed advance leaves the marker untouched and is
				// retried on the next tick.
				if aerr := s.advanceSchedulePast(ctx, d.sc, d.nominal); aerr != nil {
					s.logError("schedule advance failed", "schedule", d.sc.ID, "error", aerr.Error())
				}
				continue
			}
			s.logError("schedule fire failed", "schedule", d.sc.ID, "error", err.Error())
			// The occurrence claim was rolled back with the failed
			// enqueue: leave LastRun so the next tick refires it.
			continue
		} else if !fired {
			// Another instance claimed this nominal; skip ahead durably. A
			// failed advance is retried on the next tick.
			if aerr := s.advanceSchedulePast(ctx, d.sc, d.nominal); aerr != nil {
				s.logError("schedule advance failed", "schedule", d.sc.ID, "error", aerr.Error())
			}
			continue
		}
	}
}

// errScheduleDisabled marks an occurrence whose schedule was disabled on
// another replica and re-read as disabled by the leader: the caller advances
// past the nominal without firing.
var errScheduleDisabled = errors.New("schedule disabled")

// errScheduleGone marks an occurrence whose schedule row was deleted on
// another replica.
var errScheduleGone = errors.New("schedule deleted")

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

// advanceSchedulePast durably moves a schedule's LastRun marker past a
// nominal that could not be (or was already) claimed, so the next tick
// evaluates the following occurrence instead of spinning. The advance is
// durable FIRST and MONOTONIC: the store applies max(last_run, nominal)
// (SQL GREATEST), and the in-memory mirror is updated only after that write
// succeeds. A returned error means the marker was not advanced anywhere;
// the caller retries it on the next tick.
func (s *Server) advanceSchedulePast(ctx context.Context, sc storage.Schedule, nominal time.Time) error {
	nominal = nominal.UTC()
	if ss, ok := s.scheduleStoreDB(); ok {
		if err := ss.AdvanceScheduleLastRun(ctx, sc.ID, nominal); err != nil {
			return err
		}
		s.setScheduleLastRunMirror(sc.ID, nominal)
		return nil
	}
	// fs mode: schedules.json is the durable store. Stage the candidate
	// marker and write it BEFORE touching the mirror, so a failed write
	// leaves memory (and the next tick's due computation) exactly where it
	// was.
	s.mu.Lock()
	cur, ok := s.schedules[sc.ID]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	if cur.LastRun != nil && !cur.LastRun.Before(nominal) {
		s.mu.Unlock()
		return nil
	}
	cand := cur
	cand.LastRun = &nominal
	persistErr := s.persistSchedulesWithLocked(map[string]storage.Schedule{sc.ID: cand})
	if persistErr != nil {
		// A pre-rename failure leaves memory exactly where it was and the
		// caller retries on the next tick. A post-rename directory-fsync
		// failure (fsutil.Renamed) means schedules.json already carries the
		// advanced marker: adopt it in the mirror so memory matches the
		// visible journal and the next tick does not re-evaluate the same
		// nominal; readiness is armed by the persist.
		if fsutil.Renamed(persistErr) {
			s.schedules[sc.ID] = cand
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		return persistErr
	}
	s.mu.Unlock()
	s.setScheduleLastRunMirror(sc.ID, nominal)
	return nil
}

// setScheduleLastRunMirror applies a committed durable advance to the local
// mirror. The mirror only ever moves forward, so a stale in-memory value
// (or a concurrent advance) can never be dragged backwards.
func (s *Server) setScheduleLastRunMirror(id string, nominal time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.schedules[id]
	if !ok {
		return
	}
	if cur.LastRun == nil || cur.LastRun.Before(nominal) {
		cur.LastRun = &nominal
		s.schedules[id] = cur
	}
}

// nextDueScheduleFrom returns the next enabled schedule with a due nominal
// occurrence not already in seen (the collection loop's skip set), or
// ok=false when nothing is due. Nominals are derived from LastRun/CreatedAt
// without advancing anything. It shares one scan budget per maintenance tick
// so a large or far-behind schedule set cannot make a single tick unbounded.
func (s *Server) nextDueScheduleFrom(now time.Time, seen map[string]bool) (storage.Schedule, time.Time, bool) {
	return s.nextDueScheduleFromBudget(now, seen, newCronScanBudget(maxCronScanDaysPerTick))
}

// nextDueScheduleFromBudget is nextDueScheduleFrom with an explicit scan
// budget. A nil budget is unlimited (used by tests and one-shot probes).
func (s *Server) nextDueScheduleFromBudget(now time.Time, seen map[string]bool, budget *cronScanBudget) (storage.Schedule, time.Time, bool) {
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
			next := cron.nextBudget(base, budget)
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
	// The leader re-reads the AUTHORITATIVE row immediately before firing:
	// a disablement, spec update, trust downgrade or identity change
	// performed on another replica must take effect here without waiting
	// for a full reload. A row that disappeared or is disabled is skipped
	// (the caller advances past the nominal); a read error fails the fire
	// and leaves the occurrence for the next tick.
	if ss, ok := s.scheduleStoreDB(); ok {
		durable, found, err := ss.GetSchedule(ctx, sc.ID)
		if err != nil {
			return model.Run{}, false, fmt.Errorf("reload schedule %s before firing: %w", sc.ID, err)
		}
		if !found {
			s.auditLocked("schedule.missing", "scheduler", "", "", "schedule was deleted on another replica; occurrence skipped",
				map[string]string{"schedule": sc.ID})
			return model.Run{}, false, errScheduleGone
		}
		if !durable.Enabled {
			s.auditLocked("schedule.disabled", "scheduler", "", "", "schedule was disabled on another replica; occurrence skipped",
				map[string]string{"schedule": sc.ID})
			return model.Run{}, false, errScheduleDisabled
		}
		sc = durable
	}
	// Fail closed on an inconsistent stored identity, even when the row was
	// injected directly instead of passing the load-time validation: a
	// schedule whose Repository/RepoURL/RepoID disagree never fires. The
	// validated copy supplies the canonical RepoID/RepoURL/Forge used below.
	valid, idErr := durableScheduleIdentity(sc)
	if idErr != nil {
		s.auditLocked("schedule.invalid_disabled", "scheduler", "", "", "schedule occurrence refused: stored identity is inconsistent",
			map[string]string{"schedule": sc.ID, "repository": sc.Repository, "repo_url": sc.RepoURL, "reason": idErr.Error()})
		return model.Run{}, false, fmt.Errorf("schedule %s identity invalid: %w", sc.ID, idErr)
	}
	sc = valid
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
	// Exactly-once across the two fs durable stores: the run snapshot
	// (state.json) commits BEFORE the schedules journal (schedules.json).
	// The run carries schedule_id + schedule_nominal, so its metadata IS the
	// durable pending-occurrence marker for that nominal. Before enqueueing,
	// adopt a claim recorded in memory or reconstruct it from a committed
	// run: the nominal is already fired, so report fired=false instead of
	// creating a second run.
	if s.DB == nil {
		if runID, claimed := s.adoptCommittedScheduleOccurrence(sc.ID, nominal); claimed {
			s.auditLocked("schedule.occurrence_adopted", "scheduler", runID, "", "occurrence claim adopted from the committed run",
				map[string]string{"schedule": sc.ID, "nominal": nominal.UTC().Format(time.RFC3339)})
			return model.Run{}, false, nil
		}
	}
	preID, err := newID()
	if err != nil {
		return model.Run{}, false, err
	}
	_, ref, err := parseScheduleSpec(sc.Spec)
	if err != nil {
		return model.Run{}, false, err
	}
	// The fired run carries the schedule's stored canonical identity: the
	// policy identity is the schedule's RepoID and the checkout URL is its
	// stored clone URL. The submission is server-derived, so it skips the
	// direct-submission binding.
	in := SubmitRun{
		RepoID:          scheduleRepoID(sc),
		PolicyRepoID:    scheduleRepoID(sc),
		CheckoutRepoURL: scheduleRepoURL(sc),
		RepoURL:         scheduleRepoURL(sc),
		RepoFullName:    scheduleRepoFullName(sc),
		identityBound:   true,
		Ref:             ref,
		Event:           "schedule",
		Pipeline:        sanitizeScheduleSpec(sc.Spec),
		Trusted:         sc.Trusted,
		Metadata:        map[string]string{"schedule_id": sc.ID, "schedule_nominal": nominal.Format(time.RFC3339)},
		// The occurrence claim commits atomically with the run.
		ScheduleClaim: &storage.ScheduleClaim{ScheduleID: sc.ID, Nominal: nominal},
	}
	run, err := s.enqueueID(ctx, in, preID)
	if err != nil {
		if errors.Is(err, storage.ErrScheduleClaimLost) {
			// Another instance claimed this nominal with a different run.
			return model.Run{}, false, nil
		}
		s.auditLocked("schedule.trigger_failed", "scheduler", "", "", "scheduled run rejected", map[string]string{"schedule": sc.ID, "error": err.Error()})
		return model.Run{}, false, err
	}
	// The occurrence claim is already durable (inside the enqueue
	// transaction in DB mode, in the persisted schedules file in fs mode),
	// so this nominal can never refire. last_run only drives the NEXT due
	// computation: advance it through the same durable, monotonic contract
	// the skip path uses, and log (never fail the fired run) when the
	// durable write is unavailable — the next tick converges it through the
	// claim check or the skip advance.
	if err := s.advanceSchedulePast(ctx, sc, nominal); err != nil {
		s.logError("schedule last_run advance failed", "schedule", sc.ID, "error", err.Error())
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

// adoptCommittedScheduleOccurrence reports whether the (schedule, nominal)
// pair is already fired and, when the claim is not already in memory,
// reconstructs it from the committed run whose metadata carries
// schedule_id + schedule_nominal (the durable pending-occurrence marker that
// rides the run snapshot). The adopted claim is persisted through the
// schedules journal when possible; a failed write leaves the in-memory claim
// in place, so this process still cannot refire the nominal and the next
// tick (or restart) re-runs the same adoption. The caller holds no lock.
func (s *Server) adoptCommittedScheduleOccurrence(scheduleID string, nominal time.Time) (string, bool) {
	nominal = nominal.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	runID, claimed := s.scheduleOccurrenceRunLocked(scheduleID, nominal)
	if !claimed {
		return "", false
	}
	if err := s.persistSchedulesLocked(); err != nil {
		// Best effort: the claim is already authoritative in memory (and
		// recoverable from the committed run on restart), so a failed
		// journal write must not turn the adoption into a second run.
		s.logError("schedule occurrence claim persist failed", "schedule", scheduleID, "error", err.Error())
	}
	return runID, true
}

// scheduleOccurrenceRunLocked resolves the run that already fired a nominal:
// the in-memory claim first, then a committed run carrying the
// schedule_id + schedule_nominal metadata (adopted into the claim map). The
// caller holds s.mu. claimed=true means the nominal must not fire again,
// even when the claimed run is no longer present (the orphan reconcile
// records that; firing a second run could duplicate an execution).
func (s *Server) scheduleOccurrenceRunLocked(scheduleID string, nominal time.Time) (string, bool) {
	key := nominal.UTC().Unix()
	if occ := s.occurrences[scheduleID]; occ != nil {
		if runID, ok := occ[key]; ok {
			return runID, true
		}
	}
	want := nominal.UTC().Format(time.RFC3339)
	for id, run := range s.runs {
		if run.Metadata["schedule_id"] != scheduleID || run.Metadata["schedule_nominal"] != want {
			continue
		}
		occ := s.occurrences[scheduleID]
		if occ == nil {
			occ = map[int64]string{}
			s.occurrences[scheduleID] = occ
		}
		occ[key] = id
		return id, true
	}
	return "", false
}

// reconcileScheduleOccurrences ties the two fs-mode durable stores together
// before due evaluation:
//
//  1. Adopt: a committed run carrying schedule_id + schedule_nominal is the
//     durable pending-occurrence marker for a nominal whose claim never
//     reached the schedules journal (a crash or failed journal write in the
//     window between the two writes). The claim and LastRun are restored
//     from it, so a committed run with an unclaimed nominal is adopted and
//     never refired.
//  2. Record: a claim whose run is not present would otherwise silently
//     consume the occurrence. It is audited and logged once per claim; the
//     claim is deliberately kept (never refire a nominal that may have
//     produced a run).
func (s *Server) reconcileScheduleOccurrences() {
	s.mu.Lock()
	defer s.mu.Unlock()
	adopted := false
	for id, run := range s.runs {
		scheduleID := strings.TrimSpace(run.Metadata["schedule_id"])
		nominalText := strings.TrimSpace(run.Metadata["schedule_nominal"])
		if scheduleID == "" || nominalText == "" {
			continue
		}
		sc, ok := s.schedules[scheduleID]
		if !ok {
			continue
		}
		nominal, err := time.Parse(time.RFC3339, nominalText)
		if err != nil {
			continue
		}
		nominal = nominal.UTC()
		if occ := s.occurrences[scheduleID]; occ != nil {
			if _, claimed := occ[nominal.Unix()]; claimed {
				continue
			}
		}
		if s.occurrences[scheduleID] == nil {
			s.occurrences[scheduleID] = map[int64]string{}
		}
		s.occurrences[scheduleID][nominal.Unix()] = id
		if sc.LastRun == nil || sc.LastRun.Before(nominal) {
			sc.LastRun = &nominal
			s.schedules[scheduleID] = sc
		}
		adopted = true
	}
	if adopted {
		if err := s.persistSchedulesLocked(); err != nil {
			// The in-memory adoption still prevents a refire this process;
			// the next tick re-runs the adoption.
			s.logError("schedule occurrence reconcile persist failed", "error", err.Error())
		}
	}
	for scheduleID, occ := range s.occurrences {
		for unix, runID := range occ {
			if _, ok := s.runs[runID]; ok {
				continue
			}
			key := scheduleID + "\x00" + strconv.FormatInt(unix, 10) + "\x00" + runID
			if s.orphanOccurrences[key] {
				continue
			}
			if s.orphanOccurrences == nil {
				s.orphanOccurrences = map[string]bool{}
			}
			s.orphanOccurrences[key] = true
			nominal := time.Unix(unix, 0).UTC().Format(time.RFC3339)
			s.auditLocked("schedule.occurrence_orphaned", "scheduler", "", "", "claimed occurrence has no committed run",
				map[string]string{"schedule": scheduleID, "nominal": nominal, "run": runID})
			s.logError("schedule: claimed occurrence has no committed run", "schedule", scheduleID, "nominal", nominal, "run", runID)
		}
	}
}

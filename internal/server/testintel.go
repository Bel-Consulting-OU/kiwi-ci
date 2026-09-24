package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

func (s *Server) uploadTestReport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RunnerID        string `json:"runner_id"`
		LeaseToken      string `json:"lease_token"`
		LeaseGeneration int64  `json:"lease_generation"`
		// DeliveryID/ContentDigest are the durable-delivery identity of the
		// upload (see internal/testintel/delivery.go). DeliveryID is the
		// stable, content-derived name the runner computes for this report;
		// ContentDigest is optional and, when present, must equal the digest
		// the server computes from the bytes it received. A request without a
		// delivery ID gets a server-synthesized deterministic identity
		// (synthesizedReportDeliveryID) after the lease is verified, so even
		// a legacy client's dropped-response resend is idempotent.
		DeliveryID    string          `json:"delivery_id"`
		ContentDigest string          `json:"content_digest"`
		Report        json.RawMessage `json:"report"`
	}
	// Endpoint-specific decode cap: the shared total-bytes budget of one
	// report delivery (internal/testintel/limits.go). The global generic
	// decode cap is deliberately untouched.
	if !decodeLimit(w, r, &in, testintel.MaxTestReportRequestBytes) {
		return
	}
	if in.DeliveryID != "" && !testintel.ValidReportDeliveryID(in.DeliveryID) {
		http.Error(w, "invalid delivery_id", http.StatusBadRequest)
		return
	}
	rep, ok := decodeTestReportPayload(w, in.Report)
	if !ok {
		return
	}
	// The shared size contract is enforced on the decoded report too (case
	// count, retained message bytes, serialized payload budget): the parser,
	// the runner's pre-upload check and this endpoint all reject the same
	// boundary with the same reason. The raw payload bytes are additionally
	// bounded by the endpoint decode cap above.
	if err := testintel.ValidateReportPayload(rep); err != nil {
		http.Error(w, "report over limits: "+err.Error(), http.StatusBadRequest)
		return
	}
	// The digest is ALWAYS computed server-side from the received bytes; a
	// client-supplied digest is verified against it and never trusted.
	digest := testintel.ReportContentDigest(in.Report)
	if in.ContentDigest != "" && in.ContentDigest != digest {
		http.Error(w, "content_digest does not match the report payload", http.StatusBadRequest)
		return
	}
	j, authErr := s.authorizeRunnerLease(r, in.RunnerID, in.LeaseToken, in.LeaseGeneration)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return
	}
	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	rep.ID = id
	rep.RunID = j.RunID
	rep.JobID = j.ID
	rep.JobKey = j.Key
	rep.CreatedAt = time.Now().UTC()
	// The AUTHORITATIVE suite identity (the job key) is what the aggregate
	// upsert indexes; a pipeline declaration over the shared suite budget
	// would otherwise bypass the payload validator (which ran before this
	// override) and fail the SQL primary key later. It is refused here,
	// before any store call, with the same budget as the submitted report.
	if len(rep.JobKey) > testintel.MaxTestSuiteBytes {
		http.Error(w, "job key is over the "+strconv.Itoa(testintel.MaxTestSuiteBytes)+"-byte suite budget", http.StatusBadRequest)
		return
	}
	// The delivery key is scoped to the AUTHORITATIVE job/lease generation
	// from the verified lease, never to client-supplied values, so a replay
	// can never be re-attributed to another job or generation. A client that
	// omitted delivery_id still gets a delivery identity: the synthesized one
	// binds the verified job/lease generation and the server-computed content
	// digest, so the dropped-response resend of an OLDER client converges on
	// exactly one report and one history fold instead of inserting a second
	// report and re-folding history.
	deliveryID := in.DeliveryID
	if deliveryID == "" {
		deliveryID = synthesizedReportDeliveryID(j.ID, j.LeaseGeneration, digest)
	}
	delivery := storage.TestReportDelivery{JobID: j.ID, LeaseGeneration: j.LeaseGeneration, DeliveryID: deliveryID, ContentDigest: digest}
	// The report's history key is the run's canonical repository identity.
	// The authoritative lookup is never best-effort: a failed or missing run
	// fails the upload closed BEFORE the durable report insert and the
	// history write, so history can never be recorded under an empty repo
	// key that merges unrelated repositories.
	run, ok := s.requireRunIdentity(w, r, j.RunID)
	if !ok {
		return
	}
	repo := repoIDForRun(run)
	// The durable report and the test-history aggregates commit in ONE
	// transaction: the delivery store writes the report, folds ONLY this
	// report's cases into the per-repository aggregates, records the delivery
	// receipt and bumps the repository version atomically, so per-upload work
	// never grows with the accumulated history, a canceled request commits
	// nothing, and a replay of the same delivery is an idempotent success
	// that changes nothing. The non-idempotent aggregate/store fallbacks are
	// GONE: a configured store without the delivery contract cannot
	// deduplicate a replayed upload, so it is refused with an opaque 503
	// instead of double-inserting the report and re-folding history.
	if s.DB != nil {
		ds, isDelivery := s.DB.(storage.TestReportDeliveryStore)
		if !isDelivery {
			http.Error(w, "test report delivery storage is unavailable", http.StatusServiceUnavailable)
			return
		}
		outcome, err := ds.InsertTestReportWithHistoryDelivery(r.Context(), rep, repo, delivery)
		switch {
		case errors.Is(err, storage.ErrTestReportDeliveryConflict):
			// Same delivery identity, different payload: the stored
			// report and history are untouched and the retry is refused
			// explicitly instead of silently discarded.
			http.Error(w, "test report delivery conflict: delivery_id was already used with different content", http.StatusConflict)
			return
		case err != nil:
			s.internalError(w, r, err, "")
			return
		}
		rep.ID = outcome.ReportID
		if outcome.Replay {
			// Idempotent success: the original report already committed,
			// its history was folded once, and this retry must not
			// re-observe metrics or audit twice.
			writeJSON(w, http.StatusOK, rep)
			return
		}
		s.observeTestReportMetrics(rep)
		// Mark the cached snapshot stale; the next read reloads the
		// repository's freshly committed durable aggregates.
		s.mirrorTestReportHistoryDB(repo)
		s.auditLocked("tests.uploaded", in.RunnerID, j.RunID, j.ID, "test report uploaded", map[string]string{"job": j.Key, "tests": strconv.Itoa(rep.Tests), "failures": strconv.Itoa(rep.Failures)})
		writeJSON(w, http.StatusCreated, rep)
		return
	}
	// Memory/fs mode has no store transaction, so the delivery identity
	// (client-supplied or synthesized above) is ALWAYS bound into a
	// deterministic report ID: the same delivery maps to the same record and
	// a retry can never duplicate it (it either overwrites nothing on replay
	// or is refused as a conflict). The digest conflict is detected by
	// comparing the client-authored report content, because there is no
	// delivery table to hold the digest.
	rep.ID = testintel.DeliveryReportID(delivery.JobID, delivery.LeaseGeneration, delivery.DeliveryID)
	s.mu.Lock()
	if existing, ok := s.reports[rep.ID]; ok {
		s.mu.Unlock()
		if sameTestReportContent(existing, rep) {
			// Retry convergence: the durable report is the source of truth,
			// so an identical replay whose fold never reached the derived
			// history snapshot is folded NOW, exactly once (the fold is
			// idempotent by report ID), before the success is answered. A
			// replayed delivery can therefore never leave the history
			// permanently missing this report.
			s.ensureReportFolded(repo, existing)
			writeJSON(w, http.StatusOK, existing)
			return
		}
		http.Error(w, "test report delivery conflict: delivery_id was already used with different content", http.StatusConflict)
		return
	}
	s.observeTestReportMetrics(rep)
	s.reports[rep.ID] = rep
	perr := s.persistCheckedErrLocked("test.report")
	if perr != nil {
		// The report never became durable: remove the in-memory ghost so a
		// later successful persist cannot commit a report the runner was
		// told failed, and the retry stores exactly one.
		delete(s.reports, rep.ID)
		s.mu.Unlock()
		s.internalError(w, r, perr, "")
		return
	}
	s.mu.Unlock()
	s.recordTestReportHistory(r.Context(), repo, rep)
	s.auditLocked("tests.uploaded", in.RunnerID, j.RunID, j.ID, "test report uploaded", map[string]string{"job": j.Key, "tests": strconv.Itoa(rep.Tests), "failures": strconv.Itoa(rep.Failures)})
	writeJSON(w, http.StatusCreated, rep)
}

// decodeTestReportPayload strictly decodes the "report" member of a /tests
// request. It keeps the request decoder's contract (unknown fields and
// trailing data are rejected) while letting the handler digest and bound the
// RAW payload bytes the runner sent.
func decodeTestReportPayload(w http.ResponseWriter, raw json.RawMessage) (model.TestReport, bool) {
	var rep model.TestReport
	if len(raw) == 0 || string(raw) == "null" {
		return rep, true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return model.TestReport{}, false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "bad json: trailing data", http.StatusBadRequest)
		return model.TestReport{}, false
	}
	return rep, true
}

// observeTestReportMetrics records one committed report's case durations.
// Replayed deliveries skip it: the original upload already observed them.
func (s *Server) observeTestReportMetrics(rep model.TestReport) {
	for _, c := range rep.Cases {
		s.metricObserve("kiwi_test_duration_seconds", c.Duration, nil)
	}
}

// synthesizedReportDeliveryID derives the deterministic delivery identity of
// a report upload whose client omitted delivery_id: the hex SHA-256 of
//
//	"legacy-report" \x00 jobID \x00 leaseGeneration \x00 contentDigest
//
// Every part is length-delimited by a NUL byte so the parts can never be
// confused for one another, and the "legacy-report" namespace keeps the
// synthesized identity disjoint from the runner-derived one
// (testintel.ReportDeliveryID). It is computed AFTER the lease is verified
// and from the SERVER-computed digest, so:
//
//   - a resend of the identical bytes after a lost response resolves to the
//     same delivery and is an idempotent replay (one report, one fold, one
//     metrics observation, one audit event);
//   - different bytes under the same lease are a different delivery, never a
//     spurious conflict;
//   - a replay can never be re-attributed to another job or lease generation.
func synthesizedReportDeliveryID(jobID string, leaseGeneration int64, contentDigest string) string {
	h := sha256.New()
	h.Write([]byte("legacy-report"))
	h.Write([]byte{0})
	h.Write([]byte(jobID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(leaseGeneration, 10)))
	h.Write([]byte{0})
	h.Write([]byte(contentDigest))
	return hex.EncodeToString(h.Sum(nil))
}

// reportContentView is the client-authored part of a report plus the
// delivery-scoped job identity the server stamps. ID and CreatedAt are
// deliberately excluded (the first delivery stamps them, so a replay of the
// same bytes must still compare equal), but RunID and JobID are INCLUDED: two
// deliveries that somehow map to one record with different job identities are
// a conflict, never an idempotent replay. Together with the job/generation
// scoping of the report ID, this makes the memory-mode conflict check agree
// with the durable (job, generation, delivery ID) delivery key.
type reportContentView struct {
	RunID    string             `json:"run_id"`
	JobID    string             `json:"job_id"`
	Path     string             `json:"path"`
	Tests    int                `json:"tests"`
	Failures int                `json:"failures"`
	Errors   int                `json:"errors"`
	Skipped  int                `json:"skipped"`
	Duration float64            `json:"duration"`
	Cases    []model.TestResult `json:"cases"`
}

// sameTestReportContent reports whether two reports carry the same
// client-authored content. It is the memory-mode digest conflict check: a
// reused delivery ID with different content must be refused, while an
// identical replay is idempotent.
func sameTestReportContent(a, b model.TestReport) bool {
	ab, aerr := json.Marshal(reportContentView{RunID: a.RunID, JobID: a.JobID, Path: a.Path, Tests: a.Tests, Failures: a.Failures, Errors: a.Errors, Skipped: a.Skipped, Duration: a.Duration, Cases: a.Cases})
	bb, berr := json.Marshal(reportContentView{RunID: b.RunID, JobID: b.JobID, Path: b.Path, Tests: b.Tests, Failures: b.Failures, Errors: b.Errors, Skipped: b.Skipped, Duration: b.Duration, Cases: b.Cases})
	return aerr == nil && berr == nil && bytes.Equal(ab, bb)
}

func (s *Server) listTestReports(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	if s.DB != nil {
		run, err := s.DB.GetRun(r.Context(), runID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		if !s.requireRunRead(w, r, run) {
			return
		}
		out, err := s.DB.ListTestReports(r.Context(), runID)
		if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	out := []model.TestReport{}
	for _, rep := range s.reports {
		if rep.RunID == runID {
			out = append(out, rep)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

// testHistoryRepoResolveLimit bounds the supported AMBIGUITY of a
// test-intelligence query. A canonical (forge-scoped) repository ID is an
// exact identity and is never capped; a bare owner/name may address one
// repository per forge, so at most this many distinct canonical repositories
// are accepted and an over-limit query is refused with an opaque 409 instead
// of being answered with an arbitrary first `limit` candidates.
const testHistoryRepoResolveLimit = 64

// testHistoryFlakyLimit bounds the flaky-test list returned by
// test-intelligence (deterministic rendered-name order before the bound).
const testHistoryFlakyLimit = 1000

// testIntelligence reports flaky-test history and report volume for one
// repository. The repo query parameter is required and accepts the
// human-readable full name, the canonical RepoID or the legacy canonical
// form. The query is only candidate discovery: one bare name can address
// several forges, so every resolved canonical repository ID is authorized
// INDIVIDUALLY through canReadRepo (auth.CanReadRepo) and the aggregates are
// read from the authorized canonical-ID set ONLY. The bare query form is
// never re-injected into an aggregate predicate, so a principal granted one
// forge's repository can never receive another forge's test history.
func (s *Server) testIntelligence(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	if repo == "" {
		http.Error(w, "repo query parameter is required (e.g. ?repo=owner/name)", http.StatusBadRequest)
		return
	}
	// Coarse gate: the principal must be able to address the query form at
	// all. This is deliberately NOT the authorization decision for the data
	// (a bare name is not a repository identity); the resolved canonical IDs
	// are authorized one by one below.
	if !s.requireAction(w, r, auth.ActionRead, auth.CanonicalRepoID("", repo), false) {
		return
	}
	if !s.repoVisibleByName(r, repo) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	historyKeys := map[string]bool{}
	if s.DB != nil {
		// Incremental path: resolve the query to CANDIDATE canonical
		// repository IDs with one bounded set-based run query, authorize
		// each candidate through canReadRepo and drop the unauthorized ones
		// BEFORE any aggregate read, then read ONLY the authorized
		// repositories' aggregates and report totals. Unrelated reports are
		// never materialized and their payloads are never parsed.
		//
		// The principal's explicitly permitted canonical identities are
		// intersected with candidate discovery BEFORE the ambiguity cap: an
		// authorized repository that would sort after a bare-name cap is
		// therefore still resolved (pre-fix it was silently invisible to its
		// own owner). An over-limit bare name is refused explicitly, never
		// truncated.
		if agg, ok := s.DB.(storage.TestHistoryAggregateStore); ok {
			permitted := s.testHistoryPermittedRepoIDs(r, repo)
			var (
				ids []string
				err error
			)
			if scoped, ok := s.DB.(storage.TestHistoryRepoResolutionStore); ok {
				ids, err = scoped.ResolveTestHistoryRepoIDsScoped(r.Context(), repo, permitted, testHistoryRepoResolveLimit)
			} else {
				// Legacy resolution contract: intersect in the caller. The
				// bare-name ambiguity limit still fails closed, so an
				// authorized repository beyond the cap is refused (opaque
				// 409) rather than silently omitted.
				ids, err = agg.ResolveTestHistoryRepoIDs(r.Context(), repo, testHistoryRepoResolveLimit)
				if err == nil {
					ids = intersectTestHistoryRepoIDs(ids, permitted)
				}
			}
			if err != nil {
				if errors.Is(err, storage.ErrRepoQueryAmbiguous) {
					// Opaque: the query addresses more canonical
					// repositories than a bare name can resolve
					// unambiguously. The caller re-addresses the repository
					// by its forge-scoped canonical ID.
					http.Error(w, "repository query is ambiguous: use the forge-scoped canonical repository ID (host/owner/name)", http.StatusConflict)
					return
				}
				s.internalError(w, r, err, "")
				return
			}
			authorized := s.authorizedTestHistoryRepoIDs(r, ids)
			// Lazy repair: repositories whose aggregates predate migration
			// 0026 are rebuilt once from their durable reports (explicit
			// bounded maintenance), never per upload. Unauthorized candidates
			// are neither repaired nor read.
			for _, id := range authorized {
				if r.Context().Err() != nil {
					break
				}
				if _, _, err := s.loadRepoHistoryWithRepair(r.Context(), agg, id); err != nil {
					s.logError("test history: repository repair failed", "repo", id, "error", err.Error())
				}
			}
			// The totals predicate is the authorized canonical set ONLY; the
			// bare query form is empty here on purpose (it belongs to
			// resolution, which is allowed to find candidates across forges).
			reports, tests, failures, err := agg.TestReportTotals(r.Context(), authorized, "")
			if err != nil {
				s.internalError(w, r, err, "")
				return
			}
			flaky, err := agg.FlakyTestNames(r.Context(), authorized, testHistoryFlakyLimit)
			if err != nil {
				s.internalError(w, r, err, "")
				return
			}
			if flaky == nil {
				flaky = []string{}
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"repo":        repo,
				"reports":     reports,
				"total_tests": tests,
				"failures":    failures,
				"flaky_tests": flaky,
			})
			return
		}
		// Legacy whole-cache store: ONE whole-history snapshot is taken for
		// this response (historyForRepo converges it through the same
		// version-tracked path shard requests use) and answers every key of
		// the merge below, so the response can never mix cache generations.
		h, _ := s.historyForRepo(r.Context(), repo)
		reports, err := s.DB.ListTestReportsAll(r.Context())
		if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		filtered := make([]model.TestReport, 0, len(reports))
		for _, rep := range reports {
			run, gerr := s.DB.GetRun(r.Context(), rep.RunID)
			if gerr != nil || !runMatchesRepoQuery(run, repo) {
				continue
			}
			// The human name matching the query is not enough: the run's
			// canonical repository must itself be readable.
			repoID := repoIDForRun(run)
			if repoID == "" || !s.canReadRepo(r, repoID) {
				continue
			}
			filtered = append(filtered, rep)
			historyKeys[repoID] = true
		}
		out := summarizeTestIntelligence(filtered)
		out["repo"] = repo
		s.mergeHistoryFlakyKeys(h, historyKeys, out)
		writeJSON(w, http.StatusOK, out)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Memory/fs mode: make sure the snapshot is derived from the DURABLE
	// reports before answering, so a report whose history cache write failed
	// (or a stale cache file loaded at startup) can never hide its history.
	s.ensureDerivedHistoryLocked()
	filtered := []model.TestReport{}
	for _, rep := range s.reports {
		run, ok := s.runs[rep.RunID]
		if !ok || !runMatchesRepoQuery(run, repo) {
			continue
		}
		// The human name matching the query is not enough: the run's
		// canonical repository must itself be readable, so two forges
		// presenting the same bare name never share an answer.
		repoID := repoIDForRun(run)
		if repoID == "" || !s.canReadRepo(r, repoID) {
			continue
		}
		filtered = append(filtered, rep)
		historyKeys[repoID] = true
	}
	out := summarizeTestIntelligence(filtered)
	out["repo"] = repo
	// The snapshot is taken under s.mu (memory-mode history writes hold it)
	// and answers every key of this response. Only the AUTHORIZED canonical
	// keys collected above are merged; the raw query form is never a key.
	s.mergeHistoryFlakyKeys(s.cachedHistory(repo), historyKeys, out)
	writeJSON(w, http.StatusOK, out)
}

// authorizedTestHistoryRepoIDs filters resolved candidate canonical repository
// IDs down to the ones THIS request's principal may read, with one
// canReadRepo decision per canonical ID (auth.CanReadRepo). Resolution is
// intentionally permissive — a bare alias must still find every repository
// that presents the name — so authorization can never be inherited from the
// query string: a principal granted one forge's repository receives only that
// forge's IDs, and the aggregate reads below never see the others. With no
// principal (legacy mode/web session) the outer tier decides, so every ID
// passes.
func (s *Server) authorizedTestHistoryRepoIDs(r *http.Request, ids []string) []string {
	authorized := make([]string, 0, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			continue
		}
		if s.canReadRepo(r, id) {
			authorized = append(authorized, id)
		}
	}
	return authorized
}

// testHistoryPermittedRepoIDs returns the canonical repository identities the
// request's principal is explicitly granted AND that the query addresses. A
// nil result means candidate resolution must NOT be identity-restricted:
// either no principal is bound (legacy mode/web-session tier, already decided
// by the outer gate), or the principal holds a global read/admin role, or a
// grant is keyed by the bare owner/name — which authorizes EVERY forge
// presenting that name and therefore cannot be enumerated as canonical
// identities. A non-nil result is the exact permitted intersection —
// possibly empty — that resolution must apply BEFORE its ambiguity cap, so an
// authorized repository that sorts after a bare-name cap is still reachable.
//
// Both the query and every grant key are classified with the typed positional
// rule (auth.ParseStoredRepoID): an explicit r1: identity, an r1:-migrated
// canonical storage ID ("host/owner/name"), or a plain canonical ID with a
// DOTLESS host all parse into a RepoIdentity compared by (host, full name)
// equality; a bare owner/name or a1: string parses into a RepoAlias. The old
// splitForgeRepoKey dot heuristic is gone, so a dotless canonical grant is
// never mistaken for a bare nested group.
func (s *Server) testHistoryPermittedRepoIDs(r *http.Request, query string) []string {
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return nil
	}
	if p.Has(auth.RoleAdmin) || p.Has(auth.RoleRead) {
		return nil
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	qGrant, err := auth.ParseStoredRepoID(query)
	if err != nil {
		return nil
	}
	queryIdentity, queryIsCanonical := qGrant.Identity()
	queryFullName := qGrant.AuthorizationID()
	if queryIsCanonical {
		queryFullName = queryIdentity.FullName
	}
	permitted := []string{}
	for key := range p.Repositories {
		grant, err := auth.ParseStoredRepoID(strings.TrimSpace(key))
		if err != nil {
			continue
		}
		if alias, ok := grant.Alias(); ok {
			if alias.FullName == queryFullName {
				// A bare grant authorizes every forge presenting the name:
				// the permitted identity set is not enumerable, so keep the
				// unrestricted resolution (and its ambiguity refusal).
				return nil
			}
			continue
		}
		id, ok := grant.Identity()
		if !ok {
			continue
		}
		if queryIsCanonical {
			if id != queryIdentity {
				continue
			}
		} else if id.FullName != queryFullName {
			continue
		}
		if auth.CanReadRepoIdentity(p, id) {
			permitted = append(permitted, id.ID())
		}
	}
	return permitted
}

// intersectTestHistoryRepoIDs keeps the resolved candidate IDs inside the
// permitted set. A nil permitted set is no restriction: the candidates are
// returned unchanged (the caller still authorizes every ID individually).
func intersectTestHistoryRepoIDs(ids, permitted []string) []string {
	if permitted == nil {
		return ids
	}
	allowed := make(map[string]bool, len(permitted))
	for _, id := range permitted {
		allowed[id] = true
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if allowed[id] {
			out = append(out, id)
		}
	}
	return out
}

// runMatchesRepoQuery reports whether a test-intelligence query addresses a
// run's repository. The query may be the human-readable full name, the
// canonical RepoID, or the legacy host-less canonical form.
func runMatchesRepoQuery(run model.Run, query string) bool {
	query = strings.TrimSpace(query)
	if query == "" {
		return false
	}
	if query == run.RepoFullName || query == repoIDForRun(run) {
		return true
	}
	return query == auth.CanonicalRepoID("", run.RepoFullName)
}

// testOutcomeIdentity is the structured identity of one report-derived test
// outcome: the suite (the report's job key) plus the case's class and name.
// The persisted history model keys on (repo, suite, class, name), so the
// report-derived fold must keep the suite too: two different suites can each
// contain a case named "pkg.TestX", and merging them by class.name alone
// would let one suite's failures classify the other suite's clean test as
// flaky.
type testOutcomeIdentity struct {
	suite string
	class string
	name  string
}

// renderTestOutcomeName renders one structured identity as the API's display
// name: "name" for an empty class, "class.name" otherwise. The suite is NOT
// part of the rendered name (the API has always presented class.name); it is
// only part of the internal key.
func renderTestOutcomeName(k testOutcomeIdentity) string {
	if k.class == "" {
		return k.name
	}
	return k.class + "." + k.name
}

// summarizeTestIntelligence computes the flaky-test summary from an explicit
// report list (both the DB and the in-memory path feed pre-filtered lists).
// Each test's outcomes are folded in deterministic report order (created_at,
// then id) into the SAME bounded 16-outcome window the persisted history and
// the SQL aggregates use, so the report-derived set cannot keep a test that
// dropped out of its window — the shard, API and aggregate flaky semantics
// stay aligned. Outcomes are keyed by the full (suite, class, name) identity
// and rendered as class.name only at output; the same class.name in two
// suites therefore keeps two independent windows, and the rendered list is
// deduplicated.
func summarizeTestIntelligence(reports []model.TestReport) map[string]any {
	ordered := append([]model.TestReport(nil), reports...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
		}
		return ordered[i].ID < ordered[j].ID
	})
	history := map[testOutcomeIdentity][]bool{}
	var tests, failures int
	for _, rep := range ordered {
		tests += rep.Tests
		failures += rep.Failures
		for _, c := range rep.Cases {
			// Skip policy: a skipped case is not a pass/fail observation, so
			// it must not enter the report-derived outcome window (it would
			// read as a failure and fabricate flakiness).
			if c.Skipped {
				continue
			}
			key := testOutcomeIdentity{suite: rep.JobKey, class: c.Class, name: c.Name}
			window := append(history[key], c.Passed)
			if len(window) > testintel.OutcomeWindow {
				window = window[len(window)-testintel.OutcomeWindow:]
			}
			history[key] = window
		}
	}
	flakySet := map[string]bool{}
	for key, results := range history {
		if testintel.FlakeProbability(results) > 0 {
			flakySet[renderTestOutcomeName(key)] = true
		}
	}
	flaky := make([]string, 0, len(flakySet))
	for name := range flakySet {
		flaky = append(flaky, name)
	}
	sort.Strings(flaky)
	return map[string]any{
		"reports":     len(reports),
		"total_tests": tests,
		"failures":    failures,
		"flaky_tests": flaky,
	}
}

// mergeHistoryFlaky unions the report-derived flaky set with the flaky set of
// ONE already-taken history snapshot for one repository key. A nil snapshot
// (nothing cached) leaves the report-derived set untouched.
func (s *Server) mergeHistoryFlaky(h *testintel.History, repo string, out map[string]any) {
	existing, _ := out["flaky_tests"].([]string)
	seen := map[string]bool{}
	for _, name := range existing {
		seen[name] = true
	}
	if h != nil {
		for _, name := range h.Flaky(repo) {
			if !seen[name] {
				seen[name] = true
				existing = append(existing, name)
			}
		}
	}
	sort.Strings(existing)
	out["flaky_tests"] = existing
}

// mergeHistoryFlakyKeys unions the persisted flaky set over every canonical
// history key a query matched. h is the ONE snapshot already taken for the
// whole response (nil when nothing is cached), so the merged set can never
// mix cache generations.
func (s *Server) mergeHistoryFlakyKeys(h *testintel.History, keys map[string]bool, out map[string]any) {
	for key := range keys {
		s.mergeHistoryFlaky(h, key, out)
	}
}

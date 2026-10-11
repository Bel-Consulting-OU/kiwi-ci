package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// seedForensicAttempt seeds one completed attempt with a signed attestation,
// two run-scoped ledger events, one foreign-run event, and one artifact,
// snapshot and test report in the in-memory records.
func seedForensicAttempt(t *testing.T, s *Server, gen int64) {
	t.Helper()
	job := seedAssuranceAttestationJob(t, s, "job-a", "run-a", attestationTestPipeline, gen, true, policy.DefaultTrustedCapabilities())
	ctx := context.Background()
	for _, ev := range []model.ExecutionEvent{
		{Type: "job.started", RunID: "run-a", JobID: "job-a", RepoID: "github.com/acme/repo-a", CreatedAt: time.Now().UTC()},
		{Type: "job.completed", RunID: "run-a", JobID: "job-a", RepoID: "github.com/acme/repo-a", CreatedAt: time.Now().UTC()},
		{Type: "job.started", RunID: "run-b", JobID: "job-b", RepoID: "github.com/acme/repo-b", CreatedAt: time.Now().UTC()},
	} {
		if err := s.store.AppendExecutionEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	s.artifacts["art-1"] = model.ArtifactRecord{
		ID: "art-1", RunID: "run-a", JobID: "job-a", JobKey: job.Key, Name: "bin",
		SHA256: strings.Repeat("a", 64), Size: 42, LeaseGeneration: gen,
		ProvenanceSHA256: strings.Repeat("b", 64),
		SBOMPath:         "sboms/bin.cdx.json", SBOMSHA256: strings.Repeat("c", 64),
		SigstorePath: "sigstore/bin.bundle", SigstoreSHA256: strings.Repeat("d", 64),
	}
	s.reports["rep-1"] = model.TestReport{
		ID: "rep-1", RunID: "run-a", JobID: "job-a", JobKey: job.Key,
		Path: "junit.xml", Tests: 3, Failures: 1, LeaseGeneration: gen,
	}
	s.snapshots["snap-1"] = model.SnapshotRecord{
		ID: "snap-1", RunID: "run-a", JobID: "job-a", Phase: model.SnapshotPhasePreJob,
		SHA256: strings.Repeat("e", 64), RootSHA256: strings.Repeat("f", 64), LeaseGeneration: gen,
	}
	s.mu.Unlock()
	if err := s.attestExecution(ctx, "job-a", gen); err != nil {
		t.Fatalf("attestExecution: %v", err)
	}
}

// TestForensicProfileMaterializesReferencedStreams proves the forensic
// profile returns one bundle with the signed envelope (the signed truth; the
// surrounding bundle is unsigned presentation/context), the run-scoped
// bounded event timeline, the attempt's artifact/snapshot/report references
// and the retention watermarks, while minimal/standard keep serving the
// signed envelope bytes and an unknown profile is refused.
func TestForensicProfileMaterializesReferencedStreams(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedForensicAttempt(t, s, 3)
	path := "/api/v1/jobs/job-a/attestation?profile=forensic"

	w := doJSON(t, s, http.MethodGet, path, "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("forensic bundle = %d: %s", w.Code, w.Body.String())
	}
	var bundle forensicBundle
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("bundle decode: %v", err)
	}
	if bundle.Schema != forensicSchema || bundle.Profile != "forensic" {
		t.Fatalf("bundle identity = %q/%q", bundle.Schema, bundle.Profile)
	}
	if bundle.AttemptID != model.AttemptID("job-a", 3) || bundle.Generation != 3 {
		t.Fatalf("bundle attempt = %q gen %d", bundle.AttemptID, bundle.Generation)
	}
	// The embedded envelope is the signed truth; the bundle only carries its
	// digests for convenience. Nothing here claims the attestation digest
	// commits the surrounding timeline, report rows or reference lists.
	if len(bundle.Attestation) == 0 {
		t.Fatal("bundle carries no attestation envelope")
	}
	sum := sha256.Sum256(bundle.Attestation)
	if got := hex.EncodeToString(sum[:]); got != bundle.EnvelopeSHA256 {
		t.Fatalf("envelope digest = %q, want %q", bundle.EnvelopeSHA256, got)
	}
	s.mu.Lock()
	rec := s.attestations[model.AttemptID("job-a", 3)]
	s.mu.Unlock()
	if bundle.StatementSHA256 != rec.StatementSHA256 || bundle.StatementSHA256 == "" {
		t.Fatalf("statement digest = %q, want the durable record's %q", bundle.StatementSHA256, rec.StatementSHA256)
	}
	// The digest-header contract is shared with the standard profile: the
	// same envelope bytes must advertise the same headers from both paths.
	std := doJSON(t, s, http.MethodGet, "/api/v1/jobs/job-a/attestation", "token", "")
	if got := std.Header().Get("X-Kiwi-Content-SHA256"); got != bundle.EnvelopeSHA256 {
		t.Fatalf("standard header digest = %q, forensic digest = %q", got, bundle.EnvelopeSHA256)
	}
	if got := std.Header().Get("X-Kiwi-Statement-SHA256"); got != bundle.StatementSHA256 {
		t.Fatalf("standard statement header = %q, forensic digest = %q", got, bundle.StatementSHA256)
	}
	if got := w.Header().Get("X-Kiwi-Content-SHA256"); got != bundle.EnvelopeSHA256 {
		t.Fatalf("forensic header digest = %q, bundle digest = %q", got, bundle.EnvelopeSHA256)
	}
	// Timeline: exactly this run's events, never the foreign run's. The
	// attestation's own execution.attested event is part of the timeline.
	if len(bundle.Events) < 2 {
		t.Fatalf("events = %d, want at least the 2 run-scoped events: %+v", len(bundle.Events), bundle.Events)
	}
	seen := map[string]bool{}
	for _, e := range bundle.Events {
		if e.RunID != "run-a" {
			t.Fatalf("foreign event leaked into the bundle: %+v", e)
		}
		seen[e.Type] = true
	}
	if !seen["job.started"] || !seen["job.completed"] {
		t.Fatalf("seeded run events missing from the timeline: %+v", bundle.Events)
	}
	if bundle.EventsTruncated {
		t.Fatal("two events reported truncated")
	}
	if bundle.EventFrontier < 3 {
		t.Fatalf("event frontier = %d, want the run's latest committed seq", bundle.EventFrontier)
	}
	if bundle.RetainedFrom != 0 {
		t.Fatalf("retained_from = %d, want 0", bundle.RetainedFrom)
	}
	// References, digest-only.
	if len(bundle.Artifacts) != 1 || bundle.Artifacts[0].Name != "bin" || bundle.Artifacts[0].ProvenanceSHA256 == "" || bundle.Artifacts[0].SBOMSHA256 == "" {
		t.Fatalf("artifact refs = %+v", bundle.Artifacts)
	}
	if !strings.Contains(w.Body.String(), "sboms/bin.cdx.json") {
		t.Fatal("sidecar reference missing")
	}
	if len(bundle.Snapshots) != 1 || bundle.Snapshots[0].Phase != model.SnapshotPhasePreJob {
		t.Fatalf("snapshot refs = %+v", bundle.Snapshots)
	}
	if len(bundle.TestReports) != 1 || bundle.TestReports[0].SuiteDigest == "" || bundle.TestReports[0].Tests != 3 {
		t.Fatalf("report refs = %+v", bundle.TestReports)
	}

	// minimal/standard/default still serve the signed envelope bytes.
	wantEnvelope := fuzzEnvelopeBytes(t, s, "job-a")
	for _, profile := range []string{"", "minimal", "standard"} {
		p := "/api/v1/jobs/job-a/attestation"
		if profile != "" {
			p += "?profile=" + profile
		}
		w := doJSON(t, s, http.MethodGet, p, "token", "")
		if w.Code != http.StatusOK {
			t.Fatalf("profile %q = %d: %s", profile, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/vnd.dsse.envelope.v1+json") {
			t.Fatalf("profile %q content type = %q", profile, got)
		}
		if w.Body.String() != string(wantEnvelope) {
			t.Fatalf("profile %q served different bytes than the signed envelope", profile)
		}
	}

	// An unknown profile is a client error, never a silent fallback.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/job-a/attestation?profile=everything", "token", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown profile = %d, want 400", w.Code)
	}
}

// TestForensicProfileRequiresEventsCapability proves the timeline half of the
// bundle fails closed: a principal holding evidence:read but not the
// execution-event capability gets 403 and no part of the bundle, and adding
// the capability admits the same request.
func TestForensicProfileRequiresEventsCapability(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seedForensicAttempt(t, s, 3)
	repoKey := capabilityRepoKey(t, "github.com/acme/repo-a")
	if err := s.AuthStore.AddToken("evidence-only", auth.Principal{
		Subject: "auditor",
		RepositoryCapabilities: map[string][]auth.Capability{
			repoKey: {auth.CapEvidenceRead},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthStore.AddToken("evidence-and-events", auth.Principal{
		Subject: "auditor-events",
		RepositoryCapabilities: map[string][]auth.Capability{
			repoKey: {auth.CapEvidenceRead, auth.CapExecutionEventsRead},
		},
	}); err != nil {
		t.Fatal(err)
	}

	path := "/api/v1/jobs/job-a/attestation?profile=forensic"
	w := doJSON(t, s, http.MethodGet, path, "evidence-only", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("evidence-only forensic = %d, want 403: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "envelope_sha256") || strings.Contains(w.Body.String(), "attestation") {
		t.Fatalf("refused bundle leaked evidence: %s", w.Body.String())
	}
	// The standard profile stays available to the same principal: the extra
	// capability gates the MATERIALIZED streams, not the signed envelope.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/job-a/attestation", "evidence-only", ""); w.Code != http.StatusOK {
		t.Fatalf("evidence-only standard = %d, want 200: %s", w.Code, w.Body.String())
	}

	w = doJSON(t, s, http.MethodGet, path, "evidence-and-events", "")
	if w.Code != http.StatusOK {
		t.Fatalf("evidence+events forensic = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// fakeRetentionReader feeds forensicEventTimeline a scripted event ledger
// (the embedded nil Store is never called; only the retention read is).
type fakeRetentionReader struct {
	storage.Store
	events []model.ExecutionEvent
}

func (f fakeRetentionReader) ReadExecutionEventsRetention(_ context.Context, after int64, limit int, scope storage.ExecutionEventScope) ([]model.ExecutionEvent, int64, int64, int64, error) {
	var page []model.ExecutionEvent
	for _, e := range f.events {
		if e.Seq <= after {
			continue
		}
		if scope.Kind == storage.ExecutionEventScopeRun && e.RunID != scope.RunID {
			continue
		}
		if len(page) == limit {
			break
		}
		page = append(page, e)
	}
	cursor := after
	if len(page) > 0 {
		cursor = page[len(page)-1].Seq
	}
	var latest int64
	if n := len(f.events); n > 0 {
		latest = f.events[n-1].Seq
	}
	return page, cursor, 0, latest, nil
}

// TestForensicEventTimelineTruncatesOnlyWhenMoreExist pins the truncation
// semantics: a run-scoped ledger holding exactly the cap is COMPLETE (the
// earlier encoding marked it truncated before proving more events exist),
// while one holding more than the cap is truncated after the cap.
func TestForensicEventTimelineTruncatesOnlyWhenMoreExist(t *testing.T) {
	build := func(runID string, n int) []model.ExecutionEvent {
		events := make([]model.ExecutionEvent, 0, n)
		for i := 1; i <= n; i++ {
			events = append(events, model.ExecutionEvent{
				Seq: int64(i), Type: "job.started", RunID: runID, RepoID: "github.com/acme/" + runID,
			})
		}
		return events
	}
	s := New("token")
	s.DB = fakeRetentionReader{events: build("run-at-cap", maxForensicEvents)}

	atCap, _, _, truncatedAtCap, err := s.forensicEventTimeline(context.Background(), storage.ExecutionEventScope{
		Kind: storage.ExecutionEventScopeRun, RepoID: "github.com/acme/run-at-cap", RunID: "run-at-cap",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(atCap) != maxForensicEvents || truncatedAtCap {
		t.Fatalf("at-cap timeline = %d events truncated=%v, want %d complete", len(atCap), truncatedAtCap, maxForensicEvents)
	}

	s.DB = fakeRetentionReader{events: build("run-over-cap", maxForensicEvents+1)}
	overCap, _, _, truncatedOverCap, err := s.forensicEventTimeline(context.Background(), storage.ExecutionEventScope{
		Kind: storage.ExecutionEventScopeRun, RepoID: "github.com/acme/run-over-cap", RunID: "run-over-cap",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(overCap) != maxForensicEvents || !truncatedOverCap {
		t.Fatalf("over-cap timeline = %d events truncated=%v, want %d truncated", len(overCap), truncatedOverCap, maxForensicEvents)
	}
}

// fuzzEnvelopeBytes fetches the raw signed envelope the default profile
// serves, for byte-identity comparisons.
func fuzzEnvelopeBytes(t *testing.T, s *Server, jobID string) []byte {
	t.Helper()
	w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/attestation", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("envelope = %d: %s", w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// The forensic evidence profile (docs/evidence-contract.md §6) materializes
// the streams a standard execution attestation only REFERENCES: the bounded
// execution-event timeline, the artifact/snapshot/report records (digests and
// sidecar references, never contents) and the retention watermarks.
//
// The bundle is deliberately UNSIGNED: Kiwi never mints a second statement at
// retrieval time (the redaction rule — projection, canonicalization, then
// signature — forbids post-hoc evidence surgery). The embedded DSSE envelope
// stays the signed artifact; every other bundle field is a digest/reference
// the consumer can recompute or re-fetch through its own authorized reads.
const (
	// forensicSchema tags the bundle wire shape.
	forensicSchema = "kiwi-ci/execution-evidence-bundle/v1"
	// forensicEventPage bounds one event-ledger read.
	forensicEventPage = 250
	// maxForensicEvents bounds the total timeline materialized in one bundle:
	// the forensic profile must stay economical (the audit's evidence-cost
	// concern), so the timeline is capped and the truncation is reported
	// rather than silently materializing an unbounded ledger.
	maxForensicEvents = 1000
)

// forensicBundle is the wire shape of the forensic evidence materialization.
type forensicBundle struct {
	Schema      string    `json:"schema"`
	Profile     string    `json:"profile"`
	GeneratedAt time.Time `json:"generated_at"`
	RunID       string    `json:"run_id"`
	JobID       string    `json:"job_id"`
	JobKey      string    `json:"job_key,omitempty"`
	AttemptID   string    `json:"attempt_id"`
	Generation  int64     `json:"generation"`

	// Attestation is the signed DSSE envelope (raw bytes) plus the digests a
	// consumer checks it with; these three fields anchor the whole bundle.
	Attestation     json.RawMessage `json:"attestation"`
	EnvelopeSHA256  string          `json:"envelope_sha256"`
	StatementSHA256 string          `json:"statement_sha256"`

	Artifacts   []forensicArtifactRef `json:"artifacts"`
	Snapshots   []forensicSnapshotRef `json:"snapshots"`
	TestReports []forensicReportRef   `json:"test_reports"`

	Events          []model.ExecutionEvent `json:"events"`
	EventsTruncated bool                   `json:"events_truncated"`
	EventFrontier   int64                  `json:"event_frontier,omitempty"`
	RetainedFrom    int64                  `json:"retained_from"`
}

// forensicArtifactRef references one artifact of the attempt: identity,
// digest, ownership and sidecar (provenance/SBOM/Sigstore) references only —
// artifact contents are never copied into evidence.
type forensicArtifactRef struct {
	Name             string `json:"name"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size,omitempty"`
	ProvenanceSHA256 string `json:"provenance_sha256,omitempty"`
	SBOMPath         string `json:"sbom_path,omitempty"`
	SBOMSHA256       string `json:"sbom_sha256,omitempty"`
	SigstorePath     string `json:"sigstore_path,omitempty"`
	SigstoreSHA256   string `json:"sigstore_sha256,omitempty"`
}

// forensicSnapshotRef references one workspace checkpoint of the attempt.
type forensicSnapshotRef struct {
	ID         string `json:"id"`
	Phase      string `json:"phase,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	RootSHA256 string `json:"root_sha256,omitempty"`
	Generation int64  `json:"generation,omitempty"`
}

// forensicReportRef references one test report: the canonical suite digest
// and case counts, never raw messages (masking and size stay server-side).
type forensicReportRef struct {
	Name        string `json:"name"`
	SuiteDigest string `json:"suite_digest"`
	Generation  int64  `json:"generation,omitempty"`
	Tests       int    `json:"tests,omitempty"`
	Failures    int    `json:"failures,omitempty"`
	Errors      int    `json:"errors,omitempty"`
	Skipped     int    `json:"skipped,omitempty"`
}

// writeForensicBundle serves GET /api/v1/jobs/{id}/attestation?profile=forensic.
// The caller has already proven evidence:read on the run; the timeline half
// additionally requires execution.events:read (or a repo read capability) on
// the same run, checked by the caller before this handler runs, so a
// principal without the events capability gets NOTHING rather than a partial
// bundle.
func (s *Server) writeForensicBundle(w http.ResponseWriter, r *http.Request, j model.Job, generation int64, rec model.ExecutionAttestationRecord) {
	ctx := r.Context()
	envBytes, err := s.readExecutionAttestationEnvelope(ctx, rec)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Attempt-scoped record references, gathered through the same evidence
	// path the attestation itself was built from.
	var ev attestationEvidence
	ok := false
	if s.DB != nil {
		ev, ok, err = s.gatherAttestationEvidenceDB(ctx, j.ID, generation)
		if err != nil {
			s.internalError(w, r, err, "")
			return
		}
	} else {
		ev, ok = s.gatherAttestationEvidenceLocal(j.ID, generation)
	}
	if !ok {
		http.NotFound(w, r)
		return
	}

	// The event timeline is run-scoped and bounded; a materialization failure
	// fails the whole request closed (no partial forensic picture).
	scope := storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRun, RepoID: storage.RepoIDForJob(j), RunID: j.RunID}
	events, retained, latest, truncated, err := s.forensicEventTimeline(ctx, scope)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}

	bundle := forensicBundle{
		Schema:          forensicSchema,
		Profile:         "forensic",
		GeneratedAt:     time.Now().UTC(),
		RunID:           j.RunID,
		JobID:           j.ID,
		JobKey:          j.Key,
		AttemptID:       model.AttemptID(j.ID, generation),
		Generation:      generation,
		Attestation:     json.RawMessage(envBytes),
		StatementSHA256: rec.StatementSHA256,
		Events:          events,
		EventsTruncated: truncated,
		EventFrontier:   latest,
		RetainedFrom:    retained,
	}
	// The envelope digest is recomputed from the served bytes (the record's
	// reference names the CAS digest in CAS mode, but recomputing keeps the
	// bundle self-consistent in every storage mode). The same digest and the
	// statement digest also travel as headers through the shared emitter, so
	// every profile serving this envelope advertises the identical contract.
	bundle.EnvelopeSHA256 = writeEnvelopeDigestHeaders(w, envBytes, rec.StatementSHA256)

	for _, a := range ev.artifacts {
		bundle.Artifacts = append(bundle.Artifacts, forensicArtifactRef{
			Name:             a.Name,
			SHA256:           a.SHA256,
			Size:             a.Size,
			ProvenanceSHA256: a.ProvenanceSHA256,
			SBOMPath:         a.SBOMPath,
			SBOMSHA256:       a.SBOMSHA256,
			SigstorePath:     a.SigstorePath,
			SigstoreSHA256:   a.SigstoreSHA256,
		})
	}
	for _, snap := range ev.snapshots {
		bundle.Snapshots = append(bundle.Snapshots, forensicSnapshotRef{
			ID:         snap.ID,
			Phase:      snap.Phase,
			SHA256:     snap.SHA256,
			RootSHA256: snap.RootSHA256,
			Generation: snap.LeaseGeneration,
		})
	}
	for _, rep := range ev.reports {
		name := rep.JobKey
		if name == "" {
			name = rep.ID
		}
		bundle.TestReports = append(bundle.TestReports, forensicReportRef{
			Name:        name,
			SuiteDigest: provenance.TestReportSuiteDigest(rep),
			Generation:  rep.LeaseGeneration,
			Tests:       rep.Tests,
			Failures:    rep.Failures,
			Errors:      rep.Errors,
			Skipped:     rep.Skipped,
		})
	}
	writeJSON(w, http.StatusOK, bundle)
}

// forensicEventTimeline pages the run-scoped execution-event ledger up to the
// forensic cap. The retention watermark and latest cursor come from the same
// landed read the /api/v1/events consumers use, so the bundle can never
// disagree with what a live consumer saw. Truncation is reported ONLY after a
// read proves the ledger continues beyond the materialized window: a ledger
// holding exactly the cap is complete, not truncated.
func (s *Server) forensicEventTimeline(ctx context.Context, scope storage.ExecutionEventScope) (events []model.ExecutionEvent, retainedFrom, latest int64, truncated bool, err error) {
	after := int64(0)
	for len(events) < maxForensicEvents {
		limit := forensicEventPage
		if remaining := maxForensicEvents - len(events); remaining < limit {
			limit = remaining
		}
		page, cursor, retained, lat, rerr := s.readExecutionEventsRetention(ctx, after, limit, scope)
		if rerr != nil {
			return nil, 0, 0, false, rerr
		}
		retainedFrom, latest = retained, lat
		page = filterExecutionEventsInScope(page, scope)
		events = append(events, page...)
		if len(page) < limit || cursor <= after {
			return events, retainedFrom, latest, false, nil
		}
		after = cursor
	}
	// The cap was reached. One extra one-event read proves whether the ledger
	// continues beyond the materialized window before the bundle claims
	// truncation.
	more, _, retained, lat, rerr := s.readExecutionEventsRetention(ctx, after, 1, scope)
	if rerr != nil {
		return nil, 0, 0, false, rerr
	}
	retainedFrom, latest = retained, lat
	more = filterExecutionEventsInScope(more, scope)
	return events, retainedFrom, latest, len(more) > 0, nil
}

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// maxAttestationEnvelopeBytes bounds a served/published attestation envelope.
// It mirrors provenance's envelope cap so an oversized record can never be
// materialized in memory unbounded.
const maxAttestationEnvelopeBytes = 8 << 20

// attestExecution is the `execution_attest` completion effect: it builds,
// signs and durably records the FINAL execution attestation of one terminal
// attempt (jobID, generation). The effect is idempotent by marker: the
// execution_attestations (job_id, generation) primary key (DB) / the
// in-memory attestation map (fs/memory) is the marker, so a repeated dispatch
// after a restart, a receipt replay or a concurrent replica converges on
// exactly one row, one envelope object and one execution.attested event.
//
// A missing job is treated as already reconciled (completion effects run
// after the job exists; a deleted/absent job has no attempt to attest). Every
// other failure is returned so the INTERNAL outbox intent retries forever
// until the attestation commits.
func (s *Server) attestExecution(ctx context.Context, jobID string, generation int64) error {
	if jobID == "" {
		return nil
	}
	if _, found, err := s.lookupExecutionAttestation(ctx, jobID, generation); err != nil {
		return err
	} else if found {
		return nil
	}
	if s.DB != nil {
		return s.attestExecutionDB(ctx, jobID, generation)
	}
	return s.attestExecutionLocal(ctx, jobID, generation)
}

// attestationEvidence is the durable evidence of one attempt gathered from
// the store (DB mode) or the in-memory mirrors (fs/memory mode) before the
// statement is built and signed.
type attestationEvidence struct {
	job       model.Job
	run       model.Run
	artifacts []model.ArtifactRecord
	reports   []model.TestReport
	snapshots []model.SnapshotRecord
}

// gatherAttestationEvidenceDB loads the attempt's durable evidence through
// the store interfaces. A missing job is reported with ok=false; a missing
// run is a hard error (the job's own evidence cannot be scoped).
func (s *Server) gatherAttestationEvidenceDB(ctx context.Context, jobID string, generation int64) (attestationEvidence, bool, error) {
	j, err := s.DB.GetJob(ctx, jobID)
	if errors.Is(err, storage.ErrNotFound) {
		return attestationEvidence{}, false, nil
	}
	if err != nil {
		return attestationEvidence{}, false, err
	}
	run, err := s.DB.GetRun(ctx, j.RunID)
	if err != nil {
		return attestationEvidence{}, false, err
	}
	var ev attestationEvidence
	ev.job, ev.run = j, run
	arts, err := s.DB.ListArtifacts(ctx, j.RunID)
	if err != nil {
		return attestationEvidence{}, false, err
	}
	for _, a := range arts {
		if a.JobID == jobID && a.LeaseGeneration == generation {
			ev.artifacts = append(ev.artifacts, a)
		}
	}
	reports, err := s.DB.ListTestReports(ctx, j.RunID)
	if err != nil {
		return attestationEvidence{}, false, err
	}
	for _, r := range reports {
		if r.JobID == jobID && r.LeaseGeneration == generation {
			ev.reports = append(ev.reports, r)
		}
	}
	if ss, ok := s.DB.(storage.SnapshotStore); ok {
		snaps, err := ss.ListSnapshotsByRun(ctx, j.RunID)
		if err != nil {
			return attestationEvidence{}, false, err
		}
		for _, rec := range snaps {
			if rec.JobID == jobID && rec.LeaseGeneration == generation {
				ev.snapshots = append(ev.snapshots, rec)
			}
		}
	}
	return ev, true, nil
}

// gatherAttestationEvidenceLocal snapshots the in-memory evidence under s.mu.
func (s *Server) gatherAttestationEvidenceLocal(jobID string, generation int64) (attestationEvidence, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		return attestationEvidence{}, false
	}
	run := s.runs[j.RunID]
	ev := attestationEvidence{job: j, run: run}
	for _, a := range s.artifacts {
		if a.JobID == jobID && a.LeaseGeneration == generation {
			ev.artifacts = append(ev.artifacts, a)
		}
	}
	for _, r := range s.reports {
		if r.JobID == jobID && r.LeaseGeneration == generation {
			ev.reports = append(ev.reports, r)
		}
	}
	for _, rec := range s.snapshots {
		if rec.JobID == jobID && rec.LeaseGeneration == generation {
			ev.snapshots = append(ev.snapshots, rec)
		}
	}
	return ev, true
}

// attestationInput assembles the signed statement's input from durable
// evidence. Capsule digests are recomputed from the PERSISTED payload with
// the same shared helpers the artifact provenance path uses; unresolvable
// optional identity is omitted, never fabricated.
func attestationInput(ev attestationEvidence, generation int64) provenance.ExecutionAttestationInput {
	j := ev.job
	in := provenance.ExecutionAttestationInput{
		RunID:           j.RunID,
		JobID:           j.ID,
		JobKey:          j.Key,
		Generation:      generation,
		Status:          string(j.Status),
		StartedAt:       j.StartedAt,
		FinishedAt:      j.FinishedAt,
		RunnerIdentity:  j.AttemptRunnerID,
		ObservedRuntime: j.ObservedRuntime,
	}
	if p := j.CompiledJobPayload; p != nil {
		if d, err := provenance.CapsuleDigest(p); err == nil {
			in.CapsuleDigest = d
		}
		in.ExecutionCapsuleDigest = executionCapsuleDigestForJob(j)
	}
	for _, a := range ev.artifacts {
		in.Artifacts = append(in.Artifacts, provenance.ExecutionAttestationArtifact{
			Name:             a.Name,
			SHA256:           a.SHA256,
			Size:             a.Size,
			ProvenanceSHA256: a.ProvenanceSHA256,
		})
	}
	for _, r := range ev.reports {
		name := strings.TrimSpace(r.JobKey)
		if name == "" {
			name = r.ID
		}
		in.TestReports = append(in.TestReports, provenance.ExecutionAttestationReport{
			Name:        name,
			SuiteDigest: provenance.TestReportSuiteDigest(r),
			Generation:  r.LeaseGeneration,
		})
	}
	for _, rec := range ev.snapshots {
		in.Snapshots = append(in.Snapshots, provenance.ExecutionAttestationSnapshot{
			ID:         rec.ID,
			Phase:      rec.Phase,
			SHA256:     rec.SHA256,
			Generation: rec.LeaseGeneration,
		})
		switch rec.Phase {
		case model.SnapshotPhasePreJob:
			if in.WorkspaceRootSHA256 == "" {
				in.WorkspaceRootSHA256 = rec.RootSHA256
			}
		case model.SnapshotPhasePostJob, "":
			if in.MaterialRootSHA256 == "" {
				in.MaterialRootSHA256 = rec.RootSHA256
			}
		}
	}
	return in
}

// signAttestationEnvelope builds the deterministic statement, signs it and
// returns the envelope bytes, their digest and the statement digest.
func (s *Server) signAttestationEnvelope(in provenance.ExecutionAttestationInput) (envBytes []byte, envelopeDigest, statementDigest string, err error) {
	st, err := provenance.ExecutionAttestationStatement(in)
	if err != nil {
		return nil, "", "", err
	}
	signer := s.ensureProvenanceKey()
	env, err := provenance.Sign(st, signer.KID, signer.Private)
	if err != nil {
		return nil, "", "", err
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, "", "", fmt.Errorf("attestation envelope payload: %w", err)
	}
	statementSum := sha256.Sum256(payload)
	envBytes, err = json.Marshal(env)
	if err != nil {
		return nil, "", "", err
	}
	envSum := sha256.Sum256(envBytes)
	return envBytes, hex.EncodeToString(envSum[:]), hex.EncodeToString(statementSum[:]), nil
}

// attestationCASMode mirrors the artifact upload transport split: DB mode
// with a configured CAS publishes the envelope as a shared content-addressed
// object; fs/memory mode keeps the durable local sidecar.
func (s *Server) attestationCASMode() bool {
	return s.DB != nil && s.CAS != nil
}

// publishExecutionAttestationEnvelope publishes the signed envelope durably
// and returns its record reference plus the digest fence (if any) the caller
// must hold until the record commit.
//
// Ordering: the envelope object is published BEFORE the attestation row for
// the same reason the artifact payload is published before its record — the
// collector can never reclaim an object whose reference is about to commit.
// Under CAS the digest fence is held across the commit; a failed publication
// returns an error and commits no row (the effect retries).
func (s *Server) publishExecutionAttestationEnvelope(ctx context.Context, envBytes []byte, digest, dir string) (string, func(), error) {
	if s.attestationCASMode() {
		fctx, cancel := context.WithTimeout(ctx, provenanceFenceTimeout)
		release, ferr := s.acquireDigestFence(fctx, digest)
		cancel()
		if ferr != nil {
			return "", nil, ferr
		}
		pobj, perr := s.CAS.PutKnown(ctx, digest, int64(len(envBytes)), bytes.NewReader(envBytes))
		if perr != nil {
			release()
			return "", nil, perr
		}
		if pobj.Key != digest || pobj.SHA256 != digest || pobj.Size != int64(len(envBytes)) {
			release()
			return "", nil, fmt.Errorf("attestation CAS object disagrees with the envelope (key %s sha %s size %d)", pobj.Key, pobj.SHA256, pobj.Size)
		}
		return "cas:" + digest, release, nil
	}
	if s.store == nil || dir == "" {
		// Bare in-memory server (tests): the record is authoritative in
		// memory and no durable envelope exists.
		return "", func() {}, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, digest+".json")
	if err := s.publishProvenanceSidecarFS(path, envBytes, digest); err != nil {
		return "", nil, err
	}
	return path, func() {}, nil
}

// attestExecutionDB is the PostgreSQL path: gather durable evidence, build
// and sign the statement, publish the envelope, then commit the insert-once
// row and its execution.attested event in one store transaction.
func (s *Server) attestExecutionDB(ctx context.Context, jobID string, generation int64) error {
	ev, ok, err := s.gatherAttestationEvidenceDB(ctx, jobID, generation)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	store, ok := s.DB.(storage.ExecutionAttestationStore)
	if !ok {
		return fmt.Errorf("attestation: store lacks the ExecutionAttestationStore contract")
	}
	envBytes, envelopeDigest, statementDigest, err := s.signAttestationEnvelope(attestationInput(ev, generation))
	if err != nil {
		return err
	}
	dir := ""
	if s.store != nil {
		dir = filepath.Join(s.store.Root, "attestations", ev.job.RunID)
	}
	ref, release, err := s.publishExecutionAttestationEnvelope(ctx, envBytes, envelopeDigest, dir)
	if err != nil {
		return err
	}
	defer release()
	rec := model.ExecutionAttestationRecord{
		JobID:           jobID,
		Generation:      generation,
		RunID:           ev.job.RunID,
		Status:          string(ev.job.Status),
		StatementSHA256: statementDigest,
		EnvelopeRef:     ref,
		CreatedAt:       time.Now().UTC(),
	}
	if _, _, err := store.CommitExecutionAttestation(ctx, rec, storage.ExecutionAttestationEvent(rec)); err != nil {
		return err
	}
	return nil
}

// attestExecutionLocal is the fs/memory path: snapshot the in-memory
// evidence, build/sign/publish the envelope durably, then insert the marker
// row into the snapshot in the SAME critical section and append the event
// best-effort. A failed snapshot write rolls the marker back so the retry
// re-runs instead of acknowledging an attestation the durable state does not
// contain.
func (s *Server) attestExecutionLocal(ctx context.Context, jobID string, generation int64) error {
	ev, ok := s.gatherAttestationEvidenceLocal(jobID, generation)
	if !ok {
		return nil
	}
	envBytes, envelopeDigest, statementDigest, err := s.signAttestationEnvelope(attestationInput(ev, generation))
	if err != nil {
		return err
	}
	key := model.AttemptID(jobID, generation)
	s.mu.Lock()
	_, found := s.attestations[key]
	s.mu.Unlock()
	if found {
		return nil
	}
	dir := ""
	if s.store != nil {
		dir = filepath.Join(s.store.Root, "attestations", ev.job.RunID)
	}
	ref, release, err := s.publishExecutionAttestationEnvelope(ctx, envBytes, envelopeDigest, dir)
	if err != nil {
		return err
	}
	defer release()
	rec := model.ExecutionAttestationRecord{
		JobID:           jobID,
		Generation:      generation,
		RunID:           ev.job.RunID,
		Status:          string(ev.job.Status),
		StatementSHA256: statementDigest,
		EnvelopeRef:     ref,
		CreatedAt:       time.Now().UTC(),
	}
	s.mu.Lock()
	if s.attestations == nil {
		s.attestations = map[string]model.ExecutionAttestationRecord{}
	}
	if _, exists := s.attestations[key]; exists {
		s.mu.Unlock()
		return nil
	}
	s.attestations[key] = rec
	if err := s.persistCheckedErrLocked("job.execution_attest"); err != nil {
		delete(s.attestations, key)
		s.mu.Unlock()
		return err
	}
	// execution.attested is appended next to the durable marker (best-effort
	// in fs mode; the marker is already durable).
	s.appendExecutionEventLocked(storage.ExecutionAttestationEvent(rec))
	s.mu.Unlock()
	return nil
}

// lookupExecutionAttestation resolves the durable marker: the store record in
// DB mode, the in-memory map otherwise.
func (s *Server) lookupExecutionAttestation(ctx context.Context, jobID string, generation int64) (model.ExecutionAttestationRecord, bool, error) {
	if s.DB != nil {
		if store, ok := s.DB.(storage.ExecutionAttestationStore); ok {
			return store.GetExecutionAttestation(ctx, jobID, generation)
		}
		return model.ExecutionAttestationRecord{}, false, fmt.Errorf("attestation: store lacks the ExecutionAttestationStore contract")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.attestations[model.AttemptID(jobID, generation)]
	return rec, ok, nil
}

// jobForAttestation resolves the addressed job (store in DB mode, memory map
// otherwise) for the attestation read route.
func (s *Server) jobForAttestation(ctx context.Context, id string) (model.Job, error) {
	if s.DB != nil {
		return s.DB.GetJob(ctx, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return model.Job{}, storage.ErrNotFound
	}
	return j, nil
}

// getJobAttestation serves GET /api/v1/jobs/{id}/attestation: the signed
// DSSE envelope of the job's final execution attestation. The route consumes
// evidence:read (run-scoped) or the admin action, resolved by
// requireRunCapability. A job or attestation that does not exist answers 404;
// the optional ?generation= query selects one attempt (default: the job's
// current lease generation).
func (s *Server) getJobAttestation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	j, err := s.jobForAttestation(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	if !s.requireRunCapability(w, r, auth.CapEvidenceRead, j.RunID) {
		return
	}
	generation := j.LeaseGeneration
	if q := strings.TrimSpace(r.URL.Query().Get("generation")); q != "" {
		parsed, perr := strconv.ParseInt(q, 10, 64)
		if perr != nil || parsed < 0 {
			http.Error(w, "invalid generation", http.StatusBadRequest)
			return
		}
		generation = parsed
	}
	rec, found, err := s.lookupExecutionAttestation(r.Context(), id, generation)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	envBytes, err := s.readExecutionAttestationEnvelope(r.Context(), rec)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256(envBytes)
	w.Header().Set("Content-Type", "application/vnd.dsse.envelope.v1+json")
	w.Header().Set("X-Kiwi-Content-SHA256", hex.EncodeToString(sum[:]))
	w.Header().Set("X-Kiwi-Statement-SHA256", rec.StatementSHA256)
	_, _ = w.Write(envBytes)
}

// readExecutionAttestationEnvelope reads the envelope bytes of a record: CAS
// mode opens the content-addressed object by digest (verified by the CAS
// reader), fs mode reads the sidecar file. The read is bounded; an oversized
// or unreadable envelope is an error (the route answers 404 rather than
// serving a truncated body).
func (s *Server) readExecutionAttestationEnvelope(ctx context.Context, rec model.ExecutionAttestationRecord) ([]byte, error) {
	if rec.EnvelopeRef == "" {
		return nil, os.ErrNotExist
	}
	if strings.HasPrefix(rec.EnvelopeRef, "cas:") {
		if s.CAS == nil {
			return nil, os.ErrNotExist
		}
		rc, _, err := s.CAS.Open(ctx, strings.TrimPrefix(rec.EnvelopeRef, "cas:"))
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return readBounded(rc, maxAttestationEnvelopeBytes)
	}
	f, err := os.Open(rec.EnvelopeRef)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readBounded(f, maxAttestationEnvelopeBytes)
}

// readBounded reads at most limit bytes and rejects a source that exceeds it.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("attestation envelope exceeds %d byte limit", limit)
	}
	return b, nil
}

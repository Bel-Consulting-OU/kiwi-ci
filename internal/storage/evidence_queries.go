package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// AttemptEvidenceStore is the OPTIONAL attempt-scoped evidence read contract.
// It returns exactly the records one attempt (job_id, lease_generation)
// committed: the artifact records, test reports and workspace snapshots whose
// attempt identity matches. Stores that implement it let the final execution
// attestation gather one attempt's evidence with small indexed queries
// instead of loading every row of the run and filtering in Go (an O(n^2) walk
// over a run with n completed jobs). Callers must fall back to the run-scoped
// lists when a store does not implement it.
type AttemptEvidenceStore interface {
	ListArtifactsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.ArtifactRecord, error)
	ListTestReportsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.TestReport, error)
	ListSnapshotsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.SnapshotRecord, error)
}

var (
	_ AttemptEvidenceStore = (*PostgresStore)(nil)
	_ AttemptEvidenceStore = (*memStore)(nil)
	_ AttemptEvidenceStore = (*FaultyStore)(nil)
)

// ListArtifactsByJobGeneration reads the attempt's artifact records through
// artifacts_job_generation_name_idx (migration 0010): the (job_id,
// job_generation) prefix is the index range, so the read is proportional to
// the attempt's evidence, not to the run.
func (s *PostgresStore) ListArtifactsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.ArtifactRecord, error) {
	if err := ValidateJobID(jobID); err != nil {
		return nil, err
	}
	if generation < 0 {
		return nil, fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	rows, err := s.pool.Query(ctx, `SELECT payload FROM artifacts WHERE job_id=$1 AND job_generation=$2 ORDER BY created_at ASC, id ASC`, jobID, generation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ArtifactRecord{}
	for rows.Next() {
		var (
			payload []byte
			a       model.ArtifactRecord
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListTestReportsByJobGeneration reads the attempt's test reports through
// test_results_job_lease_generation_idx (migration 0055).
func (s *PostgresStore) ListTestReportsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.TestReport, error) {
	if err := ValidateJobID(jobID); err != nil {
		return nil, err
	}
	if generation < 0 {
		return nil, fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	return s.listTestReports(ctx, `SELECT payload FROM test_results WHERE job_id=$1 AND lease_generation=$2 ORDER BY created_at ASC, id ASC`, jobID, generation)
}

// ListSnapshotsByJobGeneration reads the attempt's workspace snapshots
// through workspace_snapshots_job_lease_generation_idx (migration 0055).
func (s *PostgresStore) ListSnapshotsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.SnapshotRecord, error) {
	if err := ValidateJobID(jobID); err != nil {
		return nil, err
	}
	if generation < 0 {
		return nil, fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	rows, err := s.pool.Query(ctx, `SELECT payload FROM workspace_snapshots WHERE job_id=$1 AND lease_generation=$2 ORDER BY created_at ASC, id ASC`, jobID, generation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SnapshotRecord{}
	for rows.Next() {
		var (
			payload []byte
			rec     model.SnapshotRecord
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ListArtifactsByJobGeneration is the in-memory mirror: a scan of the resident
// artifact records filtered by the attempt identity.
func (m *memStore) ListArtifactsByJobGeneration(_ context.Context, jobID string, generation int64) ([]model.ArtifactRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.ArtifactRecord{}
	for _, a := range m.artifacts {
		if a.JobID == jobID && a.LeaseGeneration == generation {
			out = append(out, a)
		}
	}
	return out, nil
}

// ListTestReportsByJobGeneration is the in-memory mirror.
func (m *memStore) ListTestReportsByJobGeneration(_ context.Context, jobID string, generation int64) ([]model.TestReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.TestReport{}
	for _, rep := range m.reports {
		if rep.JobID == jobID && rep.LeaseGeneration == generation {
			out = append(out, rep)
		}
	}
	return out, nil
}

// ListSnapshotsByJobGeneration is the in-memory mirror.
func (m *memStore) ListSnapshotsByJobGeneration(_ context.Context, jobID string, generation int64) ([]model.SnapshotRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.SnapshotRecord{}
	for _, rec := range m.snapshots {
		if rec.JobID == jobID && rec.LeaseGeneration == generation {
			out = append(out, rec)
		}
	}
	return out, nil
}

// FaultyStore delegation for the attempt-scoped evidence contract: reads do
// not consume the fault counter, mirroring the run-scoped lists.
func (f *FaultyStore) ListArtifactsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.ArtifactRecord, error) {
	inner, ok := f.Inner.(AttemptEvidenceStore)
	if !ok {
		return nil, errMissingInnerInterface("AttemptEvidenceStore")
	}
	return inner.ListArtifactsByJobGeneration(ctx, jobID, generation)
}

func (f *FaultyStore) ListTestReportsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.TestReport, error) {
	inner, ok := f.Inner.(AttemptEvidenceStore)
	if !ok {
		return nil, errMissingInnerInterface("AttemptEvidenceStore")
	}
	return inner.ListTestReportsByJobGeneration(ctx, jobID, generation)
}

func (f *FaultyStore) ListSnapshotsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.SnapshotRecord, error) {
	inner, ok := f.Inner.(AttemptEvidenceStore)
	if !ok {
		return nil, errMissingInnerInterface("AttemptEvidenceStore")
	}
	return inner.ListSnapshotsByJobGeneration(ctx, jobID, generation)
}

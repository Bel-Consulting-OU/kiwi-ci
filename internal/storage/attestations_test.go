package storage

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func memAttestationRecord(gen int64) model.ExecutionAttestationRecord {
	return model.ExecutionAttestationRecord{
		JobID:           leaseJobID,
		Generation:      gen,
		RunID:           leaseRunID,
		Status:          string(model.StatusSuccess),
		StatementSHA256: strings.Repeat("a", 64),
		EnvelopeRef:     "cas:" + strings.Repeat("b", 64),
		CreatedAt:       time.Unix(1700000000, 0).UTC(),
	}
}

func TestMemStoreCommitExecutionAttestationIdempotent(t *testing.T) {
	m := newMemStore()
	rec := memAttestationRecord(1)
	stored, created, err := m.CommitExecutionAttestation(ctx(), rec, ExecutionAttestationEvent(rec))
	if err != nil || !created {
		t.Fatalf("commit = %v/%v, want created", created, err)
	}
	if stored.StatementSHA256 != rec.StatementSHA256 || stored.EnvelopeRef != rec.EnvelopeRef || stored.CreatedAt.IsZero() {
		t.Fatalf("stored record = %+v", stored)
	}
	// A replay returns the STORED record and appends nothing.
	replay := memAttestationRecord(1)
	replay.StatementSHA256 = strings.Repeat("c", 64)
	again, created, err := m.CommitExecutionAttestation(ctx(), replay, ExecutionAttestationEvent(replay))
	if err != nil || created {
		t.Fatalf("replay = %v/%v, want stored", created, err)
	}
	if again.StatementSHA256 != rec.StatementSHA256 {
		t.Fatalf("replay rewrote the record: %+v", again)
	}
	got, found, err := m.GetExecutionAttestation(ctx(), leaseJobID, 1)
	if err != nil || !found || got.EnvelopeRef != rec.EnvelopeRef {
		t.Fatalf("get = %+v/%v/%v", got, found, err)
	}
	if _, found, err := m.GetExecutionAttestation(ctx(), leaseJobID, 2); err != nil || found {
		t.Fatalf("missing generation = %v/%v, want absent", found, err)
	}
	// Exactly one execution.attested event across the two commits.
	m.mu.Lock()
	events := 0
	for _, e := range m.events {
		if e.Type == model.EventExecutionAttested {
			events++
			if e.Attempt != 1 || e.JobID != leaseJobID || e.Payload["attempt"] != leaseJobID+":1" {
				m.mu.Unlock()
				t.Fatalf("attested event = %+v", e)
			}
		}
	}
	m.mu.Unlock()
	if events != 1 {
		t.Fatalf("execution.attested events = %d, want 1", events)
	}
}

func TestMemStoreRequiredProvenanceArtifactGate(t *testing.T) {
	newLeased := func(t *testing.T) *memStore {
		t.Helper()
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, model.ResourceCapacity{})
		resourceJob(t, m, leaseRunID, leaseJobID, model.ResourceCapacity{})
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, model.ResourceCapacity{})); err != nil {
			t.Fatalf("lease: %v", err)
		}
		return m
	}
	complete := func(m *memStore) error {
		receipt := model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner, ResultHash: "h"}
		return m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, receipt, nil)
	}
	artifact := func(prov string) model.ArtifactRecord {
		return model.ArtifactRecord{ID: strings.Repeat("ab", 16), RunID: leaseRunID, JobID: leaseJobID, Name: "bin", SHA256: strings.Repeat("1", 64), LeaseGeneration: 1, ProvenanceSHA256: prov}
	}

	t.Run("required provenance blocks completion without provenance", func(t *testing.T) {
		m := newLeased(t)
		if err := m.InsertJobContracts(ctx(), leaseJobID, map[string]ArtifactContract{
			"bin": {Name: "bin", Required: true, Provenance: ArtifactProvenanceRequired},
		}); err != nil {
			t.Fatal(err)
		}
		if err := m.InsertArtifact(ctx(), artifact("")); err != nil {
			t.Fatal(err)
		}
		if err := complete(m); !errors.Is(err, ErrRequiredArtifactMissing) {
			t.Fatalf("completion = %v, want ErrRequiredArtifactMissing", err)
		}
		// The job stays running so the runner can publish provenance and retry.
		j, _ := m.GetJob(ctx(), leaseJobID)
		if j.Status != model.StatusRunning {
			t.Fatalf("job status = %s, want running", j.Status)
		}
		// A record carrying durable provenance satisfies the gate.
		if err := m.InsertArtifact(ctx(), artifact(strings.Repeat("2", 64))); err != nil {
			t.Fatal(err)
		}
		if err := complete(m); err != nil {
			t.Fatalf("completion with provenance = %v", err)
		}
	})

	t.Run("best_effort keeps the historical gate", func(t *testing.T) {
		m := newLeased(t)
		if err := m.InsertJobContracts(ctx(), leaseJobID, map[string]ArtifactContract{
			"bin": {Name: "bin", Required: true},
		}); err != nil {
			t.Fatal(err)
		}
		if err := m.InsertArtifact(ctx(), artifact("")); err != nil {
			t.Fatal(err)
		}
		if err := complete(m); err != nil {
			t.Fatalf("best-effort completion = %v", err)
		}
	})

	t.Run("required artifact without contract provenance still blocks when missing", func(t *testing.T) {
		m := newLeased(t)
		if err := m.InsertJobContracts(ctx(), leaseJobID, map[string]ArtifactContract{
			"bin": {Name: "bin", Required: true, Provenance: ArtifactProvenanceRequired},
		}); err != nil {
			t.Fatal(err)
		}
		if err := complete(m); !errors.Is(err, ErrRequiredArtifactMissing) {
			t.Fatalf("completion = %v, want ErrRequiredArtifactMissing", err)
		}
	})
}

func TestMemStoreLogLeaseGenerationRoundTrip(t *testing.T) {
	m := newMemStore()
	entry := model.LogEntry{RunID: leaseRunID, JobID: leaseJobID, Step: "run", Line: "hello", LeaseGeneration: 4, CreatedAt: time.Now().UTC()}
	if err := m.AppendLog(ctx(), entry); err != nil {
		t.Fatal(err)
	}
	logs, err := m.ReadLogs(ctx(), leaseRunID, -1, 10)
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs = %+v err=%v", logs, err)
	}
	if logs[0].LeaseGeneration != 4 {
		t.Fatalf("log generation = %d, want 4", logs[0].LeaseGeneration)
	}
	// Legacy entry with no generation reads back as 0.
	if err := m.AppendLog(ctx(), model.LogEntry{RunID: leaseRunID, Line: "legacy", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	logs, err = m.ReadLogs(ctx(), leaseRunID, -1, 10)
	if err != nil || len(logs) != 2 || logs[1].LeaseGeneration != 0 {
		t.Fatalf("legacy log = %+v err=%v", logs, err)
	}
}

func TestFaultyStoreExecutionAttestationDelegates(t *testing.T) {
	m := newMemStore()
	f := &FaultyStore{Inner: m}
	rec := memAttestationRecord(3)
	if _, created, err := f.CommitExecutionAttestation(ctx(), rec, ExecutionAttestationEvent(rec)); err != nil || !created {
		t.Fatalf("faulty commit = %v/%v", created, err)
	}
	if _, found, err := f.GetExecutionAttestation(ctx(), rec.JobID, 3); err != nil || !found {
		t.Fatalf("faulty get = %v/%v", found, err)
	}
}

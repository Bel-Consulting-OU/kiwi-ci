package server

// Third coverage round: attempt-attestation error arms. All tests run over the
// shipped fakes and assert the exact returned error, HTTP status or persisted
// state.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// gapAttestStore augments dbFakeStore with per-method fault injection for the
// attempt-evidence and attestation-commit contracts.
type gapAttestStore struct {
	*dbFakeStore
	artsErr      error
	reportsErr   error
	snapsErr     error
	receiptErr   error
	commitErr    error
	fenceErr     error
	getAttErr    error
	commitCalled int
}

func (g *gapAttestStore) ListArtifactsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.ArtifactRecord, error) {
	if g.artsErr != nil {
		return nil, g.artsErr
	}
	return g.dbFakeStore.ListArtifactsByJobGeneration(ctx, jobID, generation)
}

func (g *gapAttestStore) ListTestReportsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.TestReport, error) {
	if g.reportsErr != nil {
		return nil, g.reportsErr
	}
	return g.dbFakeStore.ListTestReportsByJobGeneration(ctx, jobID, generation)
}

func (g *gapAttestStore) ListSnapshotsByJobGeneration(ctx context.Context, jobID string, generation int64) ([]model.SnapshotRecord, error) {
	if g.snapsErr != nil {
		return nil, g.snapsErr
	}
	return g.dbFakeStore.ListSnapshotsByJobGeneration(ctx, jobID, generation)
}

func (g *gapAttestStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	if g.receiptErr != nil {
		return model.CompletionReceipt{}, false, g.receiptErr
	}
	return g.dbFakeStore.HasCompletionReceipt(ctx, jobID, generation, runnerID)
}

func (g *gapAttestStore) CommitExecutionAttestation(ctx context.Context, rec model.ExecutionAttestationRecord, event model.ExecutionEvent) (model.ExecutionAttestationRecord, bool, error) {
	if g.commitErr != nil {
		return model.ExecutionAttestationRecord{}, false, g.commitErr
	}
	g.commitCalled++
	return g.dbFakeStore.CommitExecutionAttestation(ctx, rec, event)
}

func (g *gapAttestStore) GetExecutionAttestation(ctx context.Context, jobID string, generation int64) (model.ExecutionAttestationRecord, bool, error) {
	if g.getAttErr != nil {
		return model.ExecutionAttestationRecord{}, false, g.getAttErr
	}
	return g.dbFakeStore.GetExecutionAttestation(ctx, jobID, generation)
}

func (g *gapAttestStore) AcquireDigestFence(ctx context.Context, digest string) (func(), error) {
	if g.fenceErr != nil {
		return nil, g.fenceErr
	}
	return g.dbFakeStore.AcquireDigestFence(ctx, digest)
}

// gapNoAttemptIface exposes the base store surface plus SnapshotStore while
// hiding the optional attempt-scoped evidence contract.
type gapNoAttemptIface interface {
	storage.Store
	storage.SnapshotStore
}

type gapNoAttemptStore struct {
	gapNoAttemptIface
	artsErr    error
	reportsErr error
	snapsErr   error
	receiptErr error
}

func (g *gapNoAttemptStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
	if g.artsErr != nil {
		return nil, g.artsErr
	}
	return g.gapNoAttemptIface.ListArtifacts(ctx, runID)
}

func (g *gapNoAttemptStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
	if g.reportsErr != nil {
		return nil, g.reportsErr
	}
	return g.gapNoAttemptIface.ListTestReports(ctx, runID)
}

func (g *gapNoAttemptStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	if g.snapsErr != nil {
		return nil, g.snapsErr
	}
	return g.gapNoAttemptIface.ListSnapshotsByRun(ctx, runID)
}

func (g *gapNoAttemptStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	if g.receiptErr != nil {
		return model.CompletionReceipt{}, false, g.receiptErr
	}
	return g.gapNoAttemptIface.HasCompletionReceipt(ctx, jobID, generation, runnerID)
}

func TestGapAttestationEvidenceDBArms(t *testing.T) {
	ctx := context.Background()

	t.Run("jobNotFound", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &gapAttestStore{dbFakeStore: f}
		ev, ok, err := s.gatherAttestationEvidenceDB(context.Background(), "missing-job", 1)
		if err != nil || ok || ev.job.ID != "" {
			t.Fatalf("missing job evidence = %+v ok=%v err=%v; want empty,false,nil", ev, ok, err)
		}
	})

	t.Run("jobReadError", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, getJobErr: errors.New("job table down")}
		if _, _, err := s.gatherAttestationEvidenceDB(ctx, "job-a", 5); err == nil {
			t.Fatal("job read failure was swallowed")
		}
	})

	t.Run("runReadError", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run table down")}
		if _, _, err := s.gatherAttestationEvidenceDB(ctx, "job-a", 5); err == nil {
			t.Fatal("run read failure was swallowed")
		}
	})

	t.Run("attemptEvidenceErrors", func(t *testing.T) {
		cases := []struct {
			name  string
			alter func(*gapAttestStore)
		}{
			{"artifacts", func(g *gapAttestStore) { g.artsErr = errors.New("artifacts down") }},
			{"reports", func(g *gapAttestStore) { g.reportsErr = errors.New("reports down") }},
			{"snapshots", func(g *gapAttestStore) { g.snapsErr = errors.New("snapshots down") }},
		}
		for _, tc := range cases {
			s, f, _, _ := cacheFixture(t)
			g := &gapAttestStore{dbFakeStore: f}
			tc.alter(g)
			s.DB = g
			if _, _, err := s.gatherAttestationEvidenceDB(ctx, "job-a", 5); err == nil {
				t.Fatalf("%s read failure was swallowed", tc.name)
			}
		}
	})

	t.Run("fallbackListErrors", func(t *testing.T) {
		cases := []struct {
			name  string
			alter func(*gapNoAttemptStore)
		}{
			{"artifacts", func(g *gapNoAttemptStore) { g.artsErr = errors.New("artifacts down") }},
			{"reports", func(g *gapNoAttemptStore) { g.reportsErr = errors.New("reports down") }},
			{"snapshots", func(g *gapNoAttemptStore) { g.snapsErr = errors.New("snapshots down") }},
		}
		for _, tc := range cases {
			s, f, _, _ := cacheFixture(t)
			g := &gapNoAttemptStore{gapNoAttemptIface: f}
			tc.alter(g)
			s.DB = g
			if _, _, err := s.gatherAttestationEvidenceDB(ctx, "job-a", 5); err == nil {
				t.Fatalf("fallback %s read failure was swallowed", tc.name)
			}
		}
	})

	t.Run("receiptReadError", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		f.mu.Lock()
		j := f.jobs["job-a"]
		j.AttemptRunnerID = "runner-a"
		f.jobs["job-a"] = j
		f.mu.Unlock()
		s.DB = &gapAttestStore{dbFakeStore: f, receiptErr: errors.New("receipts down")}
		if _, _, err := s.gatherAttestationEvidenceDB(ctx, "job-a", 5); err == nil {
			t.Fatal("completion receipt read failure was swallowed")
		}
	})
}

func TestGapAttestationExecutionDBArms(t *testing.T) {
	ctx := context.Background()

	t.Run("emptyJobID", func(t *testing.T) {
		s := New("tok")
		if err := s.attestExecution(ctx, "", 1); err != nil {
			t.Fatalf("empty job id attestation = %v, want nil", err)
		}
	})

	t.Run("gatherFailure", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, getJobErr: errors.New("job table down")}
		if err := s.attestExecutionDB(ctx, "job-a", 5); err == nil {
			t.Fatal("gather failure was swallowed")
		}
	})

	t.Run("jobDisappeared", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &gapAttestStore{dbFakeStore: f}
		if err := s.attestExecutionDB(ctx, "missing-job", 5); err != nil {
			t.Fatalf("vanished job attestation = %v, want nil", err)
		}
	})

	t.Run("fenceFailure", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &gapAttestStore{dbFakeStore: f, fenceErr: errors.New("fence down")}
		if err := s.attestExecutionDB(ctx, "job-a", 5); err == nil {
			t.Fatal("digest fence failure was swallowed")
		}
	})

	t.Run("commitFailure", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		g := &gapAttestStore{dbFakeStore: f, commitErr: errors.New("attestation insert down")}
		s.DB = g
		if err := s.attestExecutionDB(ctx, "job-a", 5); err == nil {
			t.Fatal("attestation commit failure was swallowed")
		}
		if g.commitCalled != 0 {
			t.Fatal("commit seam was bypassed")
		}
	})

	t.Run("commitsOnce", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		g := &gapAttestStore{dbFakeStore: f}
		s.DB = g
		if err := s.attestExecutionDB(ctx, "job-a", 5); err != nil {
			t.Fatalf("attestation commit = %v", err)
		}
		if g.commitCalled != 1 {
			t.Fatalf("commit calls = %d, want 1", g.commitCalled)
		}
		// The second call replays the durable marker without a second commit.
		if err := s.attestExecution(ctx, "job-a", 5); err != nil {
			t.Fatalf("attestation replay = %v", err)
		}
		if g.commitCalled != 1 {
			t.Fatalf("replay commit calls = %d, want 1", g.commitCalled)
		}
	})
}

func TestGapAttestationLocalArms(t *testing.T) {
	ctx := context.Background()

	seedLocalJob := func(t *testing.T, s *Server) {
		t.Helper()
		s.mu.Lock()
		s.jobs["job-att"] = model.Job{ID: "job-att", RunID: "run-att", Key: "build", Status: model.StatusSuccess}
		s.mu.Unlock()
	}

	t.Run("missingJob", func(t *testing.T) {
		s, err := NewPersistent("runner", "admin", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.attestExecutionLocal(ctx, "no-job", 1); err != nil {
			t.Fatalf("missing local job attestation = %v, want nil", err)
		}
	})

	t.Run("replaySkipsWork", func(t *testing.T) {
		s, err := NewPersistent("runner", "admin", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		seedLocalJob(t, s)
		if err := s.attestExecutionLocal(ctx, "job-att", 1); err != nil {
			t.Fatalf("first local attestation = %v", err)
		}
		if err := s.attestExecutionLocal(ctx, "job-att", 1); err != nil {
			t.Fatalf("replayed local attestation = %v", err)
		}
		if _, found := s.attestations[model.AttemptID("job-att", 1)]; !found {
			t.Fatal("local attestation marker missing")
		}
	})

	t.Run("publishDirectoryFailure", func(t *testing.T) {
		root := t.TempDir()
		s, err := NewPersistent("runner", "admin", root)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(root+"/attestations", []byte("block"), 0o600); err != nil {
			t.Fatal(err)
		}
		seedLocalJob(t, s)
		if err := s.attestExecutionLocal(ctx, "job-att", 1); err == nil {
			t.Fatal("attestation publish with a blocked directory succeeded")
		}
	})

	t.Run("persistFailure", func(t *testing.T) {
		s, err := NewPersistent("runner", "admin", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		seedLocalJob(t, s)
		s.persistFailForTest = errors.New("injected persist failure")
		if err := s.attestExecutionLocal(ctx, "job-att", 1); err == nil {
			t.Fatal("attestation with a failing snapshot write succeeded")
		}
		s.mu.Lock()
		_, leaked := s.attestations[model.AttemptID("job-att", 1)]
		s.mu.Unlock()
		if leaked {
			t.Fatal("failed attestation marker leaked")
		}
	})
}

func TestGapAttestationReadArms(t *testing.T) {
	ctx := context.Background()

	t.Run("lookupError", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &gapAttestStore{dbFakeStore: f, getAttErr: errors.New("marker table down")}
		if _, _, err := s.lookupExecutionAttestation(ctx, "job-a", 5); err == nil {
			t.Fatal("marker read failure was swallowed")
		}
	})

	t.Run("jobLookupError", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, getJobErr: errors.New("job table down")}
		if _, err := s.jobForAttestation(ctx, "job-a"); err == nil {
			t.Fatal("jobForAttestation read failure was swallowed")
		}
	})

	t.Run("getHandlerErrors", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, getJobErr: errors.New("job table down")}
		if w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/job-a/attestation", "admin-tok", ""); w.Code != http.StatusInternalServerError {
			t.Fatalf("job lookup failure = %d, want 500", w.Code)
		}
		s.DB = &gapAttestStore{dbFakeStore: f, getAttErr: errors.New("marker table down")}
		if w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/job-a/attestation", "admin-tok", ""); w.Code != http.StatusInternalServerError {
			t.Fatalf("marker lookup failure = %d, want 500", w.Code)
		}
	})

	t.Run("readEnvelopeArms", func(t *testing.T) {
		s, _, _, _ := cacheFixture(t)
		if _, err := s.readExecutionAttestationEnvelope(ctx, model.ExecutionAttestationRecord{}); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("empty envelope ref = %v, want not-exist", err)
		}
		rec := model.ExecutionAttestationRecord{EnvelopeRef: "cas:deadbeef"}
		s.CAS = nil
		if _, err := s.readExecutionAttestationEnvelope(ctx, rec); err == nil {
			t.Fatal("cas envelope without CAS store was served")
		}
		s.SetBlobStore(newMemBlob())
		if _, err := s.readExecutionAttestationEnvelope(ctx, rec); err == nil {
			t.Fatal("missing cas envelope was served")
		}
		missing := model.ExecutionAttestationRecord{EnvelopeRef: t.TempDir() + "/nope.json"}
		if _, err := s.readExecutionAttestationEnvelope(ctx, missing); err == nil {
			t.Fatal("missing fs envelope was served")
		}
	})

	t.Run("readBounded", func(t *testing.T) {
		if _, err := readBounded(&gapErrReader{}, 10); err == nil {
			t.Fatal("failing reader was accepted")
		}
		if _, err := readBounded(strings.NewReader(strings.Repeat("x", 11)), 10); err == nil {
			t.Fatal("oversized envelope was accepted")
		}
		if b, err := readBounded(strings.NewReader("abc"), 10); err != nil || string(b) != "abc" {
			t.Fatalf("bounded read = %q, %v", b, err)
		}
	})
}

type gapErrReader struct{}

func (gapErrReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

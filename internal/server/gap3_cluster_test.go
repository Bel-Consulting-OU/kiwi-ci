package server

// Third coverage round, second server batch: snapshot upload commit arms,
// generated-envelope decoding, legacy execution-event retention reads, secret
// receipt journal parsing and derived test-history branches.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestGapBlobUploadNonCASCommitFailureRemovesFile(t *testing.T) {
	t.Run("jobLookup", func(t *testing.T) {
		s, f, _, hdrs, _ := cacheFixtureWithStaging(t, 1<<20)
		gapSeedRequiredContract(t, f)
		s.CAS = nil
		s.DB = &gapNthGetJobStore{dbFakeStore: f}
		if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusInternalServerError {
			t.Fatalf("non-cas job lookup failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})

	t.Run("leaseLive", func(t *testing.T) {
		s, f, _, hdrs, _ := cacheFixtureWithStaging(t, 1<<20)
		gapSeedRequiredContract(t, f)
		s.CAS = nil
		s.DB = &gapNthLiveStore{dbFakeStore: f}
		if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusInternalServerError {
			t.Fatalf("non-cas liveness failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})
}

func TestGapSnapshotMemoryCommitCapAndManifestArms(t *testing.T) {
	t.Run("commitTimeCap", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t, WithSnapshotMaxPerJob(1))
		reader := &fcHookReader{data: fcSnapshotArchive(t), hook: func() {
			s.mu.Lock()
			if s.snapshots == nil {
				s.snapshots = map[string]model.SnapshotRecord{}
			}
			s.snapshots["pre-existing"] = model.SnapshotRecord{ID: "pre-existing", RunID: "run-c", JobID: "job-a"}
			s.mu.Unlock()
		}}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", reader)
		r.Header.Set("Authorization", "Bearer runner-tok")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusConflict {
			t.Fatalf("commit-time snapshot cap = %d, want 409: %s", w.Code, w.Body.String())
		}
		dir := filepath.Join(s.store.Root, "snapshots", "run-c", "job-a")
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".tar.gz") {
					t.Fatalf("over-cap upload left archive %s", e.Name())
				}
			}
		}
	})

	t.Run("manifestAtomicWriteFailure", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		seamRand(t, seamFixedReader{})
		dir := filepath.Join(s.store.Root, "snapshots", "run-c", "job-a")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, strings.Repeat("0", 32)+".tar.gz.manifest.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", strings.NewReader(string(fcSnapshotArchive(t))))
		r.Header.Set("Authorization", "Bearer runner-tok")
		r.Header.Set("X-Kiwi-Request-ID", "gap-fixed-request")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("manifest write failure = %d, want 500: %s", w.Code, w.Body.String())
		}
		if _, err := os.Stat(filepath.Join(dir, strings.Repeat("0", 32)+".tar.gz")); !os.IsNotExist(err) {
			t.Fatalf("archive after manifest failure survived: %v", err)
		}
	})
}

func TestGapValidateSnapshotFilesManifestDecode(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "snap.tar.gz")
	body := []byte("archive-bytes")
	if err := os.WriteFile(archive, body, 0o600); err != nil {
		t.Fatal(err)
	}
	rec := model.SnapshotRecord{ID: "snap", Path: archive, Size: int64(len(body)), SHA256: sha256Hex(body)}
	if err := os.WriteFile(archive+".manifest.json", []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSnapshotFiles(rec); err == nil {
		t.Fatal("corrupt manifest sidecar was accepted")
	}
}

func TestGapParentGenerateEnvelopeArms(t *testing.T) {
	if env, err := parentGenerateEnvelope(model.Job{CompiledJobPayload: &model.CompiledJobPayload{}}); err != nil || env.Known {
		t.Fatalf("pre-schema payload = %+v, %v; want legacy fallback", env, err)
	}
	raw := []byte(`{"generate":{"max_jobs":3,"max_depth":2}}`)
	if env, err := parentGenerateEnvelope(model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: raw}}); err != nil || !env.Known || env.MaxJobs != 3 || env.MaxDepth != 2 {
		t.Fatalf("[]byte effective job = %+v, %v", env, err)
	}
	if _, err := parentGenerateEnvelope(model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: json.RawMessage{}}}); err == nil {
		t.Fatal("empty raw effective job was accepted")
	}
	restore := seamJSON(t)
	if _, err := parentGenerateEnvelope(model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: 42}}); !errors.Is(err, errSeamJSON) {
		t.Fatalf("undecodable effective job = %v, want encoder error", err)
	}
	restore()

	old := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return []byte{}, nil }
	_, err := parentGenerateEnvelope(model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: 42}})
	jsonMarshal = old
	if err == nil {
		t.Fatal("empty encoded effective job was accepted")
	}
}

func TestGapVerifyGeneratedFragmentGraphArms(t *testing.T) {
	parent := model.Job{ID: "p1"}
	deep := parent
	deep.DynamicDepth = 999
	if err := verifyGeneratedFragmentGraph(parent, deep, 1<<20, 0, 1); err == nil {
		t.Fatal("depth over the global cap was accepted")
	}
	badPolicy := model.Job{ID: "p1", CompiledJobPayload: &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: json.RawMessage(`{"generate":`)}}
	if err := verifyGeneratedFragmentGraph(parent, badPolicy, 1, 0, 1); err == nil {
		t.Fatal("malformed parent policy was accepted")
	}
	limited := model.Job{ID: "p1", CompiledJobPayload: &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: json.RawMessage(`{"generate":{"max_jobs":1}}`)}}
	if err := verifyGeneratedFragmentGraph(parent, limited, 1, 0, 2); err == nil {
		t.Fatal("child count over the parent limit was accepted")
	}
	if err := verifyGeneratedFragmentGraph(parent, model.Job{ID: "other"}, 1, 0, 1); err == nil {
		t.Fatal("changed parent identity was accepted")
	}
}

// gapLegacyEventStore serves the legacy split event contracts without the
// atomic retention read, so the fallback arms of readExecutionEventsRetention
// are reachable.
type gapLegacyEventStore struct {
	*eventsFakeStore
	retained    int64
	retainedErr error
	listErr     error
	latestErr   error
}

func (g *gapLegacyEventStore) ExecutionEventRetainedFrom(context.Context) (int64, error) {
	if g.retainedErr != nil {
		return 0, g.retainedErr
	}
	return g.retained, nil
}

func (g *gapLegacyEventStore) ListExecutionEvents(ctx context.Context, after int64, limit int, runID string) ([]model.ExecutionEvent, int64, error) {
	if g.listErr != nil {
		return nil, 0, g.listErr
	}
	return g.eventsFakeStore.ListExecutionEvents(ctx, after, limit, runID)
}

func (g *gapLegacyEventStore) LatestExecutionEventSeq(context.Context) (int64, error) {
	if g.latestErr != nil {
		return 0, g.latestErr
	}
	return 7, nil
}

type gapNoEventStore struct {
	storage.Store
}

func (g *gapNoEventStore) ExecutionEventRetainedFrom(context.Context) (int64, error) { return 4, nil }

func TestGapExecutionEventRetentionFallbackArms(t *testing.T) {
	ctx := context.Background()

	t.Run("noEventContract", func(t *testing.T) {
		s := New("tok")
		s.DB = &gapNoEventStore{Store: newDBFakeStore()}
		if _, _, _, _, err := s.readExecutionEventsRetention(ctx, 0, 10, ""); !errors.Is(err, errUnsupportedExecutionEvents) {
			t.Fatalf("missing event contract = %v, want errUnsupportedExecutionEvents", err)
		}
	})

	t.Run("listError", func(t *testing.T) {
		s := New("tok")
		s.DB = &gapLegacyEventStore{eventsFakeStore: &eventsFakeStore{dbFakeStore: newDBFakeStore()}, listErr: errors.New("page down")}
		if _, _, _, _, err := s.readExecutionEventsRetention(ctx, 0, 10, ""); err == nil {
			t.Fatal("list failure was swallowed")
		}
	})

	t.Run("latestError", func(t *testing.T) {
		s := New("tok")
		s.DB = &gapLegacyEventStore{eventsFakeStore: &eventsFakeStore{dbFakeStore: newDBFakeStore()}, latestErr: errors.New("cursor down")}
		if _, _, _, _, err := s.readExecutionEventsRetention(ctx, 0, 10, ""); err == nil {
			t.Fatal("latest cursor failure was swallowed")
		}
	})

	t.Run("splitContractSuccess", func(t *testing.T) {
		f := &eventsFakeStore{dbFakeStore: newDBFakeStore()}
		if err := f.AppendExecutionEvent(ctx, model.ExecutionEvent{Seq: 1, RunID: "run-1", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		s := New("tok")
		s.DB = &gapLegacyEventStore{eventsFakeStore: f, retained: 1}
		events, cursor, retained, latest, err := s.readExecutionEventsRetention(ctx, 0, 10, "")
		if err != nil || len(events) != 1 || cursor != 1 || retained != 0 || latest != 7 {
			t.Fatalf("split-contract retention read = %d events cursor=%d retained=%d latest=%d err=%v", len(events), cursor, retained, latest, err)
		}
	})

	t.Run("retentionStoreProbe", func(t *testing.T) {
		s := New("tok")
		if _, ok := s.executionEventRetentionStore(); ok {
			t.Fatal("memory server reported a retention store")
		}
		s.DB = &gapNoEventStore{Store: newDBFakeStore()}
		if _, ok := s.executionEventRetentionStore(); ok {
			t.Fatal("store without the retention contract reported support")
		}
		s.DB = &eventsRetentionFakeStore{eventsFakeStore: &eventsFakeStore{dbFakeStore: newDBFakeStore()}}
		if _, ok := s.executionEventRetentionStore(); !ok {
			t.Fatal("retention contract was not detected")
		}
	})
}

func TestGapSecretReceiptJournalArms(t *testing.T) {
	if _, _, ok := parseSecretReceiptKey("no-separator"); ok {
		t.Fatal("key without a separator was accepted")
	}
	if _, _, ok := parseSecretReceiptKey("job|notanumber|name"); ok {
		t.Fatal("key with a non-numeric generation was accepted")
	}
	if jobID, gen, ok := parseSecretReceiptKey("job|7|name"); !ok || jobID != "job" || gen != 7 {
		t.Fatalf("valid key = %q,%d,%v", jobID, gen, ok)
	}

	t.Run("blankFileIsEmpty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, secretReceiptsFile), []byte("  \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New("tok")
		if err := s.loadSecretReceipts(dir); err != nil || len(s.secretReceipts) != 0 {
			t.Fatalf("blank receipt journal = %d receipts, %v", len(s.secretReceipts), err)
		}
	})

	t.Run("corruptJournalFailsClosed", func(t *testing.T) {
		dir := t.TempDir()
		journal := filepath.Join(dir, secretReceiptsFile)
		if err := os.WriteFile(journal, []byte("{not json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New("tok")
		if err := s.loadSecretReceipts(dir); err == nil {
			t.Fatal("corrupt receipt journal was accepted")
		}
	})

	t.Run("persistAtomicWriteFailure", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, secretReceiptsFile), 0o700); err != nil {
			t.Fatal(err)
		}
		s := New("tok")
		s.dataDir = dir
		s.secretReceipts = map[string]secretReceipt{"job|1|name": {}}
		s.mu.Lock()
		err := s.persistSecretReceiptsLocked()
		s.mu.Unlock()
		if err == nil {
			t.Fatal("atomic receipt write over a directory succeeded")
		}
	})
}

// gapNoAggStore hides the aggregate history contract while keeping the base
// store surface, so recordTestReportHistory takes the legacy convergence path.
type gapNoAggStore struct {
	storage.Store
}

func TestGapTestHistoryDerivedArms(t *testing.T) {
	t.Run("mirrorEmptyRepo", func(t *testing.T) {
		s := New("tok")
		s.mirrorTestReportHistoryDB("")
		if _, hit := s.historyCache.lookup(""); hit {
			t.Fatal("empty repository key was mirrored")
		}
	})

	t.Run("derivedHistoryDBMode", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.mu.Lock()
		_ = s.ensureDerivedHistoryLocked()
		s.mu.Unlock()
		_ = f
	})

	t.Run("derivedHistorySkipsUnattributable", func(t *testing.T) {
		s, err := NewPersistent("runner", "admin", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.reports = map[string]model.TestReport{
			"orphan":  {ID: "orphan", RunID: "no-such-run", CreatedAt: time.Now().UTC()},
			"norepo":  {ID: "norepo", RunID: "run-empty", CreatedAt: time.Now().UTC()},
			"tracked": {ID: "tracked", RunID: "run-ok", CreatedAt: time.Now().UTC()},
		}
		s.runs["run-empty"] = model.Run{ID: "run-empty", Status: model.StatusRunning}
		s.runs["run-ok"] = model.Run{ID: "run-ok", RepoID: "github.com/o/r", Status: model.StatusRunning}
		entry := s.ensureDerivedHistoryLocked()
		s.mu.Unlock()
		if _, folded := entry.foldedReports["orphan"]; folded {
			t.Fatal("report without a run was folded")
		}
		if _, folded := entry.foldedReports["norepo"]; folded {
			t.Fatal("report without a repository was folded")
		}
		if _, folded := entry.foldedReports["tracked"]; !folded {
			t.Fatal("attributable report was not folded")
		}
	})

	t.Run("legacyRecordPath", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &gapNoAggStore{Store: f}
		s.mu.Lock()
		s.recordTestReportHistory(context.Background(), "github.com/o/r", model.TestReport{ID: "rep-1", RunID: "run-c"})
		s.mu.Unlock()
	})

	t.Run("aggregateListFailure", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, listHistoryRepoIDsErr: errors.New("repo ids down")}
		s.rebuildTestHistoryDB(context.Background())
	})

	t.Run("historyFromStatsRejectsGarbage", func(t *testing.T) {
		if _, err := historyFromStats([]byte("{not json")); err == nil {
			t.Fatal("garbage history stats were accepted")
		}
	})
}

// TestGapRestoreGeneratedFragmentsLocked drives the fs-mode receipt
// restoration validation: missing parents/children are dropped, and a
// pre-slot duplicate history deterministically keeps the newest digest.
func TestGapRestoreGeneratedFragmentsLocked(t *testing.T) {
	s := New("tok")
	s.jobs["parent"] = model.Job{ID: "parent"}
	s.jobs["child"] = model.Job{ID: "child"}
	if s.generatedFragments == nil {
		s.generatedFragments = map[string]storage.GeneratedFragmentReceipt{}
	}
	in := map[string]storage.GeneratedFragmentReceipt{
		"no-parent":     {FragmentID: "f", Children: []storage.GeneratedFragmentChild{{ID: "child"}}},
		"no-job":        {ParentJobID: "missing", FragmentID: "f", Children: []storage.GeneratedFragmentChild{{ID: "child"}}},
		"no-children":   {ParentJobID: "parent", FragmentID: "f"},
		"empty-child":   {ParentJobID: "parent", FragmentID: "f", Children: []storage.GeneratedFragmentChild{{ID: ""}}},
		"missing-child": {ParentJobID: "parent", FragmentID: "f", Children: []storage.GeneratedFragmentChild{{ID: "ghost"}}},
		"valid":         {ParentJobID: "parent", FragmentID: "f", Children: []storage.GeneratedFragmentChild{{Key: "k", ID: "child"}}},
	}
	s.restoreGeneratedFragmentsLocked(in)
	key := generatedFragmentKey("parent", storage.GeneratedFragmentSlot(""))
	if got := s.generatedFragments[key]; got.FragmentID != "f" {
		t.Fatalf("restored receipt = %+v, want the valid fragment", got)
	}
	if len(s.generatedFragments) != 1 {
		t.Fatalf("restored %d receipts, want 1 (invalid snapshots dropped)", len(s.generatedFragments))
	}

	now := time.Now().UTC()
	s.generatedFragments[key] = storage.GeneratedFragmentReceipt{ParentJobID: "parent", FragmentID: "newer", CreatedAt: now.Add(time.Hour), Children: []storage.GeneratedFragmentChild{{Key: "k", ID: "child"}}}
	older := map[string]storage.GeneratedFragmentReceipt{
		"dup": {ParentJobID: "parent", FragmentID: "older", CreatedAt: now, Children: []storage.GeneratedFragmentChild{{Key: "k", ID: "child"}}},
	}
	s.restoreGeneratedFragmentsLocked(older)
	if got := s.generatedFragments[key]; got.FragmentID != "newer" {
		t.Fatalf("older duplicate replaced the newer receipt: %+v", got)
	}
	newest := map[string]storage.GeneratedFragmentReceipt{
		"dup2": {ParentJobID: "parent", FragmentID: "newest", CreatedAt: now.Add(2 * time.Hour), Children: []storage.GeneratedFragmentChild{{Key: "k", ID: "child"}}},
	}
	s.restoreGeneratedFragmentsLocked(newest)
	if got := s.generatedFragments[key]; got.FragmentID != "newest" {
		t.Fatalf("newer duplicate did not replace the older receipt: %+v", got)
	}
}

// gapIntelStore injects failures into the aggregate test-history query path.
type gapIntelStore struct {
	*dbFakeStore
	resolveErr error
	totalsErr  error
	flakyErr   error
}

func (g *gapIntelStore) ResolveTestHistoryRepoIDs(ctx context.Context, query string, limit int) ([]string, error) {
	if g.resolveErr != nil {
		return nil, g.resolveErr
	}
	return g.dbFakeStore.ResolveTestHistoryRepoIDs(ctx, query, limit)
}

func (g *gapIntelStore) TestReportTotals(ctx context.Context, repoIDs []string, repoQuery string) (int, int, int, error) {
	if g.totalsErr != nil {
		return 0, 0, 0, g.totalsErr
	}
	return g.dbFakeStore.TestReportTotals(ctx, repoIDs, repoQuery)
}

func (g *gapIntelStore) FlakyTestNames(ctx context.Context, repoIDs []string, limit int) ([]string, error) {
	if g.flakyErr != nil {
		return nil, g.flakyErr
	}
	return g.dbFakeStore.FlakyTestNames(ctx, repoIDs, limit)
}

// TestGapTestIntelligenceAggregateArms covers the ambiguity refusal and the
// totals/flaky read failures on the incremental test-intelligence path.
func TestGapTestIntelligenceAggregateArms(t *testing.T) {
	t.Run("ambiguousRepoQuery", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, resolveRepoIDsErr: storage.ErrRepoQueryAmbiguous}
		w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "admin-tok", "")
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "ambiguous") {
			t.Fatalf("ambiguous repo query = %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("totalsFailure", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &gapIntelStore{dbFakeStore: f, totalsErr: errors.New("totals down")}
		w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "admin-tok", "")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("totals failure = %d, want 500", w.Code)
		}
	})

	t.Run("flakyFailure", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		s.DB = &gapIntelStore{dbFakeStore: f, flakyErr: errors.New("flaky down")}
		w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "admin-tok", "")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("flaky failure = %d, want 500", w.Code)
		}
	})
}

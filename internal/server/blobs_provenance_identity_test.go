package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// artifactIdentityFixture wires the DB-mode cacheFixture with the full run
// identity (repository/ref/commit) the signed provenance statement must
// carry, plus the declared "bin" contract.
func artifactIdentityFixture(t *testing.T) (*Server, *dbFakeStore, *memBlob, map[string]string) {
	t.Helper()
	s, f, mb, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.runs["run-c"] = model.Run{
		ID: "run-c", RepoID: "github.com/o/repo-a", Repo: "https://github.com/o/repo-a.git",
		RepoFullName: "o/repo-a", Ref: "refs/heads/main", SHA: "abc123", Status: model.StatusRunning,
	}
	f.mu.Unlock()
	return s, f, mb, hdrs
}

// assertNoArtifactCommitted proves an upload that failed identity resolution
// staged nothing: no artifact row, no CAS blob (payload, provenance or
// sidecar) and no local staging/provenance file under the job directory.
func assertNoArtifactCommitted(t *testing.T, s *Server, f *dbFakeStore, mb *memBlob, runID, jobID string) {
	t.Helper()
	f.mu.Lock()
	rows := len(f.artifacts)
	f.mu.Unlock()
	if rows != 0 {
		t.Fatalf("artifact rows = %d, want 0: upload proceeded without authoritative identity", rows)
	}
	mb.mu.Lock()
	objects := len(mb.objects)
	mb.mu.Unlock()
	if objects != 0 {
		t.Fatalf("CAS objects = %d, want 0: blob/provenance bytes were written", objects)
	}
	entries, err := os.ReadDir(filepath.Join(s.store.Root, "artifacts", runID, jobID))
	if err == nil && len(entries) != 0 {
		t.Fatalf("staged files = %v, want none", entries)
	}
}

func TestArtifactUploadGetRunErrorFailsClosed(t *testing.T) {
	s, f, mb, hdrs := artifactIdentityFixture(t)
	fault := errors.New("run table down")
	s.DB = &fcStore{dbFakeStore: f, getRunErr: fault}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload with failing GetRun = %d, want 503: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), fault.Error()) {
		t.Fatalf("response body leaks the raw store error: %s", w.Body.String())
	}
	assertNoArtifactCommitted(t, s, f, mb, "run-c", "job-a")
}

func TestArtifactUploadRunNotFoundFailsClosed(t *testing.T) {
	s, f, mb, hdrs := artifactIdentityFixture(t)
	f.mu.Lock()
	delete(f.runs, "run-c")
	f.mu.Unlock()
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload with missing run = %d, want 503: %s", w.Code, w.Body.String())
	}
	assertNoArtifactCommitted(t, s, f, mb, "run-c", "job-a")
}

func TestArtifactUploadMemoryRunMissingFailsClosed(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	fcSeedContract(s, "job-a", fcBinContract())
	s.mu.Lock()
	delete(s.runs, "run-c")
	s.mu.Unlock()
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("memory upload with missing run = %d, want 503: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	rows := len(s.artifacts)
	s.mu.Unlock()
	if rows != 0 {
		t.Fatalf("memory artifact rows = %d, want 0: upload proceeded without authoritative identity", rows)
	}
	entries, err := os.ReadDir(filepath.Join(s.store.Root, "artifacts", "run-c", "job-a"))
	if err == nil && len(entries) != 0 {
		t.Fatalf("staged files = %v, want none", entries)
	}
}

// provenanceStatementForUpload extracts and signature-verifies the DSSE
// statement an artifact upload published, returning the decoded statement
// and its signed payload bytes.
func provenanceStatementForUpload(t *testing.T, s *Server, rec model.ArtifactRecord) (provenance.Statement, []byte) {
	t.Helper()
	if !strings.HasPrefix(rec.ProvenancePath, "cas:") || rec.ProvenanceSHA256 == "" {
		t.Fatalf("provenance refs = %q/%q, want cas: digest", rec.ProvenancePath, rec.ProvenanceSHA256)
	}
	rc, _, err := s.CAS.Open(context.Background(), rec.ProvenanceSHA256)
	if err != nil {
		t.Fatalf("provenance not in CAS: %v", err)
	}
	envBytes, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	var env provenance.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatal(err)
	}
	if err := provenance.Verify(env, s.provenance.Public); err != nil {
		t.Fatalf("provenance verify: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var st provenance.Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	return st, payload
}

func TestArtifactUploadProvenanceCarriesFullIdentity(t *testing.T) {
	s, f, _, hdrs := artifactIdentityFixture(t)
	started := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	compiled := &model.CompiledJobPayload{
		SchemaVersion:   3,
		CompilerVersion: "kiwi-compiler/1.2.3",
		PipelineDigest:  strings.Repeat("a", 64),
		JobDigest:       strings.Repeat("b", 64),
		EffectiveJob:    map[string]any{"name": "build", "steps": []any{map[string]any{"run": "make"}}},
		EffectivePolicy: map[string]any{"oidc": false, "network": map[string]any{"allow": true, "hosts": []any{"a", "b"}}},
	}
	f.mu.Lock()
	j := f.jobs["job-a"]
	j.StartedAt = &started
	j.CompiledJobPayload = compiled
	f.jobs["job-a"] = j
	f.mu.Unlock()

	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d, want 201: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	st, payloadBytes := provenanceStatementForUpload(t, s, rec)
	want := map[string]string{
		"repository": "github.com/o/repo-a",
		"ref":        "refs/heads/main",
		"commit":     "abc123",
		"job":        "build",
	}
	params := st.Predicate.BuildDefinition.ExternalParameters
	for k, v := range want {
		if got, _ := params[k].(string); got != v {
			t.Fatalf("provenance %s = %q, want %q", k, got, v)
		}
	}
	if len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] != rec.SHA256 {
		t.Fatalf("provenance subject = %+v, want artifact digest %s", st.Subject, rec.SHA256)
	}
	// The invocation string carries the canonical attempt ID, and the
	// dedicated field lets consumers match it without parsing.
	if got := st.Predicate.RunDetails.Metadata.InvocationID; got != "run-c/job-a:5" {
		t.Fatalf("provenance invocationId = %q, want run-c/job-a:5", got)
	}
	if st.AttemptID != "job-a:5" {
		t.Fatalf("provenance attemptId = %q, want job-a:5", st.AttemptID)
	}
	wantCapsule, err := provenance.CapsuleDigest(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if st.CapsuleDigest == "" || st.CapsuleDigest != wantCapsule {
		t.Fatalf("provenance capsuleDigest = %q, want %q", st.CapsuleDigest, wantCapsule)
	}
	// The digest is deterministic over the persisted payload.
	again, err := provenance.CapsuleDigest(compiled)
	if err != nil || again != st.CapsuleDigest {
		t.Fatalf("capsule digest unstable: %q vs %q (%v)", st.CapsuleDigest, again, err)
	}
	if st.PipelineDigest != compiled.PipelineDigest || st.CompilerVersion != compiled.CompilerVersion {
		t.Fatalf("pipeline identity = %q/%q, want %q/%q", st.PipelineDigest, st.CompilerVersion, compiled.PipelineDigest, compiled.CompilerVersion)
	}
	policyJSON, err := json.Marshal(compiled.EffectivePolicy)
	if err != nil {
		t.Fatal(err)
	}
	policySum := sha256.Sum256(policyJSON)
	if st.EffectivePolicyDigest != hex.EncodeToString(policySum[:]) {
		t.Fatalf("effectivePolicyDigest = %q, want %s", st.EffectivePolicyDigest, hex.EncodeToString(policySum[:]))
	}
	if st.RunnerIdentity != "runner-a" {
		t.Fatalf("runnerIdentity = %q, want runner-a", st.RunnerIdentity)
	}
	if st.ArtifactSize != int64(len("payload")) {
		t.Fatalf("artifactSize = %d, want %d", st.ArtifactSize, len("payload"))
	}
	if st.StartTime == nil || !st.StartTime.Equal(started) {
		t.Fatalf("startTime = %v, want %v", st.StartTime, started)
	}
	// The job is still running: no completion claim, only publication time.
	if st.Predicate.RunDetails.Metadata.FinishedOn != nil {
		t.Fatalf("running job statement claimed finishedOn %v", st.Predicate.RunDetails.Metadata.FinishedOn)
	}
	if strings.Contains(string(payloadBytes), "finishedOn") {
		t.Fatalf("signed payload contains finishedOn for a running job: %s", payloadBytes)
	}
	if st.ArtifactPublishedAt == nil {
		t.Fatal("artifactPublishedAt missing from statement")
	}
}

// TestArtifactProvenanceWithoutCapsulePayloadStillUploads proves the explicit
// degraded binding: a job without a persisted CompiledJobPayload still
// uploads (201) and the statement simply omits the capsule/pipeline fields
// instead of fabricating evidence.
func TestArtifactProvenanceWithoutCapsulePayloadStillUploads(t *testing.T) {
	s, _, _, hdrs := artifactIdentityFixture(t)
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusCreated {
		t.Fatalf("upload without compiled payload = %d, want 201: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	st, payloadBytes := provenanceStatementForUpload(t, s, rec)
	if st.CapsuleDigest != "" || st.PipelineDigest != "" || st.CompilerVersion != "" || st.EffectivePolicyDigest != "" {
		t.Fatalf("capsule fields fabricated without a payload: %q/%q/%q/%q", st.CapsuleDigest, st.PipelineDigest, st.CompilerVersion, st.EffectivePolicyDigest)
	}
	if strings.Contains(string(payloadBytes), "capsuleDigest") {
		t.Fatalf("signed payload carries capsuleDigest without a payload: %s", payloadBytes)
	}
	// The rest of the identity is still bound.
	if st.AttemptID != "job-a:5" || st.Predicate.RunDetails.Metadata.InvocationID != "run-c/job-a:5" {
		t.Fatalf("attempt identity lost: %q / %q", st.AttemptID, st.Predicate.RunDetails.Metadata.InvocationID)
	}
}

// TestArtifactProvenanceNeverClaimsFinishedBeforeTerminal proves artifact
// publication records its own timestamp and only claims build completion when
// the job carries a real terminal timestamp.
func TestArtifactProvenanceNeverClaimsFinishedBeforeTerminal(t *testing.T) {
	t.Run("running job omits finishedOn", func(t *testing.T) {
		s, _, _, hdrs := artifactIdentityFixture(t)
		w := fcUploadBlobArtifact(t, s, hdrs, "payload")
		if w.Code != http.StatusCreated {
			t.Fatalf("upload = %d, want 201: %s", w.Code, w.Body.String())
		}
		var rec model.ArtifactRecord
		if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		st, payloadBytes := provenanceStatementForUpload(t, s, rec)
		if st.Predicate.RunDetails.Metadata.FinishedOn != nil {
			t.Fatalf("running job statement claimed finishedOn %v", st.Predicate.RunDetails.Metadata.FinishedOn)
		}
		if strings.Contains(string(payloadBytes), "finishedOn") {
			t.Fatalf("signed payload carries finishedOn for a running job: %s", payloadBytes)
		}
		if st.ArtifactPublishedAt == nil {
			t.Fatal("artifactPublishedAt missing")
		}
		if since := time.Since(*st.ArtifactPublishedAt); since < 0 || since > time.Minute {
			t.Fatalf("artifactPublishedAt = %v, want upload time", *st.ArtifactPublishedAt)
		}
	})

	t.Run("terminal job records its real finishedAt", func(t *testing.T) {
		s, f, _, hdrs := artifactIdentityFixture(t)
		finished := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		f.mu.Lock()
		j := f.jobs["job-a"]
		j.FinishedAt = &finished
		f.jobs["job-a"] = j
		f.mu.Unlock()

		w := fcUploadBlobArtifact(t, s, hdrs, "payload")
		if w.Code != http.StatusCreated {
			t.Fatalf("upload = %d, want 201: %s", w.Code, w.Body.String())
		}
		var rec model.ArtifactRecord
		if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		st, _ := provenanceStatementForUpload(t, s, rec)
		got := st.Predicate.RunDetails.Metadata.FinishedOn
		if got == nil || !got.Equal(finished) {
			t.Fatalf("finishedOn = %v, want the real terminal %v (never upload time)", got, finished)
		}
		if st.ArtifactPublishedAt == nil || st.ArtifactPublishedAt.Equal(finished) {
			t.Fatalf("artifactPublishedAt = %v, want a separate publication timestamp", st.ArtifactPublishedAt)
		}
	})
}

// fenceRecorder wraps a cas.Fencer and tracks which digests are currently
// held, so a test can assert the reachability invariant "every CAS object is
// fenced from publish through durable reference" for each digest.
type fenceRecorder struct {
	inner cas.Fencer
	mu    sync.Mutex
	held  map[string]int
}

func newFenceRecorder() *fenceRecorder {
	return &fenceRecorder{inner: cas.NewMemFencer(), held: map[string]int{}}
}

func (f *fenceRecorder) Acquire(ctx context.Context, digest string) (func(), error) {
	release, err := f.inner.Acquire(ctx, digest)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.held[digest]++
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			f.held[digest]--
			f.mu.Unlock()
			release()
		})
	}, nil
}

func (f *fenceRecorder) WithFence(ctx context.Context, digest string, fn func() error) error {
	release, err := f.Acquire(ctx, digest)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

func (f *fenceRecorder) holds(digest string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held[digest] > 0
}

// fenceAuditedBlob records, per CAS Put key, whether that key's digest fence
// was held at the moment of the Put: an unfenced publication is exactly the
// defect the fencing contract forbids.
type fenceAuditedBlob struct {
	blob.Store
	fencer *fenceRecorder
	mu     sync.Mutex
	order  []string
	fenced map[string]bool
}

func (b *fenceAuditedBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	b.mu.Lock()
	if b.fenced == nil {
		b.fenced = map[string]bool{}
	}
	b.fenced[key] = b.fencer.holds(key)
	b.order = append(b.order, key)
	b.mu.Unlock()
	return b.Store.Put(ctx, key, r, size)
}

// fenceAuditedStore records whether the durable artifact insert committed
// while the record's digests were still fenced.
type fenceAuditedStore struct {
	*dbFakeStore
	fencer   *fenceRecorder
	mu       sync.Mutex
	unfenced []string
}

func (st *fenceAuditedStore) InsertArtifactOnce(ctx context.Context, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	st.mu.Lock()
	for _, d := range []string{a.SHA256, a.ProvenanceSHA256} {
		if d != "" && !st.fencer.holds(d) {
			st.unfenced = append(st.unfenced, d)
		}
	}
	st.mu.Unlock()
	return st.dbFakeStore.InsertArtifactOnce(ctx, a)
}

// TestArtifactUploadFencesProvenanceDigest is the C4-C fence regression: the
// provenance envelope's CAS.Put acquires the provenance digest's fence (the
// payload digest fence alone covers only the payload), both fences are held
// through the durable artifact insert, the publication order is payload
// first then provenance, and every fence is released when the handler
// returns. A CAS.Put observed without its own digest fence fails the test.
func TestArtifactUploadFencesProvenanceDigest(t *testing.T) {
	s, f, mb, hdrs := artifactIdentityFixture(t)
	recorder := newFenceRecorder()
	// The DB-mode fake now carries the distributed capability, so the
	// observability seam is the store's fencer override (not s.digestFence,
	// which DB mode no longer falls back to).
	f.digestFenceOverride = recorder
	audit := &fenceAuditedBlob{Store: mb, fencer: recorder}
	s.SetBlobStore(audit)
	store := &fenceAuditedStore{dbFakeStore: f, fencer: recorder}
	s.DB = store

	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d, want 201: %s", w.Code, w.Body.String())
	}
	var out model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ProvenanceSHA256 == "" || out.ProvenancePath != "cas:"+out.ProvenanceSHA256 {
		t.Fatalf("provenance references = %q/%q, want a cas: digest", out.ProvenancePath, out.ProvenanceSHA256)
	}
	audit.mu.Lock()
	order := append([]string(nil), audit.order...)
	fenced := make(map[string]bool, len(audit.fenced))
	for k, v := range audit.fenced {
		fenced[k] = v
	}
	audit.mu.Unlock()
	if len(order) != 2 || order[0] != out.SHA256 || order[1] != out.ProvenanceSHA256 {
		t.Fatalf("CAS publication order = %v, want payload %s then provenance %s", order, out.SHA256, out.ProvenanceSHA256)
	}
	for _, digest := range order {
		if !fenced[digest] {
			t.Fatalf("CAS.Put for %s ran with no fence held for that digest", digest)
		}
	}
	store.mu.Lock()
	unfenced := append([]string(nil), store.unfenced...)
	store.mu.Unlock()
	if len(unfenced) != 0 {
		t.Fatalf("artifact record committed with unfenced digest(s): %v", unfenced)
	}
	for _, digest := range order {
		if recorder.holds(digest) {
			t.Fatalf("digest fence for %s still held after the upload returned", digest)
		}
	}
}

// fenceBlockingProvenance delegates to inner for one allowed digest and
// blocks every other acquisition until the context ends, simulating a
// saturated DB-mode advisory pool that cannot grant the second fence.
type fenceBlockingProvenance struct {
	inner cas.Fencer
	allow string
}

func (f *fenceBlockingProvenance) Acquire(ctx context.Context, digest string) (func(), error) {
	if digest != f.allow {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.inner.Acquire(ctx, digest)
}

func (f *fenceBlockingProvenance) WithFence(ctx context.Context, digest string, fn func() error) error {
	release, err := f.Acquire(ctx, digest)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

// TestArtifactUploadProvenanceFenceTimeoutSkipsUnfencedPut proves the second
// fence is BOUNDED: when the provenance digest's fence cannot be acquired
// (a saturated advisory pool), the envelope is not published at all — no
// unfenced CAS.Put — and the payload upload still succeeds with its own
// fence held through the commit and released afterwards.
func TestArtifactUploadProvenanceFenceTimeoutSkipsUnfencedPut(t *testing.T) {
	old := provenanceFenceTimeout
	provenanceFenceTimeout = 20 * time.Millisecond
	defer func() { provenanceFenceTimeout = old }()

	s, f, mb, hdrs := artifactIdentityFixture(t)
	payloadDigest := sha256Hex([]byte("payload"))
	recorder := newFenceRecorder()
	// DB mode uses the store's fence (the fake's override), never the local
	// server fencer: install the blocking fencer on the store.
	f.digestFenceOverride = &fenceBlockingProvenance{inner: recorder, allow: payloadDigest}
	audit := &fenceAuditedBlob{Store: mb, fencer: recorder}
	s.SetBlobStore(audit)

	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusCreated {
		t.Fatalf("upload with unavailable provenance fence = %d, want 201: %s", w.Code, w.Body.String())
	}
	var out model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ProvenanceSHA256 != "" || out.ProvenancePath != "" {
		t.Fatalf("provenance published without its fence: %q/%q", out.ProvenancePath, out.ProvenanceSHA256)
	}
	audit.mu.Lock()
	order := append([]string(nil), audit.order...)
	fenced := audit.fenced[payloadDigest]
	audit.mu.Unlock()
	if len(order) != 1 || order[0] != payloadDigest || !fenced {
		t.Fatalf("CAS puts = %v (payload fenced=%v), want only fenced payload %s", order, fenced, payloadDigest)
	}
	if recorder.holds(payloadDigest) {
		t.Fatalf("payload fence still held after the upload returned")
	}
}

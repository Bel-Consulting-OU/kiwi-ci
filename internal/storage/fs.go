package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// CompletionReceiptRecord pairs a completion receipt with the time it was
// recorded. The timestamp lets a restarted control plane prune receipts past
// the retention window and bound the restored set to the newest entries; a
// receipt itself carries no wall-clock field (the key is the idempotency
// identity: job + lease generation + runner).
type CompletionReceiptRecord struct {
	Receipt   model.CompletionReceipt `json:"receipt"`
	CreatedAt time.Time               `json:"created_at"`
}

// Completion receipt retention: a persisted receipt is honored for
// CompletionReceiptTTL after it was recorded, and a restart restores at most
// MaxCompletionReceipts entries (the newest by CreatedAt). Both keep the
// durable receipt set bounded without changing the idempotency identity.
const (
	CompletionReceiptTTL  = 7 * 24 * time.Hour
	MaxCompletionReceipts = 10_000
)

// Snapshot is the durable control-plane state. The filesystem implementation is
// intentionally boring: one atomically replaced JSON snapshot plus append-only
// log/audit files. It keeps Kiwi single-binary and dependency-free while making
// crashes recoverable. A SQL store can implement the same Repository contract.
type Snapshot struct {
	Version   int                             `json:"version"`
	Runs      map[string]model.Run            `json:"runs"`
	Jobs      map[string]model.Job            `json:"jobs"`
	Runners   map[string]model.Runner         `json:"runners"`
	Artifacts map[string]model.ArtifactRecord `json:"artifacts,omitempty"`
	Reports   map[string]model.TestReport     `json:"reports,omitempty"`
	// DownstreamLinks persists the fs-mode downstream dispatch claims
	// (downstream_links equivalents) so a restarted control plane cannot
	// launch the same child run twice. Additive; older snapshots load with
	// a nil map.
	DownstreamLinks map[string]DownstreamLink `json:"downstream_links,omitempty"`
	// Profiles persists the fs-mode server-owned runner profiles and their
	// certificate-serial bindings (runner_profiles/cert_profile_links
	// equivalents). Additive; older snapshots load with nil maps.
	Profiles         map[string]model.RunnerProfile `json:"profiles,omitempty"`
	CertProfileLinks map[string]string              `json:"cert_profile_links,omitempty"`
	// Snapshots persists the fs-mode uploaded workspace snapshot records
	// (workspace_snapshots equivalents) so the archives written under the
	// data dir stay addressable across restarts instead of becoming
	// unreferenced orphans. Additive; older snapshots load with a nil map.
	// The server validates every referenced archive/manifest pair at load
	// and drops records whose files no longer match.
	Snapshots map[string]model.SnapshotRecord `json:"snapshots,omitempty"`
	// CompletionReceipts persists the fs-mode completion idempotency
	// receipts (the completion_receipts equivalents) so a restarted control
	// plane answers a replayed completion from the durable receipt instead
	// of re-applying effects. Additive; older snapshots load with a nil
	// slice. The server prunes entries past CompletionReceiptTTL and caps
	// the restored set at MaxCompletionReceipts newest.
	CompletionReceipts []CompletionReceiptRecord `json:"completion_receipts,omitempty"`
	// Deployments persists the fs-mode deployment records (the deployments
	// equivalents) so a restarted control plane keeps the environment
	// lifecycle it acknowledged (docs/environments.md:67). Additive; older
	// snapshots load with a nil map, which the server treats as empty.
	Deployments map[string]model.Deployment `json:"deployments,omitempty"`
	// CRL persists the fs-mode runner certificate revocation list (serial ->
	// runner ID) in the SAME atomic snapshot write as the runner disable, so
	// a crash can never durably disable a runner without also revoking its
	// certificate. Additive; older snapshots load with a nil map and the
	// legacy runner-crl.json file is merged in by the server.
	CRL map[string]string `json:"crl,omitempty"`
	// PendingSidecars persists the fs-mode pending SBOM/Sigstore pointers
	// (the artifact_pending_sidecars equivalents) so a restarted control
	// plane resolves the exact digest that was accepted before the restart
	// instead of guessing between the generation directory's candidate
	// files. Additive; older snapshots load with a nil slice, and exactly
	// one unambiguous on-disk file per identity remains resolvable as
	// legacy state (multiple candidates with no pointer fail closed).
	// See pending_sidecar_snapshot.go.
	PendingSidecars []PendingSidecarPointer `json:"pending_sidecars,omitempty"`
}

type Repository struct {
	Root string
	mu   sync.Mutex
	// legacyLogBatchesChecked marks the one-time in-place migration of the
	// pre-per-run flat committed layout (logbatches/committed/<key>.json)
	// into logbatches/committed/<runID>/<key>.json. Guarded by mu.
	legacyLogBatchesChecked bool

	// Log-batch sequence watermark state. All fields are guarded by mu.
	//
	// logBatchMaxSeq is the in-memory authoritative high-water mark of the
	// committed batches; every publish raises it before its rename, so the
	// running process never allocates a sequence at or below a durable one.
	// logBatchMaxSeqPersisted is the value last written to the checkpoint
	// file; it may lag logBatchMaxSeq between checkpoint flushes and is only
	// ever recovered by the one-time load scan (see
	// initLogBatchMaxSeqLocked). loaded=false means the watermark has not
	// been initialized from disk yet.
	logBatchMaxSeq          int64
	logBatchMaxSeqPersisted int64
	logBatchMaxSeqLoaded    bool
	// logBatchPublishes counts publishes that advanced the in-memory
	// watermark since the last durable checkpoint write.
	logBatchPublishes int
	// logBatchCheckpointWrites counts durable checkpoint writes (a test
	// seam for the amortization tests; never read by production code).
	logBatchCheckpointWrites int
	// checkpointEvery/checkpointDelta override the package checkpoint
	// thresholds when positive; tests set them to exercise the triggers with
	// small stores. Zero means the package default.
	checkpointEvery int
	checkpointDelta int64
}

func New(root string) *Repository { return &Repository{Root: root} }

func (r *Repository) Load() (Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadLocked()
}

func (r *Repository) loadLocked() (Snapshot, error) {
	s := Snapshot{Version: 1, Runs: map[string]model.Run{}, Jobs: map[string]model.Job{}, Runners: map[string]model.Runner{}, Artifacts: map[string]model.ArtifactRecord{}, Reports: map[string]model.TestReport{}, Deployments: map[string]model.Deployment{}}
	// Reconcile interrupted fs log batches before exposing any state: a
	// journal written by a crashed append is either republished or dropped
	// when its batch already committed. A partially written batch is never
	// visible because only the atomically published committed record is read.
	if err := r.recoverLogBatchesLocked(); err != nil {
		return s, err
	}
	// Load is the opportunistic checkpoint point required by the crash-lost
	// recovery contract: initialize the in-memory watermark from the durable
	// checkpoint plus the one-time scan of committed records and pending
	// journals, and persist the corrected value if the scan advanced it. A
	// restart after a crash that lost the checkpoint tail therefore heals the
	// checkpoint immediately, and this process's later MaxLogSeq calls are
	// O(1) reads of the in-memory watermark.
	if _, err := r.initLogBatchMaxSeqLocked(); err != nil {
		return s, err
	}
	b, err := os.ReadFile(filepath.Join(r.Root, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("decode state: %w", err)
	}
	if s.Runs == nil {
		s.Runs = map[string]model.Run{}
	}
	if s.Jobs == nil {
		s.Jobs = map[string]model.Job{}
	}
	if s.Runners == nil {
		s.Runners = map[string]model.Runner{}
	}
	if s.Artifacts == nil {
		s.Artifacts = map[string]model.ArtifactRecord{}
	}
	if s.Reports == nil {
		s.Reports = map[string]model.TestReport{}
	}
	if s.DownstreamLinks == nil {
		s.DownstreamLinks = map[string]DownstreamLink{}
	}
	if s.Profiles == nil {
		s.Profiles = map[string]model.RunnerProfile{}
	}
	if s.CertProfileLinks == nil {
		s.CertProfileLinks = map[string]string{}
	}
	if s.Snapshots == nil {
		s.Snapshots = map[string]model.SnapshotRecord{}
	}
	if s.Deployments == nil {
		s.Deployments = map[string]model.Deployment{}
	}
	if s.CRL == nil {
		s.CRL = map[string]string{}
	}
	return s, nil
}

func (r *Repository) Save(s Snapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(r.Root, 0o700); err != nil {
		return err
	}
	s.Version = 1
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// AtomicWriteFile checks the temp file's Sync/Close errors and fsyncs
	// the parent directory after the rename: a state snapshot is only
	// reported written when it is durable, and a crash can never leave a
	// truncated or half-renamed state.json.
	return AtomicWriteFile(filepath.Join(r.Root, "state.json"), b, 0o600)
}

func (r *Repository) AppendLog(e model.LogEntry) error {
	return r.appendJSONL("logs.jsonl", e)
}
func (r *Repository) AppendAudit(e model.AuditEvent) error {
	return r.appendJSONL("audit.jsonl", e)
}
func (r *Repository) appendJSONL(name string, v any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(r.Root, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(r.Root, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return f.Sync()
}

// logBatchRecord is one fs log-batch journal/commit record. The record is
// written to the pending directory with AtomicWriteFile and atomically
// PUBLISHED by renaming it into the committed directory of its run, so the
// batch's lines become durable all at once: a reader only ever unions
// committed records, and a read for one run never opens another run's files.
// RunID makes the record self-describing; records written before the per-run
// layout carry it only inside Entries (see recordRunID).
type logBatchRecord struct {
	RunID    string           `json:"run_id,omitempty"`
	Identity LogBatchIdentity `json:"identity"`
	Digest   string           `json:"digest"`
	Entries  []model.LogEntry `json:"entries"`
}

// logBatchKey derives the filesystem-safe key of one batch identity.
func logBatchKey(identity LogBatchIdentity) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("kiwi-log-batch-key\x00%s\x00%d\x00%s", identity.JobID, identity.Generation, identity.BatchID)))
	return hex.EncodeToString(sum[:])
}

func (r *Repository) logBatchPendingDir() string {
	return filepath.Join(r.Root, "logbatches", "pending")
}

// logBatchCommittedDir is the committed-batch ROOT. Records live one level
// deeper, under their run's directory (see logBatchRunDir), so
// ReadLogs(runID) only opens that run's files instead of decoding every
// batch in the store on every poll.
func (r *Repository) logBatchCommittedDir() string {
	return filepath.Join(r.Root, "logbatches", "committed")
}

// logBatchRunDir returns the committed directory of one run. Run ids are
// server-generated, but they still cross a filesystem boundary, so unsafe ids
// are rejected fail-closed instead of escaping the store root.
func (r *Repository) logBatchRunDir(runID string) (string, error) {
	if err := validateLogBatchRunID(runID); err != nil {
		return "", err
	}
	return filepath.Join(r.logBatchCommittedDir(), runID), nil
}

// Durable max-seq checkpoint amortization. The checkpoint (logBatchMaxSeqPath)
// only has to be a monotone lower bound of the true high-water mark that is
// never behind the records after a load scan. It is therefore written at most
// once per defaultCheckpointEvery publishes that advanced the watermark, or as
// soon as the in-memory watermark has advanced defaultCheckpointDelta beyond
// the persisted value, whichever comes first. Between writes the in-memory
// watermark stays authoritative, and a crash loses at most the unflushed tail,
// which initLogBatchMaxSeqLocked reconstructs from the committed run
// directories and pending journals.
const (
	defaultCheckpointEvery = 32
	defaultCheckpointDelta = 4096
)

// logBatchMaxSeqPath is the durable max-seq checkpoint of the committed
// batches: a monotone non-decreasing lower bound of the true high-water mark.
// The in-memory watermark is raised BEFORE each publish rename (see
// publishLogBatchLocked); the durable file is flushed from it on the
// amortized checkpoint schedule and opportunistically on load and prune. A
// crash can therefore leave the checkpoint behind the records, never ahead of
// them in a way that matters, and a load never trusts it alone: the one-time
// scan in initLogBatchMaxSeqLocked takes the maximum of the checkpoint and
// every committed/pending record, so a sequence is never reused after a
// restart even when the checkpoint lost the most recent advances.
func (r *Repository) logBatchMaxSeqPath() string {
	return filepath.Join(r.Root, "logbatches", "maxseq")
}

// validateLogBatchRunID rejects run ids that would escape the run's
// directory. Empty ids are rejected too: every batch belongs to exactly one
// run, and ReadLogs/PruneLogBatches address runs by id.
func validateLogBatchRunID(runID string) error {
	if runID == "" {
		return errors.New("storage: log batch requires a run id")
	}
	if runID == "." || runID == ".." || strings.ContainsAny(runID, `/\`) {
		return fmt.Errorf("storage: unsafe log batch run id %q", runID)
	}
	return nil
}

// logBatchRunID returns the single run a batch belongs to: every entry must
// carry the same non-empty run id, so a batch can never straddle run
// directories (fail closed rather than guessing).
func logBatchRunID(entries []model.LogEntry) (string, error) {
	if len(entries) == 0 {
		return "", errors.New("storage: empty log batch")
	}
	runID := entries[0].RunID
	if err := validateLogBatchRunID(runID); err != nil {
		return "", err
	}
	for _, e := range entries[1:] {
		if e.RunID != runID {
			return "", fmt.Errorf("storage: log batch mixes runs %q and %q", runID, e.RunID)
		}
	}
	return runID, nil
}

// recordRunID resolves the run of a stored record: the persisted RunID when
// present, otherwise the run of its entries (records written before the
// per-run layout did not carry the field).
func recordRunID(rec logBatchRecord) (string, error) {
	if rec.RunID != "" {
		if err := validateLogBatchRunID(rec.RunID); err != nil {
			return "", err
		}
		return rec.RunID, nil
	}
	return logBatchRunID(rec.Entries)
}

// logBatchMaxSeq returns the highest Seq in a batch's entries.
func logBatchMaxSeq(entries []model.LogEntry) int64 {
	var maxSeq int64
	for _, e := range entries {
		if e.Seq > maxSeq {
			maxSeq = e.Seq
		}
	}
	return maxSeq
}

// readLogBatchRecord decodes one journal/commit record. ok=false means the
// file does not exist; a decode failure is a hard error (fail closed: a
// corrupt durable record must not be silently ignored).
func readLogBatchRecord(path string) (logBatchRecord, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return logBatchRecord{}, false, nil
	}
	if err != nil {
		return logBatchRecord{}, false, err
	}
	var rec logBatchRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return logBatchRecord{}, false, fmt.Errorf("storage: decode log batch record %s: %w", path, err)
	}
	if rec.Digest == "" || rec.Identity.JobID == "" || rec.Identity.BatchID == "" {
		return logBatchRecord{}, false, fmt.Errorf("storage: log batch record %s is incomplete", path)
	}
	if rec.RunID != "" {
		if err := validateLogBatchRunID(rec.RunID); err != nil {
			return logBatchRecord{}, false, fmt.Errorf("storage: log batch record %s: %w", path, err)
		}
		if len(rec.Entries) > 0 && rec.Entries[0].RunID != "" && rec.Entries[0].RunID != rec.RunID {
			return logBatchRecord{}, false, fmt.Errorf("storage: log batch record %s run id %q does not match its entries", path, rec.RunID)
		}
	}
	return rec, true, nil
}

// publishLogBatchLocked atomically publishes a complete pending journal: the
// rename into the run's committed directory is the commit point and the
// directory fsyncs make it durable. The in-memory max-seq watermark is raised
// BEFORE the rename (bumpLogBatchMaxSeqLocked), so no sequence this process
// has published can be handed out again, and a checkpoint flush inside that
// bump also happens before the rename: a crash between a flush and the rename
// leaves the checkpoint ahead of the records, which only skips sequence
// values (safe for a monotone sequence). The opposite crash - rename
// committed but the amortized checkpoint not yet flushed - leaves the
// checkpoint behind the records, which the next load repairs by scanning the
// committed run directories and pending journals
// (initLogBatchMaxSeqLocked). A failure after the rename leaves the committed
// record visible, which the retry recognizes as an idempotent success; a
// failure before it leaves the pending journal, which the retry republishes.
func (r *Repository) publishLogBatchLocked(pendingPath, key string, rec logBatchRecord) error {
	runID, err := recordRunID(rec)
	if err != nil {
		return err
	}
	root := r.logBatchCommittedDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	dir := filepath.Join(root, runID)
	created := false
	switch err := os.Mkdir(dir, 0o700); {
	case err == nil:
		created = true
	case !errors.Is(err, os.ErrExist):
		return err
	}
	if err := r.bumpLogBatchMaxSeqLocked(logBatchMaxSeq(rec.Entries)); err != nil {
		return err
	}
	if err := os.Rename(pendingPath, filepath.Join(dir, key+".json")); err != nil {
		return err
	}
	if err := SyncDir(dir); err != nil {
		return err
	}
	if created {
		return SyncDir(root)
	}
	return nil
}

// migrateLegacyLogBatchesLocked moves committed records written by the
// pre-per-run flat layout (logbatches/committed/<key>.json) into their run's
// directory. It runs at most once per Repository instance and is resumable: a
// crash mid-migration leaves the not-yet-moved files in the flat root and the
// next process finishes the move. The in-memory max-seq watermark is raised
// before the first move (bumpLogBatchMaxSeqLocked), and the load scan that
// initializes it covers both the flat root and the per-run directories, so an
// interruption can never leave the watermark - in memory or in the
// checkpoint - behind a published record, even though the checkpoint is now
// written lazily rather than on every move.
func (r *Repository) migrateLegacyLogBatchesLocked() error {
	if r.legacyLogBatchesChecked {
		return nil
	}
	root := r.logBatchCommittedDir()
	ents, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		r.legacyLogBatchesChecked = true
		return nil
	}
	if err != nil {
		return err
	}
	type legacyBatch struct {
		name string
		rec  logBatchRecord
	}
	var legacy []legacyBatch
	var maxSeq int64
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		rec, ok, err := readLogBatchRecord(filepath.Join(root, ent.Name()))
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		legacy = append(legacy, legacyBatch{name: ent.Name(), rec: rec})
		if v := logBatchMaxSeq(rec.Entries); v > maxSeq {
			maxSeq = v
		}
	}
	if len(legacy) == 0 {
		r.legacyLogBatchesChecked = true
		return nil
	}
	if err := r.bumpLogBatchMaxSeqLocked(maxSeq); err != nil {
		return err
	}
	for _, l := range legacy {
		runID, err := recordRunID(l.rec)
		if err != nil {
			return err
		}
		dir := filepath.Join(root, runID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(root, l.name), filepath.Join(dir, l.name)); err != nil {
			return err
		}
	}
	if err := SyncDir(root); err != nil {
		return err
	}
	r.legacyLogBatchesChecked = true
	return nil
}

// recoverLogBatchesLocked reconciles interrupted appends. It first migrates
// the legacy flat layout, then republishes a pending journal whose batch
// never committed (its entries were staged atomically, so it is complete) and
// drops one whose batch already committed. Recovery never duplicates lines
// because pending entries are not readable through ReadLogs until published.
func (r *Repository) recoverLogBatchesLocked() error {
	if err := r.migrateLegacyLogBatchesLocked(); err != nil {
		return err
	}
	pendingDir := r.logBatchPendingDir()
	entries, err := os.ReadDir(pendingDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		key := strings.TrimSuffix(ent.Name(), ".json")
		pendingPath := filepath.Join(pendingDir, ent.Name())
		rec, ok, err := readLogBatchRecord(pendingPath)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		runID, err := recordRunID(rec)
		if err != nil {
			return err
		}
		committedPath := filepath.Join(r.logBatchCommittedDir(), runID, ent.Name())
		if _, serr := os.Stat(committedPath); serr == nil {
			if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		} else if !errors.Is(serr, os.ErrNotExist) {
			return serr
		}
		if err := r.publishLogBatchLocked(pendingPath, key, rec); err != nil {
			return err
		}
	}
	return nil
}

// AppendLogBatch durably appends one whole batch under its identity:
//
//  1. the same identity with the same payload digest is an idempotent no-op
//     (nothing is written again);
//  2. a different payload digest returns ErrLogBatchConflict and writes
//     nothing;
//  3. otherwise the complete batch is staged in a pending journal with one
//     AtomicWriteFile (fsync + rename + dir fsync), then atomically published
//     by renaming the journal into the committed directory of its run.
//     Readers only ever see committed records, so an interrupted append is
//     never exposed as durable and recovery replays the complete journal.
//     The max-seq checkpoint is NOT written per publish: the in-memory
//     watermark is raised by the publish and flushed on the amortized
//     schedule (see bumpLogBatchMaxSeqLocked), so the steady-state cost of a
//     publish is the journal write plus the rename, not a second full
//     AtomicWriteFile.
func (r *Repository) AppendLogBatch(identity LogBatchIdentity, entries []model.LogEntry) error {
	if identity.JobID == "" || identity.BatchID == "" {
		return fmt.Errorf("storage: log batch requires job id and batch id")
	}
	if len(entries) == 0 {
		return fmt.Errorf("storage: empty log batch")
	}
	runID, err := logBatchRunID(entries)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.recoverLogBatchesLocked(); err != nil {
		return err
	}
	key := logBatchKey(identity)
	name := key + ".json"
	digest := LogBatchPayloadDigest(identity, entries)
	if rec, ok, err := readLogBatchRecord(filepath.Join(r.logBatchCommittedDir(), runID, name)); err != nil {
		return err
	} else if ok {
		if rec.Digest == digest {
			return nil
		}
		return ErrLogBatchConflict
	}
	pendingPath := filepath.Join(r.logBatchPendingDir(), name)
	if rec, ok, err := readLogBatchRecord(pendingPath); err != nil {
		return err
	} else if ok {
		// A previous attempt staged this exact payload but did not publish:
		// republish it instead of writing a second journal.
		if rec.Digest != digest {
			return ErrLogBatchConflict
		}
		return r.publishLogBatchLocked(pendingPath, key, rec)
	}
	rec := logBatchRecord{RunID: runID, Identity: identity, Digest: digest, Entries: entries}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := AtomicWriteFile(pendingPath, b, 0o600); err != nil {
		return err
	}
	return r.publishLogBatchLocked(pendingPath, key, rec)
}

// committedLogBatchEntriesLocked returns the committed batch lines of runID
// with Seq > after, in committed-file (ReadDir) order. Only that run's
// directory is listed and decoded, so the cost is bounded by the run's own
// batches, not by the whole store's history.
func (r *Repository) committedLogBatchEntriesLocked(runID string, after int64) ([]model.LogEntry, error) {
	dir, err := r.logBatchRunDir(runID)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []model.LogEntry
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		rec, ok, err := readLogBatchRecord(filepath.Join(dir, ent.Name()))
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		for _, e := range rec.Entries {
			if e.RunID == runID && e.Seq > after {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// ReadLogs merges the single-line JSONL stream with the committed batch
// records and orders the union by Seq (batch publication is out-of-band, so
// physical file order alone is not the log order). The limit trims the tail,
// matching readJSONL's keep-the-newest behavior.
func (r *Repository) ReadLogs(runID string, after int64, limit int) ([]model.LogEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.recoverLogBatchesLocked(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	out, err := readJSONL[model.LogEntry](filepath.Join(r.Root, "logs.jsonl"), limit, func(e model.LogEntry) bool { return e.RunID == runID && e.Seq > after })
	if err != nil {
		return nil, err
	}
	batched, err := r.committedLogBatchEntriesLocked(runID, after)
	if err != nil {
		return nil, err
	}
	out = append(out, batched...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}
func (r *Repository) ReadAudit(limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	return readJSONL[model.AuditEvent](filepath.Join(r.Root, "audit.jsonl"), limit, func(model.AuditEvent) bool { return true })
}
func readJSONL[T any](path string, limit int, keep func(T) bool) ([]T, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	out := make([]T, 0)
	for {
		var v T
		if err := dec.Decode(&v); err != nil {
			if jsonlStreamFinished(err) {
				return out, nil
			}
			return out, err
		}
		if keep(v) {
			out = append(out, v)
			if len(out) > limit {
				out = out[len(out)-limit:]
			}
		}
	}
}

// jsonlStreamFinished reports whether a JSON-lines decode error means the
// stream ended cleanly (EOF or an already-closed file) rather than a
// malformed record. Both cases are the normal end of a log file.
func jsonlStreamFinished(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF)
}

// MaxLogSeq returns the highest durable log sequence so a restarted control
// plane can continue the monotonic stream without reusing cursor values. Both
// the single-line JSONL stream and the committed batch records participate:
// batch lines are durable log entries too. The committed batches contribute
// through the in-memory watermark, which is initialized once from the durable
// checkpoint plus the load scan and raised before every publish rename, so
// this is O(1) plus the existing JSONL scan instead of decoding every batch
// in the store. A missing checkpoint (fresh store, manual deletion, or a
// crash before its very first write) is re-persisted here from the
// authoritative in-memory value, so the amortized checkpoint can never lag
// silently; a checkpoint that is merely behind is left for the scheduled
// flush, because the in-memory value already answers this call.
func (r *Repository) MaxLogSeq() (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.recoverLogBatchesLocked(); err != nil {
		return 0, err
	}
	maxSeq, err := r.maxLogSeqJSONL()
	if err != nil {
		return 0, err
	}
	batched, err := r.initLogBatchMaxSeqLocked()
	if err != nil {
		return 0, err
	}
	if _, ok, err := r.readMaxLogSeqIndexLocked(); err != nil {
		return 0, err
	} else if !ok {
		if err := r.flushLogBatchMaxSeqLocked(); err != nil {
			return 0, err
		}
	}
	if batched > maxSeq {
		maxSeq = batched
	}
	return maxSeq, nil
}

// readMaxLogSeqIndexLocked reads the durable max-seq checkpoint. ok=false
// means the file is absent, which is not an error.
func (r *Repository) readMaxLogSeqIndexLocked() (int64, bool, error) {
	b, err := os.ReadFile(r.logBatchMaxSeqPath())
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("storage: decode log batch max seq: %w", err)
	}
	if v < 0 {
		return 0, false, fmt.Errorf("storage: log batch max seq is negative: %d", v)
	}
	return v, true, nil
}

// writeMaxLogSeqIndexLocked durably persists the max-seq checkpoint.
func (r *Repository) writeMaxLogSeqIndexLocked(v int64) error {
	return AtomicWriteFile(r.logBatchMaxSeqPath(), []byte(strconv.FormatInt(v, 10)+"\n"), 0o600)
}

// initLogBatchMaxSeqLocked initializes the in-memory max-seq watermark once
// per Repository instance and returns it. The value is the maximum of:
//
//   - the durable checkpoint, and
//   - the highest Seq discovered by scanLogBatchMaxSeqLocked over the
//     committed per-run directories, legacy flat records and pending
//     journals.
//
// The scan is the recovery path for a crash between a publish and the next
// amortized checkpoint flush: the checkpoint may be behind the records, and
// only the listing knows the true value. It is bounded by the store's batch
// count and runs exactly once per process; afterwards the in-memory watermark
// is authoritative and every later call is O(1). When the scan or a missing
// checkpoint puts a value ahead of the persisted one, the corrected value is
// persisted immediately - the load-time opportunistic checkpoint - so a later
// restart already finds the recovered value on disk (it still scans
// defensively and would reconstruct it again if not).
func (r *Repository) initLogBatchMaxSeqLocked() (int64, error) {
	if r.logBatchMaxSeqLoaded {
		return r.logBatchMaxSeq, nil
	}
	persisted, _, err := r.readMaxLogSeqIndexLocked()
	if err != nil {
		return 0, err
	}
	scanned, err := r.scanLogBatchMaxSeqLocked()
	if err != nil {
		return 0, err
	}
	r.logBatchMaxSeq = persisted
	if scanned > r.logBatchMaxSeq {
		r.logBatchMaxSeq = scanned
	}
	r.logBatchMaxSeqPersisted = persisted
	r.logBatchMaxSeqLoaded = true
	// Only write when the scan or a missing checkpoint produced something to
	// record: an empty store is left without a logbatches/ directory (Load
	// stays write-free), while a recovered advance is persisted so a later
	// restart already finds it.
	if r.logBatchMaxSeq > persisted {
		if err := r.flushLogBatchMaxSeqLocked(); err != nil {
			return 0, err
		}
	}
	return r.logBatchMaxSeq, nil
}

// checkpointPublishInterval returns how many advancing publishes may pass
// before the durable checkpoint must be flushed (the instance override in
// tests, otherwise the package default).
func (r *Repository) checkpointPublishInterval() int {
	if r.checkpointEvery > 0 {
		return r.checkpointEvery
	}
	return defaultCheckpointEvery
}

// checkpointSeqDelta returns the sequence advance beyond the persisted value
// that forces an immediate checkpoint flush, bounding the checkpoint lag even
// when few, large batches are published (the instance override in tests,
// otherwise the package default).
func (r *Repository) checkpointSeqDelta() int64 {
	if r.checkpointDelta > 0 {
		return r.checkpointDelta
	}
	return defaultCheckpointDelta
}

// flushLogBatchMaxSeqLocked durably writes the in-memory watermark and resets
// the amortization counters. Callers hold mu. The write is fail-closed: a
// publish whose checkpoint flush fails does not reach its rename, so the
// batch is not committed and the retry republishes the pending journal.
func (r *Repository) flushLogBatchMaxSeqLocked() error {
	if err := r.writeMaxLogSeqIndexLocked(r.logBatchMaxSeq); err != nil {
		return err
	}
	r.logBatchMaxSeqPersisted = r.logBatchMaxSeq
	r.logBatchPublishes = 0
	r.logBatchCheckpointWrites++
	return nil
}

// bumpLogBatchMaxSeqLocked raises the in-memory watermark to at least
// batchMax and flushes the durable checkpoint on the amortized schedule:
// every checkpointPublishInterval publishes that advanced the watermark, or
// as soon as the watermark is checkpointSeqDelta ahead of the persisted
// value. Initializing on the first bump makes the one-time scan happen before
// any allocation can regress; a missing checkpoint is also (re)created by
// that init. Between flushes a publish costs no checkpoint I/O, which is the
// point of the amortization: the durable checkpoint may lag, but the
// in-memory watermark (authoritative for this process) never does, and the
// load scan repairs the file after a crash.
func (r *Repository) bumpLogBatchMaxSeqLocked(batchMax int64) error {
	if batchMax <= 0 {
		return nil
	}
	if _, err := r.initLogBatchMaxSeqLocked(); err != nil {
		return err
	}
	if batchMax > r.logBatchMaxSeq {
		r.logBatchMaxSeq = batchMax
		r.logBatchPublishes++
	}
	if r.logBatchMaxSeq <= r.logBatchMaxSeqPersisted {
		return nil
	}
	if r.logBatchPublishes >= r.checkpointPublishInterval() ||
		r.logBatchMaxSeq-r.logBatchMaxSeqPersisted >= r.checkpointSeqDelta() {
		return r.flushLogBatchMaxSeqLocked()
	}
	return nil
}

// scanLogBatchMaxSeqLocked is the one-time O(batches) load scan: it decodes
// the committed records of every run directory (and any legacy flat record
// migration has not moved yet) plus the pending journals and returns the
// highest Seq. Pending journals participate because a crash can leave a
// staged batch whose sequences were already allocated; including them means
// the "never reuse a sequence across restart" guarantee does not depend on
// recovery having republished them first. A corrupt record is a hard error
// (fail closed), exactly like every other durable-record decode.
func (r *Repository) scanLogBatchMaxSeqLocked() (int64, error) {
	var maxSeq int64
	scan := func(dir string, files []os.DirEntry) error {
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			rec, ok, err := readLogBatchRecord(filepath.Join(dir, f.Name()))
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if v := logBatchMaxSeq(rec.Entries); v > maxSeq {
				maxSeq = v
			}
		}
		return nil
	}
	root := r.logBatchCommittedDir()
	ents, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	for _, ent := range ents {
		if !ent.IsDir() {
			// Legacy flat committed record.
			if err := scan(root, []os.DirEntry{ent}); err != nil {
				return 0, err
			}
			continue
		}
		runDir := filepath.Join(root, ent.Name())
		files, err := os.ReadDir(runDir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if err := scan(runDir, files); err != nil {
			return 0, err
		}
	}
	pending := r.logBatchPendingDir()
	files, err := os.ReadDir(pending)
	if errors.Is(err, os.ErrNotExist) {
		return maxSeq, nil
	}
	if err != nil {
		return 0, err
	}
	if err := scan(pending, files); err != nil {
		return 0, err
	}
	return maxSeq, nil
}

// PruneLogBatches removes every durable log-batch record of one run.
//
// Retention contract: the caller invokes it only for a run the retention
// policy already considers dead - the fs Repository itself does not know run
// lifecycle, so it never decides when a run is prunable. The server calls it
// from the maintenance sweep for TERMINAL runs finished before its retention
// window (see server.logBatchRetention); logs of active or recently finished
// runs must never be pruned because their stream can still be read. The
// single-line logs.jsonl stream is not part of this contract: it has no
// per-run layout and is left untouched.
//
// The prune is idempotent and multi-call safe: removing an already-absent run
// directory is a no-op. Crash safety comes from record granularity and the
// absence of a per-record index: files are removed whole, so a crash
// mid-remove leaves either a complete record or nothing (never a partial
// record), the next prune finishes the removal, and the only index (the
// global max-seq checkpoint) is deliberately NOT lowered, so it can never
// dangle after its records are gone. Interrupted pending journals are first
// republished into the run directory by recovery and then removed with it, so
// a prune cannot be undone by a later restart replaying a journal for the
// same run.
//
// Prune is also an opportunistic checkpoint point: the store is already doing
// maintenance I/O, so the in-memory watermark (which recovery may just have
// raised) is flushed if it is ahead of the durable checkpoint. This bounds the
// next load scan's recovery gap but is not required for correctness - the
// scan would rediscover the same value.
func (r *Repository) PruneLogBatches(runID string) error {
	dir, err := r.logBatchRunDir(runID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.recoverLogBatchesLocked(); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if _, err := r.initLogBatchMaxSeqLocked(); err != nil {
		return err
	}
	if r.logBatchMaxSeq > r.logBatchMaxSeqPersisted {
		return r.flushLogBatchMaxSeqLocked()
	}
	return nil
}

// maxLogSeqJSONL returns the highest Seq in the single-line log stream.
func (r *Repository) maxLogSeqJSONL() (int64, error) {
	f, err := os.Open(filepath.Join(r.Root, "logs.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var maxSeq int64
	for {
		var e model.LogEntry
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return maxSeq, nil
			}
			return 0, err
		}
		if e.Seq > maxSeq {
			maxSeq = e.Seq
		}
	}
}

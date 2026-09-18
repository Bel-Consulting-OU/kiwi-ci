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
}

type Repository struct {
	Root string
	mu   sync.Mutex
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
// PUBLISHED by renaming it into the committed directory, so the batch's lines
// become durable all at once: a reader only ever unions committed records.
type logBatchRecord struct {
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

func (r *Repository) logBatchCommittedDir() string {
	return filepath.Join(r.Root, "logbatches", "committed")
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
	return rec, true, nil
}

// publishLogBatchLocked atomically publishes a complete pending journal: the
// rename is the commit point and the directory fsync makes it durable. A
// failure after the rename leaves the committed record visible, which the
// retry recognizes as an idempotent success.
func (r *Repository) publishLogBatchLocked(pendingPath, key string) error {
	dir := r.logBatchCommittedDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Rename(pendingPath, filepath.Join(dir, key+".json")); err != nil {
		return err
	}
	return SyncDir(dir)
}

// recoverLogBatchesLocked reconciles interrupted appends. A pending journal
// whose batch never committed is republished (its entries were staged
// atomically, so it is complete); one whose batch already committed is
// dropped. Recovery never duplicates lines because pending entries are not
// readable through ReadLogs until published.
func (r *Repository) recoverLogBatchesLocked() error {
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
		committedPath := filepath.Join(r.logBatchCommittedDir(), ent.Name())
		if _, serr := os.Stat(committedPath); serr == nil {
			if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		} else if !errors.Is(serr, os.ErrNotExist) {
			return serr
		}
		if _, ok, err := readLogBatchRecord(pendingPath); err != nil {
			return err
		} else if !ok {
			continue
		}
		if err := r.publishLogBatchLocked(pendingPath, key); err != nil {
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
//     by renaming the journal into the committed directory. Readers only ever
//     see committed records, so an interrupted append is never exposed as
//     durable and recovery replays the complete journal.
func (r *Repository) AppendLogBatch(identity LogBatchIdentity, entries []model.LogEntry) error {
	if identity.JobID == "" || identity.BatchID == "" {
		return fmt.Errorf("storage: log batch requires job id and batch id")
	}
	if len(entries) == 0 {
		return fmt.Errorf("storage: empty log batch")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.recoverLogBatchesLocked(); err != nil {
		return err
	}
	key := logBatchKey(identity)
	name := key + ".json"
	digest := LogBatchPayloadDigest(identity, entries)
	if rec, ok, err := readLogBatchRecord(filepath.Join(r.logBatchCommittedDir(), name)); err != nil {
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
		return r.publishLogBatchLocked(pendingPath, key)
	}
	b, err := json.Marshal(logBatchRecord{Identity: identity, Digest: digest, Entries: entries})
	if err != nil {
		return err
	}
	if err := AtomicWriteFile(pendingPath, b, 0o600); err != nil {
		return err
	}
	return r.publishLogBatchLocked(pendingPath, key)
}

// committedLogBatchEntriesLocked returns the committed batch lines of runID
// with Seq > after, in committed-file (ReadDir) order.
func (r *Repository) committedLogBatchEntriesLocked(runID string, after int64) ([]model.LogEntry, error) {
	dir := r.logBatchCommittedDir()
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
// batch lines are durable log entries too.
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
	dir := r.logBatchCommittedDir()
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return maxSeq, nil
	}
	if err != nil {
		return 0, err
	}
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		rec, ok, err := readLogBatchRecord(filepath.Join(dir, ent.Name()))
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		for _, e := range rec.Entries {
			if e.Seq > maxSeq {
				maxSeq = e.Seq
			}
		}
	}
	return maxSeq, nil
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

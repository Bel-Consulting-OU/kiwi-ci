package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Durable per-job log batch journal.
//
// The in-memory spool and the batch sequence are process-local: a runner
// that restarts mid-batch under the same lease would re-drain the same lines
// under different boundaries (a different batch identity) and the control
// plane's (job, generation, batch_id) receipt could not dedupe them, and
// lines drained after the last acknowledged batch would be lost. The journal
// closes both gaps:
//
//  1. when the sink forms a batch from drained lines, and BEFORE the first
//     POST attempt, the batch is appended to the per-(job, generation)
//     journal and fsynced;
//  2. the record is deleted only after the control plane acknowledged the
//     delivery (204/200 duplicate);
//  3. a fresh sink for the same (job, generation) replays the unconsumed
//     records IN ORDER with their original batch_id/sequence before it forms
//     any new batch, and continues the sequence after the persisted maximum.
//
// Crash safety: a record is created with a durable atomic replace (temp file
// + fsync + rename + parent fsync), so it is either fully present or absent,
// and it exists on disk before the first POST can leave the process.
// Acknowledgement is a durable ack watermark (the highest acked sequence,
// written atomically and fsynced) followed by a best-effort delete of the
// record:
//
//   - a crash before the watermark write leaves the record unconsumed, and
//     the replay carries the identical (job, generation, batch_id) identity,
//     so the server's receipt answers 204 without duplicating lines;
//   - a crash after the watermark write but before the delete leaves a
//     record the watermark already covers: the next open recognizes it as
//     consumed, never replays it, and reclaims the file;
//   - a record is never deleted before the ack is received (the watermark
//     write itself is the durable ack point and precedes the unlink).
//
// The watermark also preserves the persisted maximum across ack+cleanup, so
// a fresh same-generation sink never regresses the sequence and can never
// false-dedupe genuinely new lines against an already-acked batch id. A
// persisted watermark is required because deleting every record would
// otherwise erase the only local record of how far the sequence got.
//
// Records persist the MASKED lines — exactly the bytes the delivery posts —
// so secret material never lands in the journal, and a replay re-masks the
// already masked lines, which is idempotent.
//
// Accepted loss boundary: lines drained from the pipes but not yet journaled
// when the process dies are lost. A line counts as delivered only once its
// batch is journaled AND acknowledged; the control plane re-executes the job
// under a new lease generation after lease expiry, which is the recovery
// path for that window.
type logJournal struct {
	root          string
	dir           string
	watermarkPath string
	jobID         string
	generation    int64
	mask          func(string) string

	mu        sync.Mutex
	records   []logBatch
	paths     map[int64]string
	sizes     map[int64]int64
	maxSeq    int64
	watermark int64
	bytes     int64
	removed   bool
}

// logJournalWatermark is the durable ack point: every sequence up to (and
// including) it is delivered and must never be replayed, and new batches
// continue after it.
type logJournalWatermark struct {
	JobID      string `json:"job_id"`
	Generation int64  `json:"generation"`
	Sequence   int64  `json:"sequence"`
}

// logJournalRecord is one durable batch record. The identity fields make the
// record self-describing (a record found under the wrong job/generation is a
// hard error, never silently replayed) and the ordered lines are the exact
// masked payload of the batch.
type logJournalRecord struct {
	JobID      string           `json:"job_id"`
	Generation int64            `json:"generation"`
	Sequence   int64            `json:"sequence"`
	BatchID    string           `json:"batch_id"`
	Lines      []logJournalLine `json:"lines"`
}

type logJournalLine struct {
	Job  string `json:"job"`
	Step string `json:"step"`
	Line string `json:"line"`
}

// asyncJournalBytes bounds the on-disk journal of ONE (job, generation). It
// is deliberately proportional to the in-memory 32 MiB spool budget (4x):
// the journal retains every line until its batch is acked, so a stalled
// control plane can grow it well past the memory spool, but never without a
// bound. Overflow fails the job explicitly through the existing log failure
// reporting; lines are NEVER silently dropped by the journal.
var asyncJournalBytes = int64(4) * int64(32<<20)

// errLogJournalOverflow reports that journaling a batch would exceed the
// per-job-generation disk budget. The sink treats it like any other journal
// failure: the batch is not posted, the lines stay in the memory spool, and
// the job fails explicitly (never an ack for an unjournaled batch, never a
// silent drop).
var errLogJournalOverflow = errors.New("log journal disk budget exceeded")

// Durable-write seams. journalFileSync/journalFileClose are the checked
// file Sync/Close steps, journalDirSync is the parent directory fsync after
// the rename or unlink, and journalRemove is the record unlink. Tests
// override them to inject journal write/cleanup failures deterministically.
var (
	journalFileSync  = func(f *os.File) error { return f.Sync() }
	journalFileClose = func(f *os.File) error { return f.Close() }
	journalDirSync   = syncJournalDir
	journalRemove    = os.Remove
)

// logJournalKey derives the filesystem-safe per-job directory name: job IDs
// are server-supplied, so the directory name is a hash and the record itself
// carries the authoritative ID to validate against.
func logJournalKey(jobID string) string {
	sum := sha256.Sum256([]byte("kiwi-runner-log-journal\x00" + jobID))
	return hex.EncodeToString(sum[:16])
}

// journalRecordName is the record's on-disk name: the zero-padded sequence
// makes ReadDir order match replay order and the batch id disambiguates a
// (buggy) duplicated sequence.
func journalRecordName(sequence int64, batchID string) string {
	return fmt.Sprintf("%020d-%s.json", sequence, batchID)
}

// openLogJournal opens (creating on first use) the journal for one
// (job, generation) under root and loads every unconsumed record. A corrupt
// or foreign record is a hard error: fail the job rather than silently
// ignoring durable state. root=="" disables journaling (the caller has no
// durable state directory).
func openLogJournal(root, jobID string, generation int64, mask func(string) string) (*logJournal, error) {
	if root == "" || jobID == "" {
		return nil, nil
	}
	jobDir := filepath.Join(root, logJournalKey(jobID))
	dir := filepath.Join(jobDir, "gen-"+strconv.FormatInt(generation, 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("log journal: %w", err)
	}
	j := &logJournal{
		root:          root,
		dir:           dir,
		watermarkPath: filepath.Join(dir, "ack-watermark"),
		jobID:         jobID,
		generation:    generation,
		mask:          mask,
		paths:         map[int64]string{},
		sizes:         map[int64]int64{},
	}
	if err := j.load(); err != nil {
		return nil, err
	}
	j.pruneOlderGenerations(jobDir)
	return j, nil
}

// readLogJournalWatermark reads the durable ack point. A missing watermark
// means nothing was acked yet; a corrupt or foreign one is a hard error.
func readLogJournalWatermark(path, jobID string, generation int64) (int64, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("log journal: read watermark %s: %w", path, err)
	}
	var wm logJournalWatermark
	if err := json.Unmarshal(b, &wm); err != nil {
		return 0, fmt.Errorf("log journal: decode watermark %s: %w", path, err)
	}
	if wm.JobID != jobID || wm.Generation != generation {
		return 0, fmt.Errorf("log journal: watermark %s belongs to (%q, %d), not (%q, %d)", path, wm.JobID, wm.Generation, jobID, generation)
	}
	if wm.Sequence < 0 {
		return 0, fmt.Errorf("log journal: watermark %s has a negative sequence", path)
	}
	return wm.Sequence, nil
}

// load reads the durable ack watermark and the unconsumed records, in
// durable order. Records the watermark already covers are consumed state
// left by a skipped cleanup: they are never replayed and are reclaimed as
// the journal opens. A decode or identity failure is a hard error (fail
// closed: durable state must not be silently ignored).
func (j *logJournal) load() error {
	wm, err := readLogJournalWatermark(j.watermarkPath, j.jobID, j.generation)
	if err != nil {
		return err
	}
	j.watermark = wm
	j.maxSeq = wm
	ents, err := os.ReadDir(j.dir)
	if err != nil {
		return fmt.Errorf("log journal: read %s: %w", j.dir, err)
	}
	seen := map[int64]bool{}
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			// Temp files from an interrupted write are never records.
			continue
		}
		path := filepath.Join(j.dir, ent.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("log journal: read %s: %w", path, err)
		}
		var rec logJournalRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return fmt.Errorf("log journal: decode %s: %w", path, err)
		}
		if rec.JobID != j.jobID || rec.Generation != j.generation {
			return fmt.Errorf("log journal: record %s belongs to (%q, %d), not (%q, %d)", path, rec.JobID, rec.Generation, j.jobID, j.generation)
		}
		if rec.Sequence <= 0 || rec.BatchID == "" || len(rec.Lines) == 0 {
			return fmt.Errorf("log journal: record %s is incomplete", path)
		}
		if rec.Sequence <= j.watermark {
			// Acked, cleanup skipped/delayed: consumed, never replayed.
			// Reclaiming the file is best effort; a failure only delays
			// space reclamation and never re-sends the batch.
			_ = journalRemove(path)
			continue
		}
		if seen[rec.Sequence] {
			return fmt.Errorf("log journal: duplicate sequence %d under %s", rec.Sequence, j.dir)
		}
		seen[rec.Sequence] = true
		batch := logBatch{Sequence: rec.Sequence, ID: rec.BatchID, Lines: make([]logLine, 0, len(rec.Lines))}
		for _, l := range rec.Lines {
			batch.Lines = append(batch.Lines, logLine{
				Job:       l.Job,
				Step:      l.Step,
				Line:      l.Line,
				spoolCost: int64(len(l.Job) + len(l.Step) + len(l.Line)),
			})
		}
		j.records = append(j.records, batch)
		j.paths[rec.Sequence] = path
		j.sizes[rec.Sequence] = int64(len(b))
		j.bytes += int64(len(b))
		if rec.Sequence > j.maxSeq {
			j.maxSeq = rec.Sequence
		}
	}
	sort.Slice(j.records, func(a, b int) bool { return j.records[a].Sequence < j.records[b].Sequence })
	return nil
}

// pruneOlderGenerations removes journal directories of earlier lease
// generations of the same job. The control plane increments the generation
// on every lease, so an older generation can never be resumed; without this
// a hard crash would leak its records forever. Best effort: pruning never
// fails the job.
func (j *logJournal) pruneOlderGenerations(jobDir string) {
	ents, err := os.ReadDir(jobDir)
	if err != nil {
		return
	}
	for _, ent := range ents {
		if !ent.IsDir() || !strings.HasPrefix(ent.Name(), "gen-") {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(ent.Name(), "gen-"), 10, 64)
		if err != nil || n >= j.generation {
			continue
		}
		_ = os.RemoveAll(filepath.Join(jobDir, ent.Name()))
	}
}

// pendingBatches returns the unconsumed records in sequence order. The lines
// are the already-masked journaled payload; the batch identity is the
// ORIGINAL one, never recomputed.
func (j *logJournal) pendingBatches() []logBatch {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]logBatch, 0, len(j.records))
	for _, b := range j.records {
		out = append(out, logBatch{Sequence: b.Sequence, ID: b.ID, Lines: append([]logLine(nil), b.Lines...)})
	}
	return out
}

// maxSequence is the highest persisted sequence: new batches continue after
// it so a restarted runner never regresses the sequence.
func (j *logJournal) maxSequence() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.maxSeq
}

// append durably journals one batch before its first POST attempt. It fails
// (and writes nothing) when the batch would exceed the disk budget; the
// caller must then not post the batch.
func (j *logJournal) append(batch logBatch) error {
	if batch.Sequence <= 0 || batch.ID == "" || len(batch.Lines) == 0 {
		return fmt.Errorf("log journal: refusing to journal a batch without an identity")
	}
	rec := logJournalRecord{JobID: j.jobID, Generation: j.generation, Sequence: batch.Sequence, BatchID: batch.ID}
	masked := make([]logLine, 0, len(batch.Lines))
	for _, l := range batch.Lines {
		m := logLine{Job: l.Job, Step: l.Step, Line: j.maskLine(l.Line)}
		m.spoolCost = int64(len(m.Job) + len(m.Step) + len(m.Line))
		masked = append(masked, m)
		rec.Lines = append(rec.Lines, logJournalLine{Job: m.Job, Step: m.Step, Line: m.Line})
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("log journal: encode batch %d: %w", batch.Sequence, err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.removed {
		return fmt.Errorf("log journal: journal for (%q, %d) is closed", j.jobID, j.generation)
	}
	if batch.Sequence <= j.watermark {
		return fmt.Errorf("log journal: sequence %d is already durably acked (watermark %d)", batch.Sequence, j.watermark)
	}
	if _, ok := j.paths[batch.Sequence]; ok {
		return fmt.Errorf("log journal: sequence %d already journaled", batch.Sequence)
	}
	if j.bytes+int64(len(b)) > asyncJournalBytes {
		return fmt.Errorf("%w: %d pending bytes + %d byte batch exceeds the %d byte budget for job %s generation %d",
			errLogJournalOverflow, j.bytes, len(b), asyncJournalBytes, j.jobID, j.generation)
	}
	path := filepath.Join(j.dir, journalRecordName(batch.Sequence, batch.ID))
	if err := durableWriteJournalRecord(path, b); err != nil {
		return err
	}
	j.paths[batch.Sequence] = path
	j.sizes[batch.Sequence] = int64(len(b))
	j.bytes += int64(len(b))
	j.records = append(j.records, logBatch{Sequence: batch.Sequence, ID: batch.ID, Lines: masked})
	if batch.Sequence > j.maxSeq {
		j.maxSeq = batch.Sequence
	}
	return nil
}

// ack durably marks the batch consumed after the control plane confirmed its
// delivery. The durable ack point is the watermark write; the record unlink
// afterwards is only space reclamation, so a failing unlink (or a crash right
// after the watermark) can never resurrect a replay: the next open sees the
// watermark and reclaims the record without sending it. The watermark is
// written BEFORE the unlink, so a record is never deleted before the ack.
// It is a no-op for a sequence already acked (or never journaled).
func (j *logJournal) ack(sequence int64, batchID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.removed {
		return nil
	}
	path, ok := j.paths[sequence]
	if !ok {
		return nil
	}
	if filepath.Base(path) != journalRecordName(sequence, batchID) {
		return fmt.Errorf("log journal: ack sequence %d does not match the journaled batch %s", sequence, batchID)
	}
	if sequence > j.watermark {
		wm, err := json.Marshal(logJournalWatermark{JobID: j.jobID, Generation: j.generation, Sequence: sequence})
		if err != nil {
			return fmt.Errorf("log journal: encode ack watermark %d: %w", sequence, err)
		}
		if err := durableWriteJournalRecord(j.watermarkPath, wm); err != nil {
			// The record stays unconsumed: a restart replays it and the
			// server dedupes. This failure is surfaced to fail the job.
			return fmt.Errorf("log journal: ack watermark %d: %w", sequence, err)
		}
		j.watermark = sequence
	}
	size := j.sizes[sequence]
	delete(j.paths, sequence)
	delete(j.sizes, sequence)
	for i, b := range j.records {
		if b.Sequence == sequence {
			j.records = append(j.records[:i], j.records[i+1:]...)
			break
		}
	}
	if err := journalRemove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The watermark already covers the record; keep its bytes accounted
		// so a persistently failing cleanup keeps the disk bound enforced,
		// and let a later open or the terminal remove reclaim it.
		return nil
	}
	j.bytes -= size
	if err := journalDirSync(j.dir); err != nil {
		return fmt.Errorf("log journal: ack batch %d: %w", sequence, err)
	}
	return nil
}

// remove deletes the whole journal for this (job, generation). It is called
// after terminal completion (the lease is over; no same-generation resume
// can happen anymore) so no stale records survive the job. Acked records are
// already gone; any unconsumed record is terminal state for a completed job.
func (j *logJournal) remove() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.removed {
		return nil
	}
	j.removed = true
	if err := os.RemoveAll(j.dir); err != nil {
		return fmt.Errorf("log journal: remove %s: %w", j.dir, err)
	}
	// Best effort: drop the per-job directory too when it is now empty.
	_ = os.Remove(filepath.Dir(j.dir))
	if err := journalDirSync(j.root); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("log journal: remove %s: %w", j.dir, err)
	}
	return nil
}

// maskLine applies the delivery mask to a line before it is persisted, so
// the journal only ever holds masked payload. A nil mask is the identity.
func (j *logJournal) maskLine(line string) string {
	if j.mask == nil {
		return line
	}
	return j.mask(line)
}

// durableWriteJournalRecord creates path with the publisher pattern used by
// the runner's other durable writes: a temp file in the target directory,
// checked Write/Sync/Close, an atomic rename over the target, then a parent
// directory fsync so the rename itself survives a crash. A failure before
// the rename removes the temp file and leaves no record, so the caller never
// posts a batch that is not journaled.
func durableWriteJournalRecord(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("log journal: %w", err)
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = journalFileClose(f)
		_ = os.Remove(tmp)
		return fmt.Errorf("log journal: write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = journalFileClose(f)
		_ = os.Remove(tmp)
		return fmt.Errorf("log journal: chmod %s: %w", tmp, err)
	}
	if err := journalFileSync(f); err != nil {
		_ = journalFileClose(f)
		_ = os.Remove(tmp)
		return fmt.Errorf("log journal: sync %s: %w", tmp, err)
	}
	if err := journalFileClose(f); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("log journal: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("log journal: publish %s: %w", path, err)
	}
	if err := journalDirSync(dir); err != nil {
		return fmt.Errorf("log journal: sync %s: %w", dir, err)
	}
	return nil
}

// syncJournalDir fsyncs a directory so a rename or unlink inside it is
// durable. Windows has no directory-fsync equivalent, so there it is a
// documented no-op: renames are still atomic and NTFS journals metadata, but
// a power loss may lose the rename sooner than on unix.
func syncJournalDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

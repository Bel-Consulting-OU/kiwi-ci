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
	"sync/atomic"
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
// Acknowledgement is a durable ack watermark (the highest CONTIGUOUS acked
// sequence) followed by reclamation of the records it covers:
//
//   - a crash before the watermark write leaves every record unconsumed, and
//     the replay carries the identical (job, generation, batch_id) identity,
//     so the server's receipt answers 204 without duplicating lines;
//   - a crash after the watermark write but before the unlink leaves a
//     record the watermark already covers: the next open recognizes it as
//     consumed, never replays it, and reclaims the file;
//   - a record is never deleted before the ack is durably covered (the
//     watermark write itself is the durable ack point and precedes the
//     unlink).
//
// The watermark also preserves the persisted maximum across ack+cleanup, so
// a fresh same-generation sink never regresses the sequence and can never
// false-dedupe genuinely new lines against an already-acked batch id. A
// persisted watermark is required because deleting every record would
// otherwise erase the only local record of how far the sequence got.
//
// Contiguous-ack invariant: the watermark equals the highest sequence whose
// delivery was confirmed, and no lower sequence may be left unconsumed. The
// sink enforces it by stopping at the first send/ack failure, and ack
// refuses to advance across an unconsumed record (fail closed). A format-1
// watermark (the field absent: the pre-amortization sender) did NOT preserve
// this invariant, so a record at or below a format-1 watermark is not proof
// of delivery and is replayed rather than reclaimed; only a record whose
// sequence EQUALS the watermark is unambiguously consumed.
//
// Ack amortization: the watermark write and the record unlinks are batched
// (every journalAckFlushEvery acks, and on Finish). A crash after an ack but
// before the flush replays already-delivered batches, which the server
// dedupes by batch id; a crash before the flush can never skip an un-acked
// batch because acks are recorded only after a confirmed delivery and the
// flush only covers confirmed sequences. The trade-off is idempotent replay
// work in a crash window in exchange for ~2 fsyncs per batch instead of ~4
// on the sender critical path.
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

	// mem is the ONE in-memory byte budget shared with the sink's spool:
	// every journal-resident record is charged against asyncSpoolBytes, so
	// the documented bound covers the spool AND the journal backlog instead
	// of the journal adding a second, unbudgeted 128 MiB in memory.
	mem *logMemBudget

	mu            sync.Mutex
	records       []logBatch
	paths         map[int64]string
	sizes         map[int64]int64
	resident      int64
	maxSeq        int64
	watermark     int64
	ackedSeq      int64
	unflushedAcks int
	// trustWatermark is true for format-2+ watermarks, whose contiguous-ack
	// invariant means every record at or below it is consumed.
	trustWatermark bool
	bytes          int64
	removed        bool
}

// logJournalFormat is the durable journal format version written into the ack
// watermark. Format 1 (the field absent) is the pre-amortization sender,
// whose watermark could leapfrog a failed, never-delivered batch; format 2
// (current) preserves watermark == highest contiguous acked sequence.
const logJournalFormat = 2

// journalAckFlushEvery amortizes the ack-side durable work: a watermark
// write (temp+fsync+rename+dir-fsync) and the covered record unlinks are
// batched per this many confirmed batches. It is a var so tests can drive
// the flush boundary deterministically.
var journalAckFlushEvery = 16

// journalWatermarkWrites counts durable ack-watermark writes. Test seam: the
// amortization test asserts a burst of K batches performs fewer than K
// writes without relying on timing.
var journalWatermarkWrites atomic.Int64

// logJournalWatermark is the durable ack point: every sequence up to (and
// including) it is delivered and must never be replayed, and new batches
// continue after it. Format is the journal format that wrote it (0/absent
// for the pre-amortization sender).
type logJournalWatermark struct {
	JobID      string `json:"job_id"`
	Generation int64  `json:"generation"`
	Sequence   int64  `json:"sequence"`
	Format     int    `json:"format"`
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
// reporting; lines are NEVER silently dropped by the journal. The MEMORY
// retained for pending records is bounded separately (and jointly with the
// spool) by asyncSpoolBytes through logMemBudget.
var asyncJournalBytes = int64(4) * int64(32<<20)

// errLogJournalOverflow reports that journaling a batch would exceed the
// per-job-generation disk budget. The sink treats it like any other journal
// failure: the batch is not posted, the lines stay in the memory spool, and
// the job fails explicitly (never an ack for an unjournaled batch, never a
// silent drop).
var errLogJournalOverflow = errors.New("log journal disk budget exceeded")

// errLogJournalMemoryOverflow reports that journal-resident pending records
// would exceed the shared in-memory budget (asyncSpoolBytes). Fail closed
// with the same explicit semantics as the disk budget: no POST for a batch
// that cannot be journaled, no silent drop, and on load no durable record is
// ever discarded.
var errLogJournalMemoryOverflow = errors.New("log journal memory budget exceeded")

// logMemBudget is the single in-memory byte budget shared by the sink's
// async spool and the journal's resident pending records. Both charge the
// same counter, so the documented asyncSpoolBytes bound covers their sum
// (previously the journal retained up to the 128 MiB DISK budget in memory
// on top of the spool). Reservations are all-or-nothing; callers surface an
// overflow explicitly (the spool counts a dropped line, the journal fails
// the batch) and never silently discard.
type logMemBudget struct{ used atomic.Int64 }

func (b *logMemBudget) reserve(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		cur := b.used.Load()
		if cur+n > asyncSpoolBytes {
			return false
		}
		if b.used.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

func (b *logMemBudget) release(n int64) {
	if n <= 0 {
		return
	}
	for {
		cur := b.used.Load()
		next := cur - n
		if next < 0 {
			next = 0
		}
		if b.used.CompareAndSwap(cur, next) {
			return
		}
	}
}

func (b *logMemBudget) load() int64 { return b.used.Load() }

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
		mem:           &logMemBudget{},
		paths:         map[int64]string{},
		sizes:         map[int64]int64{},
	}
	if err := j.load(); err != nil {
		return nil, err
	}
	j.pruneOlderGenerations(jobDir)
	return j, nil
}

// readLogJournalWatermark reads the durable ack point and its format. A
// missing watermark means nothing was acked yet; a corrupt, foreign or
// future-format one is a hard error.
func readLogJournalWatermark(path, jobID string, generation int64) (int64, int, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, logJournalFormat, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("log journal: read watermark %s: %w", path, err)
	}
	var wm logJournalWatermark
	if err := json.Unmarshal(b, &wm); err != nil {
		return 0, 0, fmt.Errorf("log journal: decode watermark %s: %w", path, err)
	}
	if wm.JobID != jobID || wm.Generation != generation {
		return 0, 0, fmt.Errorf("log journal: watermark %s belongs to (%q, %d), not (%q, %d)", path, wm.JobID, wm.Generation, jobID, generation)
	}
	if wm.Sequence < 0 {
		return 0, 0, fmt.Errorf("log journal: watermark %s has a negative sequence", path)
	}
	if wm.Format > logJournalFormat {
		return 0, 0, fmt.Errorf("log journal: watermark %s uses unsupported format %d", path, wm.Format)
	}
	return wm.Sequence, wm.Format, nil
}

// load reads the durable ack watermark and the unconsumed records, in
// durable order. A format-2+ watermark covers every record at or below it
// (contiguous ack) and those are never replayed; a format-1 watermark is
// untrusted, so only a record EQUAL to it is treated as consumed and a lower
// record (a failed batch the old sender's watermark leapfrogged) is
// replayed. Reclaimed/loaded records are charged against the shared memory
// budget; exceeding it is an explicit load failure, never a silent drop. A
// decode or identity failure is a hard error (fail closed: durable state
// must not be silently ignored).
func (j *logJournal) load() error {
	wm, format, err := readLogJournalWatermark(j.watermarkPath, j.jobID, j.generation)
	if err != nil {
		return err
	}
	j.watermark = wm
	j.ackedSeq = wm
	j.maxSeq = wm
	j.trustWatermark = format >= logJournalFormat
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
		if rec.Sequence <= j.watermark && (j.trustWatermark || rec.Sequence == j.watermark) {
			// Consumed: either the format-2 contiguous watermark covers it
			// or the format-1 legacy watermark equals it (the ack that wrote
			// it unlinked this exact record). Reclaiming the file is best
			// effort; a failure only delays space reclamation and never
			// re-sends the batch.
			_ = journalRemove(path)
			continue
		}
		if seen[rec.Sequence] {
			return fmt.Errorf("log journal: duplicate sequence %d under %s", rec.Sequence, j.dir)
		}
		seen[rec.Sequence] = true
		if !j.mem.reserve(int64(len(b))) {
			return fmt.Errorf("%w: loading %s (%d bytes) on top of %d resident bytes exceeds the %d byte memory budget for job %s generation %d",
				errLogJournalMemoryOverflow, path, len(b), j.mem.load(), asyncSpoolBytes, j.jobID, j.generation)
		}
		j.resident += int64(len(b))
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

// pendingBatches returns a copy of the unconsumed records in sequence order.
// The lines are the already-masked journaled payload; the batch identity is
// the ORIGINAL one, never recomputed. Tests use this to inspect durable
// state; the sink moves the records out with takePendingBatches so the
// replay payload is not duplicated in memory.
func (j *logJournal) pendingBatches() []logBatch {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]logBatch, 0, len(j.records))
	for _, b := range j.records {
		out = append(out, logBatch{Sequence: b.Sequence, ID: b.ID, Lines: append([]logLine(nil), b.Lines...)})
	}
	return out
}

// takePendingBatches moves the loaded unconsumed records to the caller. The
// journal drops its own reference so the sink's replay buffer is the single
// in-memory copy; the records stay charged against the shared memory budget
// until their batches are acked.
func (j *logJournal) takePendingBatches() []logBatch {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := j.records
	j.records = nil
	return out
}

// residentBytes is the memory charged for journal-resident pending records
// (loaded plus appended, minus acked and removed). Test/accounting seam.
func (j *logJournal) residentBytes() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.resident
}

// maxSequence is the highest persisted sequence: new batches continue after
// it so a restarted runner never regresses the sequence.
func (j *logJournal) maxSequence() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.maxSeq
}

// append durably journals one batch before its first POST attempt. It fails
// (and writes nothing) when the batch would exceed the disk budget OR the
// shared in-memory budget; the caller must then not post the batch.
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
	if batch.Sequence <= j.ackedSeq {
		return fmt.Errorf("log journal: sequence %d is already acked (durable watermark %d)", batch.Sequence, j.watermark)
	}
	if _, ok := j.paths[batch.Sequence]; ok {
		return fmt.Errorf("log journal: sequence %d already journaled", batch.Sequence)
	}
	if j.bytes+int64(len(b)) > asyncJournalBytes {
		return fmt.Errorf("%w: %d pending bytes + %d byte batch exceeds the %d byte budget for job %s generation %d",
			errLogJournalOverflow, j.bytes, len(b), asyncJournalBytes, j.jobID, j.generation)
	}
	if !j.mem.reserve(int64(len(b))) {
		return fmt.Errorf("%w: %d resident bytes + %d byte record exceeds the %d byte memory budget for job %s generation %d",
			errLogJournalMemoryOverflow, j.mem.load(), len(b), asyncSpoolBytes, j.jobID, j.generation)
	}
	path := filepath.Join(j.dir, journalRecordName(batch.Sequence, batch.ID))
	if err := durableWriteJournalRecord(path, b); err != nil {
		j.mem.release(int64(len(b)))
		return err
	}
	j.resident += int64(len(b))
	j.paths[batch.Sequence] = path
	j.sizes[batch.Sequence] = int64(len(b))
	j.bytes += int64(len(b))
	j.records = append(j.records, logBatch{Sequence: batch.Sequence, ID: batch.ID, Lines: masked})
	if batch.Sequence > j.maxSeq {
		j.maxSeq = batch.Sequence
	}
	return nil
}

// minUnackedSequenceLocked returns the lowest record sequence that is not
// yet confirmed: records at or below ackedSeq are acked (their payload and
// unlink are pending the next flush) and never count as a gap.
func (j *logJournal) minUnackedSequenceLocked() (int64, bool) {
	min := int64(0)
	found := false
	for seq := range j.paths {
		if seq <= j.ackedSeq {
			continue
		}
		if !found || seq < min {
			min = seq
			found = true
		}
	}
	return min, found
}

// ack records a confirmed delivery. The durable watermark and the record
// unlink are amortized (journalAckFlushEvery acks, or an explicit flushAcks
// from the sink's Finish), but the ordering guarantee is unchanged: the
// watermark write precedes every unlink it covers, so a crash can only
// replay idempotently, never lose a delivered batch and never skip an
// un-acked one.
//
// ack refuses to advance past an unconsumed lower sequence (fail closed):
// the watermark must stay the highest CONTIGUOUS acked sequence, otherwise
// load would have to guess whether a leapfrogged record was delivered.
// It is a no-op for a sequence already acked or never journaled.
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
	if min, ok := j.minUnackedSequenceLocked(); ok && min < sequence {
		return fmt.Errorf("log journal: refusing to ack sequence %d past unconsumed sequence %d", sequence, min)
	}
	if sequence <= j.watermark {
		// Already durably acked (a replayed legacy record, or a replay whose
		// original ack landed): reclaim without moving the watermark.
		_, err := j.reclaimCoveredLocked(sequence)
		return err
	}
	if sequence <= j.ackedSeq {
		// Acked in memory earlier; the pending flush will cover and reclaim
		// it. Never unlink before the watermark is durable.
		return nil
	}
	j.ackedSeq = sequence
	j.unflushedAcks++
	if j.unflushedAcks >= journalAckFlushEvery {
		return j.flushAcksLocked()
	}
	return nil
}

// flushAcks makes every in-memory ack durable and reclaims the records it
// covers. Ordering is the invariant: the watermark write precedes the
// unlinks, so a record is never deleted before its delivery is durable. A
// failure from the watermark write leaves every record unconsumed and is
// surfaced as a delivery failure; a failing unlink is only cleanup lag and
// never fails the job (the watermark already covers the record).
func (j *logJournal) flushAcks() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.flushAcksLocked()
}

func (j *logJournal) flushAcksLocked() error {
	if j.removed {
		return nil
	}
	if j.ackedSeq > j.watermark {
		wm, err := json.Marshal(logJournalWatermark{JobID: j.jobID, Generation: j.generation, Sequence: j.ackedSeq, Format: logJournalFormat})
		if err != nil {
			return fmt.Errorf("log journal: encode ack watermark %d: %w", j.ackedSeq, err)
		}
		journalWatermarkWrites.Add(1)
		if err := durableWriteJournalRecord(j.watermarkPath, wm); err != nil {
			// The records stay unconsumed: a restart replays them and the
			// server dedupes. This failure is surfaced to fail the job.
			return fmt.Errorf("log journal: ack watermark %d: %w", j.ackedSeq, err)
		}
		j.watermark = j.ackedSeq
	}
	j.unflushedAcks = 0
	// Reclaim every record the durable watermark now covers, in sequence
	// order so a crash mid-cleanup leaves a suffix, never a hole.
	seqs := make([]int64, 0, len(j.paths))
	for seq := range j.paths {
		if seq <= j.watermark {
			seqs = append(seqs, seq)
		}
	}
	sort.Slice(seqs, func(a, b int) bool { return seqs[a] < seqs[b] })
	dirDirty := false
	for _, seq := range seqs {
		dirty, err := j.reclaimCoveredLocked(seq)
		if err != nil {
			return err
		}
		dirDirty = dirDirty || dirty
	}
	if dirDirty {
		if err := journalDirSync(j.dir); err != nil {
			return fmt.Errorf("log journal: ack cleanup: %w", err)
		}
	}
	return nil
}

// reclaimCoveredLocked removes one durably acked record. It refuses to touch
// a sequence the durable watermark does not cover (that record must stay for
// replay), releases the record's share of the shared memory budget, and
// treats a failed unlink as cleanup lag: the watermark already covers the
// record, so a later open or the terminal remove reclaims it, and the disk
// bytes stay accounted so the bound remains enforced. It reports whether a
// directory entry changed (a caller batches one directory fsync).
func (j *logJournal) reclaimCoveredLocked(sequence int64) (bool, error) {
	path, ok := j.paths[sequence]
	if !ok {
		return false, nil
	}
	if sequence > j.watermark {
		return false, fmt.Errorf("log journal: refusing to reclaim unacked sequence %d (watermark %d)", sequence, j.watermark)
	}
	size := j.sizes[sequence]
	delete(j.paths, sequence)
	delete(j.sizes, sequence)
	for i, b := range j.records {
		if b.Sequence == sequence {
			copy(j.records[i:], j.records[i+1:])
			j.records[len(j.records)-1] = logBatch{}
			j.records = j.records[:len(j.records)-1]
			break
		}
	}
	j.mem.release(size)
	j.resident -= size
	if err := journalRemove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	j.bytes -= size
	return true, nil
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
	// The in-memory payload is gone with the journal: release its share of
	// the shared budget even if the disk removal below fails.
	j.mem.release(j.resident)
	j.resident = 0
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

package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestEffectUsageAccountPersistFailureDoesNotLeakMarker is the F2-1
// regression: the fs/memory usage effect used to set the job's
// usage_recorded marker and the amounts on the LIVE row before the snapshot
// write, and on a write failure returned the error while leaving the marker
// behind. The outbox retry then re-entered at the marker check, reported
// success and was ACKed even though usage was never durable (lost on
// restart). The failed attempt must leave the live row EXACTLY as it was —
// marker, cost, energy — and move no metrics; the retry must account exactly
// once and the snapshot must carry the marker.
func TestEffectUsageAccountPersistFailureDoesNotLeakMarker(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	jobID := "0123456789abcdef0123456789abcdef"
	started := time.Now().UTC().Add(-2 * time.Minute)
	finished := time.Now().UTC()
	s.mu.Lock()
	s.jobs[jobID] = model.Job{
		ID: jobID, RunID: "run-usage-persist-fail", Key: "build",
		Status: model.StatusSuccess, StartedAt: &started, FinishedAt: &finished,
		CostRate: 60, PowerWatts: 100,
	}
	if err := s.persistCheckedErrLocked("test.seed_usage"); err != nil {
		s.mu.Unlock()
		t.Fatalf("seed persist: %v", err)
	}
	// The effect's copy is what a stale caller (outbox retry after a crash)
	// would carry: usage not yet recorded.
	callerCopy := s.jobs[jobID]
	s.mu.Unlock()

	seamErr := errors.New("synthetic snapshot write failure")
	s.persistFailForTest = seamErr
	if err := s.effectUsageAccount(context.Background(), callerCopy); !errors.Is(err, seamErr) {
		t.Fatalf("usage effect with a broken snapshot store = %v, want %v", err, seamErr)
	}

	s.mu.Lock()
	live := s.jobs[jobID]
	s.mu.Unlock()
	if live.UsageRecorded || live.Cost != 0 || live.EnergyWh != 0 {
		t.Fatalf("failed persist leaked usage state onto the live row: marker=%v cost=%v energy=%v",
			live.UsageRecorded, live.Cost, live.EnergyWh)
	}
	if live.Status != model.StatusSuccess || live.FinishedAt == nil || !live.FinishedAt.Equal(finished) {
		t.Fatalf("failed persist mutated unrelated live row state: %+v", live)
	}
	cost, energy := usageMetricsSnapshot(s)
	if cost != 0 || energy != 0 {
		t.Fatalf("failed persist moved usage metrics: cost=%v energy=%v", cost, energy)
	}
	s.usageMu.Lock()
	usageLen := len(s.usage)
	s.usageMu.Unlock()
	if usageLen != 0 {
		t.Fatalf("failed persist appended %d usage window entries", usageLen)
	}

	// Clear the seam: the retry re-runs the accounting and persists it
	// exactly once.
	s.persistFailForTest = nil
	if err := s.effectUsageAccount(context.Background(), callerCopy); err != nil {
		t.Fatalf("retried usage effect: %v", err)
	}
	costOnce, energyOnce := usageMetricsSnapshot(s)
	if costOnce <= 0 || energyOnce <= 0 {
		t.Fatalf("retry did not account usage: cost=%v energy=%v", costOnce, energyOnce)
	}
	s.mu.Lock()
	accounted := s.jobs[jobID]
	s.mu.Unlock()
	if !accounted.UsageRecorded || accounted.Cost != costOnce || accounted.EnergyWh != energyOnce {
		t.Fatalf("live row after retry = %+v, want marker with cost=%v energy=%v", accounted, costOnce, energyOnce)
	}
	s.usageMu.Lock()
	if len(s.usage) != 1 {
		n := len(s.usage)
		s.usageMu.Unlock()
		t.Fatalf("usage window entries after retry = %d, want exactly 1", n)
	}
	windowCost := s.usage[0].Cost
	s.usageMu.Unlock()
	if windowCost != costOnce {
		t.Fatalf("usage window cost = %v, metrics cost = %v; want one accounting", windowCost, costOnce)
	}

	// A stale replay after the successful retry must not account a second
	// time.
	if err := s.effectUsageAccount(context.Background(), callerCopy); err != nil {
		t.Fatalf("stale replay: %v", err)
	}
	costAfter, energyAfter := usageMetricsSnapshot(s)
	if costAfter != costOnce || energyAfter != energyOnce {
		t.Fatalf("stale replay moved metrics: %v/%v -> %v/%v", costOnce, energyOnce, costAfter, energyAfter)
	}
	s.usageMu.Lock()
	replayLen := len(s.usage)
	s.usageMu.Unlock()
	if replayLen != 1 {
		t.Fatalf("usage window entries after stale replay = %d, want 1", replayLen)
	}

	// The persisted snapshot carries the marker and the amounts.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	disk := s2.jobs[jobID]
	s2.mu.Unlock()
	if !disk.UsageRecorded || disk.Cost != costOnce || disk.EnergyWh != energyOnce {
		t.Fatalf("persisted snapshot job = %+v, want usage_recorded cost=%v energy=%v", disk, costOnce, energyOnce)
	}
}

// seedTiedCompletionReceipts fills the bounded receipt table to capacity with
// entries sharing one recorded-at timestamp. s.mu must not be held.
func seedTiedCompletionReceipts(t *testing.T, s *Server, tiedAt time.Time) map[string]bool {
	t.Helper()
	seeded := make(map[string]bool, maxCompletionReceipts)
	s.mu.Lock()
	for i := 0; i < maxCompletionReceipts; i++ {
		id := "job-" + strconv.Itoa(i)
		key := completionReceiptKey(id, 1, "r")
		seeded[key] = true
		s.completions[key] = model.CompletionReceipt{JobID: id, Generation: 1, RunnerID: "r", ResultHash: "hash"}
		s.completionReceiptAt[key] = tiedAt
	}
	s.mu.Unlock()
	return seeded
}

// assertDeterministicReceiptEviction seeds a full receipt table where every
// timestamp ties and asserts that the oldest-receipt prediction used by the
// eviction and by the rollback capture agree on the same victim, that the
// prediction is stable across calls, and that recording one more receipt
// evicts exactly that victim.
func assertDeterministicReceiptEviction(t *testing.T, s *Server, tiedAt time.Time) {
	t.Helper()
	seeded := seedTiedCompletionReceipts(t, s, tiedAt)

	s.mu.Lock()
	predicted, _ := s.oldestCompletionReceiptLocked()
	for i := 0; i < 4; i++ {
		if again, _ := s.oldestCompletionReceiptLocked(); again != predicted {
			s.mu.Unlock()
			t.Fatalf("oldest receipt prediction unstable on tied timestamps: %q then %q", predicted, again)
		}
	}
	rb := s.captureCompletionRollbackLocked("new-job", 1, "r")
	if rb.evictedKey != predicted {
		s.mu.Unlock()
		t.Fatalf("rollback capture predicts victim %q but eviction predicts %q", rb.evictedKey, predicted)
	}
	s.recordCompletionReceiptLocked("new-job", 1, "r", "hash")
	n := len(s.completions)
	_, hasNew := s.completions[completionReceiptKey("new-job", 1, "r")]
	_, hasVictim := s.completions[predicted]
	missing := 0
	for key := range seeded {
		if _, ok := s.completions[key]; !ok {
			missing++
		}
	}
	s.mu.Unlock()

	if !hasNew || n != maxCompletionReceipts {
		t.Fatalf("eviction: n=%d hasNew=%v", n, hasNew)
	}
	if hasVictim {
		t.Fatalf("predicted victim %q survived eviction", predicted)
	}
	if missing != 1 {
		t.Fatalf("eviction removed %d seeded receipts, want exactly 1", missing)
	}
}

// TestCompletionReceiptEvictionAllZeroTimestampsDeterministic is the F2-2
// regression for zero-time legacy receipts: with every timestamp equal,
// map-iteration order used to decide the eviction victim, while the rollback
// capture (a separate iteration) could predict a different one and rollback
// then restored only the captured receipt — permanently deleting an
// unrelated entry.
func TestCompletionReceiptEvictionAllZeroTimestampsDeterministic(t *testing.T) {
	assertDeterministicReceiptEviction(t, New("t"), time.Time{})
}

// TestCompletionReceiptEvictionTiedTimestampsDeterministic covers the same
// tie on non-zero timestamps (coarse clock resolution).
func TestCompletionReceiptEvictionTiedTimestampsDeterministic(t *testing.T) {
	assertDeterministicReceiptEviction(t, New("t"), time.Now().UTC().Add(-time.Hour))
}

// assertReceiptRecordsMatchTableLocked checks the emitted snapshot records
// against the live in-memory table. The caller holds s.mu.
func assertReceiptRecordsMatchTableLocked(t *testing.T, s *Server, records []storage.CompletionReceiptRecord) {
	t.Helper()
	emitted := make(map[string]model.CompletionReceipt, len(records))
	for _, rec := range records {
		emitted[completionReceiptKey(rec.Receipt.JobID, rec.Receipt.Generation, rec.Receipt.RunnerID)] = rec.Receipt
	}
	if len(emitted) != len(s.completions) {
		t.Fatalf("emitted %d receipts, live table has %d", len(emitted), len(s.completions))
	}
	for key, rec := range s.completions {
		got, ok := emitted[key]
		if !ok || got != rec {
			t.Fatalf("emitted receipts diverge from the live table at %q", key)
		}
	}
}

// TestCompletionReceiptRecordsCacheVersioned is the F2-3 regression: the
// rendered+sorted snapshot slice is cached under a mutation version and
// reused while the table is unchanged, and any record/eviction/rollback/
// restore invalidates it. The test asserts cache reuse (same backing slice)
// without timing, and that the emitted records always equal the live table.
func TestCompletionReceiptRecordsCacheVersioned(t *testing.T) {
	s := New("t")
	now := time.Now().UTC()
	s.mu.Lock()
	for i := 0; i < 3; i++ {
		id := "job-" + strconv.Itoa(i)
		s.recordCompletionReceiptLocked(id, 1, "r", "hash")
		s.completionReceiptAt[completionReceiptKey(id, 1, "r")] = now.Add(time.Duration(i) * time.Second)
	}
	records := s.completionReceiptRecordsLocked()
	if !s.completionReceiptsCacheOK || s.completionReceiptsCacheVer != s.completionReceiptsVer {
		s.mu.Unlock()
		t.Fatalf("cache not installed after render: ok=%v cacheVer=%d ver=%d",
			s.completionReceiptsCacheOK, s.completionReceiptsCacheVer, s.completionReceiptsVer)
	}
	assertReceiptRecordsMatchTableLocked(t, s, records)

	// Repeating the render without a mutation reuses the cached slice.
	again := s.completionReceiptRecordsLocked()
	if len(records) != len(again) || (len(records) > 0 && &records[0] != &again[0]) {
		s.mu.Unlock()
		t.Fatal("repeated render did not reuse the cached slice")
	}

	// Recording to capacity (which evicts) bumps the version and the fresh
	// render still matches the live table.
	beforeFillVer := s.completionReceiptsVer
	for i := 0; i < maxCompletionReceipts; i++ {
		s.recordCompletionReceiptLocked("fill-"+strconv.Itoa(i), 1, "r", "hash")
	}
	if s.completionReceiptsVer == beforeFillVer {
		s.mu.Unlock()
		t.Fatal("record/eviction did not bump the receipt version")
	}
	afterFill := s.completionReceiptRecordsLocked()
	if len(afterFill) != maxCompletionReceipts {
		s.mu.Unlock()
		t.Fatalf("emitted receipts after fill = %d, want %d", len(afterFill), maxCompletionReceipts)
	}
	assertReceiptRecordsMatchTableLocked(t, s, afterFill)

	// Rollback restores the table and must invalidate the cache: a stale
	// render would omit the receipt the rollback put back.
	rb := s.captureCompletionRollbackLocked("rollback-job", 2, "r2")
	s.recordCompletionReceiptLocked("rollback-job", 2, "r2", "hash")
	_ = s.completionReceiptRecordsLocked()
	s.rollbackCompletionLocked(rb)
	afterRollback := s.completionReceiptRecordsLocked()
	assertReceiptRecordsMatchTableLocked(t, s, afterRollback)
	s.mu.Unlock()

	// Restore bumps the version and rendered output equals the restored set.
	s2 := New("t")
	restored := []storage.CompletionReceiptRecord{
		{Receipt: model.CompletionReceipt{JobID: "restore-a", Generation: 1, RunnerID: "r", ResultHash: "h"}, CreatedAt: now},
		{Receipt: model.CompletionReceipt{JobID: "restore-b", Generation: 1, RunnerID: "r", ResultHash: "h"}, CreatedAt: now},
	}
	s2.mu.Lock()
	restoreVer := s2.completionReceiptsVer
	s2.restoreCompletionReceiptsLocked(restored)
	if s2.completionReceiptsVer == restoreVer {
		s2.mu.Unlock()
		t.Fatal("restore did not bump the receipt version")
	}
	rendered := s2.completionReceiptRecordsLocked()
	assertReceiptRecordsMatchTableLocked(t, s2, rendered)
	s2.mu.Unlock()
	if len(rendered) != len(restored) {
		t.Fatalf("rendered restored receipts = %d, want %d", len(rendered), len(restored))
	}
}

// TestCompletionReceiptRecordsPrunesExpired is the F2-4 regression: a
// long-running fs server used to emit receipts past CompletionReceiptTTL
// forever (TTL was only enforced at restore), so the snapshot carried entries
// that a restart would discard. Expired entries are now filtered out of the
// emitted records and pruned opportunistically, and their dedupe no longer
// short-circuits a replay; a fresh receipt keeps deduping. This matches the
// restore contract, which already drops expired receipts.
func TestCompletionReceiptRecordsPrunesExpired(t *testing.T) {
	s := New("t")
	now := time.Now().UTC()
	expiredKey := completionReceiptKey("expired-job", 1, "r")
	freshKey := completionReceiptKey("fresh-job", 1, "r")
	s.mu.Lock()
	s.completions[expiredKey] = model.CompletionReceipt{JobID: "expired-job", Generation: 1, RunnerID: "r", ResultHash: "h"}
	s.completionReceiptAt[expiredKey] = now.Add(-storage.CompletionReceiptTTL - time.Minute)
	s.completions[freshKey] = model.CompletionReceipt{JobID: "fresh-job", Generation: 1, RunnerID: "r", ResultHash: "h"}
	s.completionReceiptAt[freshKey] = now

	records := s.completionReceiptRecordsLocked()
	_, expiredLive := s.completions[expiredKey]
	_, freshLive := s.completions[freshKey]
	if len(records) != 1 || records[0].Receipt.JobID != "fresh-job" {
		s.mu.Unlock()
		t.Fatalf("emitted records = %+v, want only the fresh receipt", records)
	}
	// The cache bound must be the earliest live expiry, or a heartbeat-only
	// server would keep serving an aged receipt from the cached render until
	// the table happens to mutate.
	wantExpiry := now.Add(storage.CompletionReceiptTTL)
	if !s.completionReceiptsCacheExpiry.Equal(wantExpiry) {
		s.mu.Unlock()
		t.Fatalf("cache expiry = %v, want earliest live expiry %v", s.completionReceiptsCacheExpiry, wantExpiry)
	}
	expiredMatched, expiredErr := s.completionReplayReadyLocked("expired-job", 1, "r", "h")
	freshMatched, freshErr := s.completionReplayReadyLocked("fresh-job", 1, "r", "h")
	// Crossing the earliest expiry forces a re-render even with an unchanged
	// table version (the slice must be re-allocated) so aging is enforced
	// over wall-clock time, not only on mutation.
	s.completionReceiptsCacheExpiry = now.Add(-time.Second)
	rerendered := s.completionReceiptRecordsLocked()
	if len(rerendered) != 1 || (len(records) > 0 && &rerendered[0] == &records[0]) {
		s.mu.Unlock()
		t.Fatalf("cache was not re-rendered after the expiry bound passed: %d records", len(rerendered))
	}
	s.mu.Unlock()

	if expiredLive {
		t.Fatal("expired receipt not pruned from the live table")
	}
	if !freshLive {
		t.Fatal("fresh receipt was pruned")
	}
	if expiredMatched || expiredErr != nil {
		t.Fatalf("expired receipt still dedupes a replay: matched=%v err=%v", expiredMatched, expiredErr)
	}
	if !freshMatched || freshErr != nil {
		t.Fatalf("fresh receipt stopped deduping a replay: matched=%v err=%v", freshMatched, freshErr)
	}
}

// TestReadinessHealsAcrossSwitchToDB is the F2-5 regression: a server armed
// stateDegraded by an fs-mode snapshot failure that then switches to DB mode
// returned early from persistLocked forever, pinning /readiness at 503. The
// transition clears the flag and the diagnostic.
func TestReadinessHealsAcrossSwitchToDB(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`); w.Code != http.StatusOK {
		t.Fatalf("register = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness before switch = %d, want 503", w.Code)
	}

	s.persistFailForTest = nil
	if err := s.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	if s.stateDegraded.Load() {
		t.Fatal("degraded flag survived the transition to DB mode")
	}
	if got := s.persistDegraded(); got != "" {
		t.Fatalf("last persist error after switch = %q, want empty", got)
	}
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusOK {
		t.Fatalf("readiness after switch = %d, want 200: %s", w.Code, w.Body.String())
	}
}

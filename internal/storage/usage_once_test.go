package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemStoreRecordUsageOnce pins the in-memory exactly-once contract: the
// first caller wins and writes the marker plus amounts atomically; every
// later call (and unknown jobs) reports won=false without touching the row.
func TestMemStoreRecordUsageOnce(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	m.jobs["j1"] = model.Job{ID: "j1", RunID: "r1", Status: model.StatusSuccess}

	won, err := m.RecordUsageOnce(ctx, "j1", 1.5, 2.5)
	if err != nil || !won {
		t.Fatalf("first RecordUsageOnce = %v, %v; want true, nil", won, err)
	}
	won, err = m.RecordUsageOnce(ctx, "j1", 9, 9)
	if err != nil || won {
		t.Fatalf("second RecordUsageOnce = %v, %v; want false, nil", won, err)
	}
	got := m.jobs["j1"]
	if !got.UsageRecorded || got.Cost != 1.5 || got.EnergyWh != 2.5 {
		t.Fatalf("job after RecordUsageOnce = %+v", got)
	}
	won, err = m.RecordUsageOnce(ctx, "missing", 1, 1)
	if err != nil || won {
		t.Fatalf("unknown job RecordUsageOnce = %v, %v; want false, nil", won, err)
	}
}

// TestMemStoreRecordUsageOnceConcurrent races N callers for one job through
// the in-memory store: exactly one wins, every loser reports false with no
// error, and the serialized job carries the winner's amounts under a single
// usage_recorded=true marker. Run with -race.
func TestMemStoreRecordUsageOnceConcurrent(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	m.jobs["j1"] = model.Job{ID: "j1", RunID: "r1", Status: model.StatusSuccess}

	const callers = 32
	type outcome struct {
		cost, energy float64
		won          bool
		err          error
	}
	results := make(chan outcome, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cost := float64(i + 1)
			energy := cost * 10
			won, err := m.RecordUsageOnce(ctx, "j1", cost, energy)
			results <- outcome{cost: cost, energy: energy, won: won, err: err}
		}(i)
	}
	wg.Wait()
	close(results)

	var winners []outcome
	for r := range results {
		if r.err != nil {
			t.Fatalf("concurrent RecordUsageOnce: %v", r.err)
		}
		if r.won {
			winners = append(winners, r)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("concurrent winners = %d, want exactly 1", len(winners))
	}
	win := winners[0]
	got := m.jobs["j1"]
	if !got.UsageRecorded || got.Cost != win.cost || got.EnergyWh != win.energy {
		t.Fatalf("job after race = %+v, want winner cost=%v energy=%v recorded", got, win.cost, win.energy)
	}
	// The persisted payload must carry exactly one marker and the winner's
	// amounts: a losing caller's numbers never leak in.
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	if n := strings.Count(string(b), `"usage_recorded":true`); n != 1 {
		t.Fatalf("usage_recorded markers in payload = %d, want 1: %s", n, b)
	}
	var payload struct {
		Cost     float64 `json:"cost"`
		EnergyWh float64 `json:"energy_wh"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatalf("decode job payload: %v", err)
	}
	if payload.Cost != win.cost || payload.EnergyWh != win.energy {
		t.Fatalf("persisted amounts = %v/%v, want %v/%v", payload.Cost, payload.EnergyWh, win.cost, win.energy)
	}
}

// TestFaultyStoreRecordUsageOncePassthrough proves the fault wrapper forwards
// the exactly-once call and injects its error BEFORE the inner store mutates.
func TestFaultyStoreRecordUsageOncePassthrough(t *testing.T) {
	inner := newMemStore()
	inner.jobs["j1"] = model.Job{ID: "j1", RunID: "r1"}
	fault := &FaultyStore{Inner: inner, FailAfter: 1, Err: errUsageOnceDown}
	ctx := context.Background()

	if _, err := fault.RecordUsageOnce(ctx, "j1", 1, 1); err == nil {
		t.Fatal("injected failure must surface")
	}
	if inner.jobs["j1"].UsageRecorded {
		t.Fatal("failed call must not mutate the inner store")
	}
	won, err := fault.RecordUsageOnce(ctx, "j1", 3, 4)
	if err != nil || !won {
		t.Fatalf("retry RecordUsageOnce = %v, %v; want true, nil", won, err)
	}
	if got := inner.jobs["j1"]; !got.UsageRecorded || got.Cost != 3 || got.EnergyWh != 4 {
		t.Fatalf("job after retry = %+v", got)
	}
}

var errUsageOnceDown = usageOnceErr("usage store down")

type usageOnceErr string

func (e usageOnceErr) Error() string { return string(e) }

// TestSnapshotCompletionReceiptsRoundTrip pins the additive snapshot field.
// The pre-field case is real: state.json is written WITHOUT a
// completion_receipts key (a snapshot from before the field existed), loaded
// through a fresh repository that must report no receipts, and only then is a
// snapshot with receipts saved and asserted to round-trip exactly, recording
// timestamps included.
func TestSnapshotCompletionReceiptsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	legacyJSON := []byte(`{"version":1,"runs":{},"jobs":{}}`)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), legacyJSON, 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
	legacy, err := New(dir).loadLocked()
	if err != nil {
		t.Fatalf("loadLocked legacy snapshot: %v", err)
	}
	if legacy.CompletionReceipts != nil {
		t.Fatalf("legacy snapshot loaded %d receipts, want the documented nil pre-field slice", len(legacy.CompletionReceipts))
	}

	repo := New(dir)
	atA := time.Date(2026, 9, 1, 10, 30, 0, 0, time.UTC)
	atB := time.Date(2026, 9, 18, 10, 38, 32, 0, time.UTC)
	recA := model.CompletionReceipt{JobID: "job-1", Generation: 3, RunnerID: "runner-1", ResultHash: "hash-a"}
	recB := model.CompletionReceipt{JobID: "job-2", Generation: 1, RunnerID: "runner-2", ResultHash: "hash-b"}
	want := []CompletionReceiptRecord{{Receipt: recA, CreatedAt: atA}, {Receipt: recB, CreatedAt: atB}}
	if err := repo.Save(Snapshot{Version: legacy.Version, CompletionReceipts: want}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := repo.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.CompletionReceipts) != len(want) {
		t.Fatalf("receipts = %d, want %d", len(got.CompletionReceipts), len(want))
	}
	for i, w := range want {
		g := got.CompletionReceipts[i]
		if g.Receipt != w.Receipt || !g.CreatedAt.Equal(w.CreatedAt) {
			t.Fatalf("receipt %d round trip = %+v, want %+v", i, g, w)
		}
	}
}

// TestSnapshotCompletionReceiptsSurviveFailedSave injects failures into the
// fs snapshot atomic write and proves a failed save neither corrupts nor
// drops existing completion receipts. Pre-rename failures (Sync/Close) leave
// the previous receipt set exactly in place; a post-rename directory-fsync
// failure still leaves a complete, parseable snapshot carrying every receipt
// that was being saved (never a truncated file).
func TestSnapshotCompletionReceiptsSurviveFailedSave(t *testing.T) {
	dir := t.TempDir()
	repo := New(dir)
	atA := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	atB := time.Date(2026, 9, 2, 9, 30, 0, 0, time.UTC)
	first := CompletionReceiptRecord{Receipt: model.CompletionReceipt{JobID: "job-a", Generation: 1, RunnerID: "runner-a", ResultHash: "ha"}, CreatedAt: atA}
	second := CompletionReceiptRecord{Receipt: model.CompletionReceipt{JobID: "job-b", Generation: 2, RunnerID: "runner-b", ResultHash: "hb"}, CreatedAt: atB}
	if err := repo.Save(Snapshot{Version: 1, CompletionReceipts: []CompletionReceiptRecord{first}}); err != nil {
		t.Fatalf("seed Save: %v", err)
	}

	preRename := []struct {
		name   string
		inject func() func()
	}{
		{"Sync", func() func() {
			old := atomicFileSync
			atomicFileSync = func(*os.File) error { return errors.New("injected sync failure") }
			return func() { atomicFileSync = old }
		}},
		{"Close", func() func() {
			old := atomicFileClose
			atomicFileClose = func(f *os.File) error {
				_ = old(f)
				return errors.New("injected close failure")
			}
			return func() { atomicFileClose = old }
		}},
	}
	for _, fail := range preRename {
		restore := fail.inject()
		err := repo.Save(Snapshot{Version: 1, CompletionReceipts: []CompletionReceiptRecord{first, second}})
		restore()
		if err == nil {
			t.Fatalf("%s failure: Save succeeded, want error", fail.name)
		}
		got, err := repo.Load()
		if err != nil {
			t.Fatalf("%s failure: Load: %v", fail.name, err)
		}
		if len(got.CompletionReceipts) != 1 {
			t.Fatalf("%s failure: receipts = %d, want the old 1", fail.name, len(got.CompletionReceipts))
		}
		g := got.CompletionReceipts[0]
		if g.Receipt != first.Receipt || !g.CreatedAt.Equal(first.CreatedAt) {
			t.Fatalf("%s failure: durable receipt changed to %+v, want %+v", fail.name, g, first)
		}
		assertNoScratchFiles(t, dir, "state.json")
	}

	// The directory fsync fails AFTER the rename: Save reports an error (the
	// rename is not yet guaranteed durable), but state.json must already be
	// the complete new document.
	oldDirSync := atomicDirSync
	atomicDirSync = func(string) error { return errors.New("injected dir fsync failure") }
	err := repo.Save(Snapshot{Version: 1, CompletionReceipts: []CompletionReceiptRecord{first, second}})
	atomicDirSync = oldDirSync
	if err == nil {
		t.Fatal("dir fsync failure: Save succeeded, want error")
	}
	got, err := repo.Load()
	if err != nil {
		t.Fatalf("dir fsync failure: Load: %v", err)
	}
	if len(got.CompletionReceipts) != 2 {
		t.Fatalf("dir fsync failure: receipts = %d, want 2", len(got.CompletionReceipts))
	}
	for i, want := range []CompletionReceiptRecord{first, second} {
		g := got.CompletionReceipts[i]
		if g.Receipt != want.Receipt || !g.CreatedAt.Equal(want.CreatedAt) {
			t.Fatalf("dir fsync failure: receipt %d = %+v, want %+v", i, g, want)
		}
	}
	assertNoScratchFiles(t, dir, "state.json")
}

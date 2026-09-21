package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPendingSidecarSnapshotRoundTrip proves the fs pending-sidecar pointers
// ride the state snapshot: the rendered slice is deterministic, Save/Load
// restores the exact (identity -> digest, created) map, and the field is
// additive/omitted when empty so older snapshots stay readable.
func TestPendingSidecarSnapshotRoundTrip(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	pending := map[string]string{
		PendingSidecarKey("job-b", 2, "bin", ArtifactSidecarKindSigstore): EncodePendingSidecarValue(strings.Repeat("b", 64), created),
		PendingSidecarKey("job-a", 1, "bin", ArtifactSidecarKindSBOM):     EncodePendingSidecarValue(strings.Repeat("a", 64), created.Add(time.Hour)),
	}
	ptrs := SnapshotPendingSidecarPointers(pending)
	if len(ptrs) != 2 {
		t.Fatalf("pointers = %d, want 2", len(ptrs))
	}
	// Deterministic (key-sorted) order: job-a before job-b.
	if ptrs[0].JobID != "job-a" || ptrs[1].JobID != "job-b" {
		t.Fatalf("pointer order = %q,%q", ptrs[0].JobID, ptrs[1].JobID)
	}
	if ptrs[0].Artifact != "bin" || ptrs[0].Kind != ArtifactSidecarKindSBOM || ptrs[0].Generation != 1 {
		t.Fatalf("pointer identity = %+v", ptrs[0])
	}
	if ptrs[0].Digest != strings.Repeat("a", 64) || !ptrs[0].CreatedAt.Equal(created.Add(time.Hour)) {
		t.Fatalf("pointer value = %+v", ptrs[0])
	}

	dir := t.TempDir()
	repo := New(dir)
	if err := repo.Save(Snapshot{PendingSidecars: ptrs}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "pending_sidecars") {
		t.Fatalf("state.json does not carry the durable pointer field: %s", raw)
	}
	loaded, err := repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	state := loaded.PendingSidecarState()
	if len(state) != len(pending) {
		t.Fatalf("restored pointers = %d, want %d (%v)", len(state), len(pending), state)
	}
	for key, want := range pending {
		if got := state[key]; got != want {
			t.Fatalf("restored %q = %q, want %q", key, got, want)
		}
	}

	// An empty pointer set stays omitted: an older control plane can read
	// (and an older snapshot can be upgraded without) the new field.
	if err := repo.Save(Snapshot{}); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "pending_sidecars") {
		t.Fatalf("empty pointers were written: %s", raw)
	}
	loaded, err = repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.PendingSidecarState(); len(got) != 0 {
		t.Fatalf("empty snapshot restored %d pointers", len(got))
	}
}

// TestPendingSidecarSnapshotLegacyCompatibility proves an OLD state snapshot
// (no pending_sidecars field at all) loads cleanly and yields an empty
// pointer set: the field is additive.
func TestPendingSidecarSnapshotLegacyCompatibility(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"version":1,"runs":{},"jobs":{},"runners":{},"artifacts":{},"reports":{}}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := New(dir)
	snap, err := repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.PendingSidecars) != 0 {
		t.Fatalf("legacy snapshot restored %d pointers", len(snap.PendingSidecars))
	}
	if got := snap.PendingSidecarState(); len(got) != 0 {
		t.Fatalf("legacy snapshot state = %v, want empty", got)
	}
	// A save after the upgrade writes the (empty) field state without
	// breaking the load round trip.
	if err := repo.Save(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Load(); err != nil {
		t.Fatal(err)
	}
}

// TestPendingSidecarPointersIgnoreMalformedEntries proves a pointer that
// cannot name an exact digest is never written durably, while the legacy
// bare-digest value form still decodes as a digest-only pointer (zero time,
// so the prune ages it out).
func TestPendingSidecarPointersIgnoreMalformedEntries(t *testing.T) {
	created := time.Now().UTC()
	pending := map[string]string{
		"not-a-key": EncodePendingSidecarValue("d", created),
		PendingSidecarKey("", 1, "bin", ArtifactSidecarKindSBOM):          EncodePendingSidecarValue("d", created),
		PendingSidecarKey("job-a", 1, "bin", ArtifactSidecarKindSBOM):     EncodePendingSidecarValue("", created),
		PendingSidecarKey("job-b", 2, "bin", ArtifactSidecarKindSigstore): "bare-digest",
	}
	ptrs := SnapshotPendingSidecarPointers(pending)
	if len(ptrs) != 1 {
		t.Fatalf("pointers = %+v, want only the legacy digest-only entry", ptrs)
	}
	if ptrs[0].JobID != "job-b" || ptrs[0].Digest != "bare-digest" || !ptrs[0].CreatedAt.IsZero() {
		t.Fatalf("legacy pointer = %+v", ptrs[0])
	}

	// Decode semantics: empty is absent, a bare value is digest-only, an
	// encoded value round-trips.
	if _, _, ok := DecodePendingSidecarValue(""); ok {
		t.Fatal("empty value must be absent")
	}
	d, ts, ok := DecodePendingSidecarValue("bare")
	if !ok || d != "bare" || !ts.IsZero() {
		t.Fatalf("bare value = %q %v %v", d, ts, ok)
	}
	encoded := EncodePendingSidecarValue("sum", created)
	if d, ts, ok := DecodePendingSidecarValue(encoded); !ok || d != "sum" || !ts.Equal(created) {
		t.Fatalf("encoded value = %q %v %v", d, ts, ok)
	}
	if got := SnapshotPendingSidecarPointers(nil); got != nil {
		t.Fatalf("nil map pointers = %v, want nil", got)
	}

	// The durable JSON field is additive and self-describing.
	raw, err := json.Marshal(Snapshot{PendingSidecars: ptrs})
	if err != nil {
		t.Fatal(err)
	}
	var back Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.PendingSidecarState()) != 1 {
		t.Fatalf("round-tripped pointers = %v", back.PendingSidecarState())
	}
}

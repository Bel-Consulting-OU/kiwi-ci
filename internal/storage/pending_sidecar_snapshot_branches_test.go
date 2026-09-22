package storage

// Branch coverage for the durable pending-sidecar pointer codec: the
// malformed-key and malformed-value rejections plus the "nothing durable to
// write" outcomes that keep the snapshot field omitted.

import (
	"testing"
	"time"
)

// TestPendingSidecarKeyDecodeRejectsMalformedKeys pins the decode guard: only
// the exact four-NUL-separated shape with a non-empty job id, a non-empty
// kind and a numeric generation is a pending identity. Every other shape
// yields ok=false so a corrupt key is dropped instead of being written.
func TestPendingSidecarKeyDecodeRejectsMalformedKeys(t *testing.T) {
	valid := PendingSidecarKey("job-a", 3, "bin", ArtifactSidecarKindSBOM)
	jobID, generation, artifact, kind, ok := decodePendingSidecarKey(valid)
	if !ok || jobID != "job-a" || generation != 3 || artifact != "bin" || kind != ArtifactSidecarKindSBOM {
		t.Fatalf("valid key decoded to (%q, %d, %q, %q, %v)", jobID, generation, artifact, kind, ok)
	}
	for name, key := range map[string]string{
		"empty":               "",
		"too-few-parts":       "job-a\x001\x00bin",
		"too-many-parts":      "job-a\x001\x00bin\x00sbom\x00extra",
		"empty-job":           "\x001\x00bin\x00sbom",
		"empty-kind":          "job-a\x001\x00bin\x00",
		"non-numeric-gen":     PendingSidecarKey("job-a", 1, "bin", ArtifactSidecarKindSBOM)[:len("job-a")] + "\x00nope\x00bin\x00sbom",
		"generation-not-int":  "job-a\x00\x00bin\x00sbom",
		"generation-overflow": "job-a\x009999999999999999999999999999\x00bin\x00sbom",
	} {
		if _, _, _, _, ok := decodePendingSidecarKey(key); ok {
			t.Fatalf("%s: malformed key %q accepted", name, key)
		}
	}
	// A negative generation is still a numeric pending identity (only the
	// generation field's format is checked here).
	if _, gen, _, _, ok := decodePendingSidecarKey("job-a\x00-2\x00bin\x00sbom"); !ok || gen != -2 {
		t.Fatal("negative generation rejected by the key codec")
	}
}

// TestPendingSidecarValueDecodeMalformed pins the value codec's three
// outcomes: empty is absent, a bare (or malformed-timestamp) value is a
// digest-only legacy entry whose zero time lets the prune age it out, and an
// encoded value round-trips its timestamp.
func TestPendingSidecarValueDecodeMalformed(t *testing.T) {
	created := time.Date(2026, 5, 6, 7, 8, 9, 10, time.UTC)
	encoded := EncodePendingSidecarValue("deadbeef", created)
	digest, ts, ok := DecodePendingSidecarValue(encoded)
	if !ok || digest != "deadbeef" || !ts.Equal(created) {
		t.Fatalf("encoded value decoded to (%q, %v, %v)", digest, ts, ok)
	}
	// A value whose timestamp part is not an integer keeps the WHOLE string
	// as the digest (the legacy format), with a zero time.
	digest, ts, ok = DecodePendingSidecarValue("not-a-number\x00digest")
	if !ok || digest != "not-a-number\x00digest" || !ts.IsZero() {
		t.Fatalf("malformed timestamp decoded to (%q, %v, %v)", digest, ts, ok)
	}
	if _, _, ok := DecodePendingSidecarValue(""); ok {
		t.Fatal("empty value must be absent")
	}
}

// TestPendingSidecarStateDropsEmptyDigests: a durable pointer that cannot
// name an exact digest is not a pointer, so it never enters the restored
// map; a valid pointer restores its encoded value.
func TestPendingSidecarStateDropsEmptyDigests(t *testing.T) {
	created := time.Now().UTC()
	snap := Snapshot{PendingSidecars: []PendingSidecarPointer{
		{JobID: "no-digest", Generation: 1, Artifact: "bin", Kind: ArtifactSidecarKindSBOM, Digest: ""},
		{JobID: "job-a", Generation: 2, Artifact: "bin", Kind: ArtifactSidecarKindSigstore, Digest: "d", CreatedAt: created},
	}}
	state := snap.PendingSidecarState()
	if len(state) != 1 {
		t.Fatalf("state = %v, want only the digest-bearing pointer", state)
	}
	if got := state[PendingSidecarKey("job-a", 2, "bin", ArtifactSidecarKindSigstore)]; got != EncodePendingSidecarValue("d", created) {
		t.Fatalf("restored value = %q", got)
	}
	if _, ok := state[PendingSidecarKey("no-digest", 1, "bin", ArtifactSidecarKindSBOM)]; ok {
		t.Fatal("empty-digest pointer restored")
	}
}

// TestSnapshotPendingSidecarPointersAllMalformedIsNil: when every in-memory
// entry is malformed the rendered slice is nil, so the snapshot field stays
// omitted rather than being written as an empty list.
func TestSnapshotPendingSidecarPointersAllMalformedIsNil(t *testing.T) {
	created := time.Now().UTC()
	// Every entry is either an unparseable key (including a non-numeric
	// generation) or an empty value: none can name a durable pointer.
	allMalformed := map[string]string{
		"not-a-key":                                EncodePendingSidecarValue("d", created),
		"job-a\x00nan\x00bin\x00sbom":              EncodePendingSidecarValue("d", created),
		PendingSidecarKey("job-b", 1, "b", "sbom"): "",
	}
	if got := SnapshotPendingSidecarPointers(allMalformed); got != nil {
		t.Fatalf("all-malformed pointers = %+v, want nil", got)
	}
	// One valid entry among malformed ones is still rendered.
	withValid := map[string]string{"not-a-key": "d", PendingSidecarKey("job-c", 1, "bin", ArtifactSidecarKindSBOM): EncodePendingSidecarValue("d", created)}
	got := SnapshotPendingSidecarPointers(withValid)
	if len(got) != 1 || got[0].JobID != "job-c" {
		t.Fatalf("valid entry dropped: %+v", got)
	}
}

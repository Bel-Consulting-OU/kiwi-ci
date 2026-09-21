package storage

// Durable fs-mode pending-sidecar pointers (D4-E).
//
// FS/dev mode stores SBOM/Sigstore sidecars as immutable digest-qualified
// files (internal/server/supplychain_gate.go). The "latest accepted" pointer
// used to live only in the server's in-memory map, so after a restart a
// lookup without a digest picked the lexicographically first file of the
// generation directory — an arbitrary choice with no relationship to what
// was accepted. These types persist that pointer map inside the SAME atomic
// state snapshot as the rest of the control-plane state, so a restart
// restores the exact accepted digest; when more than one candidate exists
// with no durable pointer, resolution fails closed instead of guessing. The
// field is additive: older snapshots decode with a nil slice, and exactly
// one unambiguous on-disk file per identity remains resolvable as legacy
// state.

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// PendingSidecarPointer is one durable pending-sidecar pointer: the full
// artifact identity of a sidecar uploaded before its artifact payload (the
// same (job, lease generation, artifact, kind) identity the DB-mode
// artifact_pending_sidecars table keys on), the digest of the accepted
// sidecar bytes and when they were recorded.
type PendingSidecarPointer struct {
	JobID      string    `json:"job_id"`
	Generation int64     `json:"generation"`
	Artifact   string    `json:"artifact"`
	Kind       string    `json:"kind"`
	Digest     string    `json:"digest"`
	CreatedAt  time.Time `json:"created_at"`
}

// PendingSidecarKey renders the canonical in-memory/snapshot key of one
// pending-sidecar identity. The fields are NUL-separated so no part can be
// confused with the separator: job IDs, artifact names and kinds are
// validated separator-free and the generation is numeric.
func PendingSidecarKey(jobID string, generation int64, artifact, kind string) string {
	return jobID + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + artifact + "\x00" + kind
}

// decodePendingSidecarKey splits a key produced by PendingSidecarKey. A key
// that does not carry exactly four NUL-separated parts (or a non-numeric
// generation) is not a pending identity.
func decodePendingSidecarKey(key string) (jobID string, generation int64, artifact, kind string, ok bool) {
	parts := strings.Split(key, "\x00")
	if len(parts) != 4 || parts[0] == "" || parts[3] == "" {
		return "", 0, "", "", false
	}
	gen, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, "", "", false
	}
	return parts[0], gen, parts[2], parts[3], true
}

// EncodePendingSidecarValue packs a pending map VALUE: the creation time in
// Unix nanoseconds, NUL, the digest. The encoding is the in-memory mirror's
// canonical form; entries written in the legacy bare-digest form decode as
// digest-only (zero time) so they are pruned as stale.
func EncodePendingSidecarValue(digest string, created time.Time) string {
	return strconv.FormatInt(created.UTC().UnixNano(), 10) + "\x00" + digest
}

// DecodePendingSidecarValue unpacks a value produced by
// EncodePendingSidecarValue. ok is false only for the empty string (no
// entry); a malformed timestamp keeps the whole value as the digest, exactly
// like the legacy format, so prune can still age it out.
func DecodePendingSidecarValue(v string) (digest string, created time.Time, ok bool) {
	idx := strings.IndexByte(v, 0)
	if idx <= 0 {
		if v == "" {
			return "", time.Time{}, false
		}
		return v, time.Time{}, true
	}
	ns, err := strconv.ParseInt(v[:idx], 10, 64)
	if err != nil {
		return v, time.Time{}, true
	}
	return v[idx+1:], time.Unix(0, ns).UTC(), true
}

// PendingSidecarState returns the snapshot's durable pending-sidecar
// pointers decoded into the server's in-memory form (canonical key ->
// encoded value). Older snapshots carry no pointers and yield an empty map.
// Malformed entries (empty digest, unparseable key) are dropped: a pointer
// that cannot name an exact digest is not a pointer.
func (s Snapshot) PendingSidecarState() map[string]string {
	if len(s.PendingSidecars) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(s.PendingSidecars))
	for _, p := range s.PendingSidecars {
		if p.Digest == "" {
			continue
		}
		key := PendingSidecarKey(p.JobID, p.Generation, p.Artifact, p.Kind)
		out[key] = EncodePendingSidecarValue(p.Digest, p.CreatedAt)
	}
	return out
}

// SnapshotPendingSidecarPointers renders an in-memory pending map (canonical
// key -> encoded value) as the durable, deterministically ordered pointer
// slice the fs snapshot stores. Malformed keys/values are skipped rather
// than written, and an empty map yields nil so the field stays omitted.
func SnapshotPendingSidecarPointers(pending map[string]string) []PendingSidecarPointer {
	if len(pending) == 0 {
		return nil
	}
	keys := make([]string, 0, len(pending))
	for key := range pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]PendingSidecarPointer, 0, len(keys))
	for _, key := range keys {
		jobID, generation, artifact, kind, ok := decodePendingSidecarKey(key)
		if !ok {
			continue
		}
		digest, created, ok := DecodePendingSidecarValue(pending[key])
		if !ok || digest == "" {
			continue
		}
		out = append(out, PendingSidecarPointer{
			JobID:      jobID,
			Generation: generation,
			Artifact:   artifact,
			Kind:       kind,
			Digest:     digest,
			CreatedAt:  created,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

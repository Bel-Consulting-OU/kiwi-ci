package storage

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sort"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Completion result digest versions. New completions always write version 2
// (see model.CompletionReceipt.ResultHashVersion); version 1 is the legacy
// computation that bound only status, error and outputs. A stored receipt
// without the version column (or a pre-field fs record) reads as version 1,
// the semantic it had when it was written.
const (
	// CompletionResultHashVersionLegacy is the pre-runtime-evidence completion
	// result hash: status/error/outputs only.
	CompletionResultHashVersionLegacy = 1
	// CompletionResultHashVersionV2 binds the observed runtime evidence too,
	// so the same completion identity cannot replay with contradictory
	// runtime evidence.
	CompletionResultHashVersionV2 = 2

	completionResultDigestV2Version = "kiwi-ci/completion-result/v2"
	completionErrorDigestVersion    = "kiwi-ci/completion-result-error/v1"
	observedRuntimeDigestVersion    = "kiwi-ci/observed-runtime/v1"
)

// CompletionResultDigestV1 returns the LEGACY completion result hash, byte for
// byte the computation every server wrote before the versioned digest: SHA-256
// over the status, a NUL, the error string, a NUL and the canonical JSON of
// the outputs (encoding/json sorts map keys and the marshal error is ignored,
// exactly like the historical completionResultHash helper). It exists so a
// stored v1 receipt can be resolved against a retried completion after the
// upgrade; new completions must use CompletionResultDigestV2.
func CompletionResultDigestV1(status model.Status, errMsg string, outputs map[string]string) string {
	outJSON, _ := jsonMarshal(outputs)
	h := sha256.New()
	_, _ = io.WriteString(h, string(status))
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, errMsg)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(outJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// CompletionResultDigestV2 is the canonical, versioned completion identity
// digest. It is a SHA-256 over a length-prefixed encoding tagged
// "kiwi-ci/completion-result/v2" carrying, in stable order:
//
//   - the status string,
//   - the digest of the error string (a nested tagged SHA-256, so the raw
//     error is never part of the preimage and no error content can leak),
//   - the sorted outputs map (count, then every key/value length-prefixed),
//   - the digest of the observed runtime (nil is encoded as the literal
//     marker "nil", distinct from any non-nil runtime, including an empty
//     one).
//
// The same completion payload always encodes identically, so a replay is
// recognized exactly, while any change to status, error, outputs OR observed
// runtime yields a different digest: a retry can never replay a completion
// with contradictory runtime evidence.
func CompletionResultDigestV2(status model.Status, errMsg string, outputs map[string]string, observed *model.ObservedRuntime) string {
	h := sha256.New()
	writeLenPrefixed(h, completionResultDigestV2Version)
	writeLenPrefixed(h, string(status))
	writeLenPrefixed(h, completionErrorDigest(errMsg))
	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeUint64(h, uint64(len(keys)))
	for _, k := range keys {
		writeLenPrefixed(h, k)
		writeLenPrefixed(h, outputs[k])
	}
	if observed == nil {
		writeLenPrefixed(h, "nil")
	} else {
		writeLenPrefixed(h, "sha256:"+ObservedRuntimeDigest(observed))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// completionErrorDigest is the tagged canonical digest of one error string.
// Hashing (rather than embedding) the message keeps arbitrarily large or
// sensitive error text out of the digest preimage; the digest still binds the
// exact bytes, so a changed error is a different completion identity.
func completionErrorDigest(errMsg string) string {
	h := sha256.New()
	writeLenPrefixed(h, completionErrorDigestVersion)
	writeLenPrefixed(h, errMsg)
	return hex.EncodeToString(h.Sum(nil))
}

// ObservedRuntimeDigest is the canonical digest of a NON-NIL observed runtime:
// a length-prefixed encoding over every field in stable declaration order,
// with the string maps canonicalized by sorted key. An empty runtime is valid
// and distinct from a nil one (callers encode nil separately). The same
// capture always hashes identically, so it can be compared across retries.
func ObservedRuntimeDigest(observed *model.ObservedRuntime) string {
	if observed == nil {
		return ""
	}
	h := sha256.New()
	writeLenPrefixed(h, observedRuntimeDigestVersion)
	writeLenPrefixed(h, observed.OS)
	writeLenPrefixed(h, observed.Arch)
	writeLenPrefixed(h, observed.RuntimeName)
	writeLenPrefixed(h, observed.RuntimeVersion)
	writeLenPrefixed(h, observed.MainImage)
	writeLenPrefixed(h, observed.MainImageDigest)
	writeStringMap(h, observed.ServiceImages)
	writeStringMap(h, observed.ServiceImageDigests)
	writeStringMap(h, observed.Components)
	if observed.CapturedAt.IsZero() {
		writeLenPrefixed(h, "")
	} else {
		writeLenPrefixed(h, observed.CapturedAt.UTC().Format(time.RFC3339Nano))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// StoredAttemptObservedRuntime returns the runtime evidence a job row carries
// for the given attempt, or nil when the row does not represent that attempt
// (a re-leased job whose payload was overwritten) or is not terminal yet.
// A running row never carries the completed attempt's evidence, and a newer
// generation's evidence must never be attributed to an older receipt.
func StoredAttemptObservedRuntime(j model.Job, generation int64) *model.ObservedRuntime {
	if j.LeaseGeneration != generation || !j.Status.Terminal() {
		return nil
	}
	return j.ObservedRuntime
}

// CompletionReceiptReplayMatches reports whether a completion request replays
// the stored receipt identity (job, generation, runner), applying the
// versioned compatibility contract:
//
//   - A stored v2 receipt matches only a v2 request with the identical digest
//     (the v2 digest already binds status, error, outputs and runtime).
//   - A stored v1 (or version-less legacy) receipt matches only:
//     a request whose v1 digest matches (the request hash directly, or the v1
//     computation over the request's status/error/outputs), AND runtime
//     evidence that is nil-or-equal: the request captured nothing, or the
//     stored attempt evidence is present and canonically identical. A
//     v2-evidence-bearing retry against a legacy receipt with no (or
//     different) stored evidence is a contradiction and must conflict.
//
// requestVersion of 0 is treated as v2: every production completion caller
// computes the v2 digest, and only records persisted before the version field
// existed read back as legacy.
func CompletionReceiptReplayMatches(stored model.CompletionReceipt, requestHash string, requestVersion int, status model.Status, errMsg string, outputs map[string]string, requestObserved, storedObserved *model.ObservedRuntime) bool {
	if requestVersion <= 0 {
		requestVersion = CompletionResultHashVersionV2
	}
	if stored.ResultHashVersion >= CompletionResultHashVersionV2 {
		return requestVersion >= CompletionResultHashVersionV2 && stored.ResultHash == requestHash
	}
	matched := stored.ResultHash == requestHash
	if !matched && requestVersion >= CompletionResultHashVersionV2 {
		matched = stored.ResultHash == CompletionResultDigestV1(status, errMsg, outputs)
	}
	if !matched {
		return false
	}
	return completionLegacyRuntimeEvidenceCompatible(requestObserved, storedObserved)
}

// completionLegacyRuntimeEvidenceCompatible reports whether runtime evidence
// supplied with a retry may replay against a legacy (v1) receipt: the retry
// captured nothing (it cannot contradict the stored identity), or the stored
// attempt evidence exists and is canonically equal. A retry bearing runtime
// evidence the legacy receipt never bound is refused: that is exactly the
// masquerade the v2 digest exists to prevent.
func completionLegacyRuntimeEvidenceCompatible(request, stored *model.ObservedRuntime) bool {
	if request == nil {
		return true
	}
	if stored == nil {
		return false
	}
	return ObservedRuntimeDigest(request) == ObservedRuntimeDigest(stored)
}

// writeLenPrefixed writes an 8-byte big-endian length followed by the bytes.
func writeLenPrefixed(w io.Writer, s string) {
	writeUint64(w, uint64(len(s)))
	_, _ = io.WriteString(w, s)
}

// writeUint64 writes v big-endian.
func writeUint64(w io.Writer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, _ = w.Write(b[:])
}

// writeStringMap canonically encodes a string map: count, then every key and
// value length-prefixed in sorted key order.
func writeStringMap(w io.Writer, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeUint64(w, uint64(len(keys)))
	for _, k := range keys {
		writeLenPrefixed(w, k)
		writeLenPrefixed(w, m[k])
	}
}

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

// Completion result digest versions. Current completions write version 3
// (see model.CompletionReceipt.ResultHashVersion); version 2 is the
// historical frozen format that first bound observed runtime evidence;
// version 1 is the legacy computation that bound only status, error and
// outputs. A stored receipt without the version column (or a pre-field fs
// record) reads as version 1, the semantic it had when it was written.
const (
	// CompletionResultHashVersionLegacy is the pre-runtime-evidence completion
	// result hash: status/error/outputs only.
	CompletionResultHashVersionLegacy = 1
	// CompletionResultHashVersionV2 binds the observed runtime evidence too,
	// so the same completion identity cannot replay with contradictory
	// runtime evidence. FROZEN: nested observed-runtime/v1 encoding (no
	// Control receipt). Never change this algorithm — historical receipts
	// must keep verifying and replaying byte-for-byte.
	CompletionResultHashVersionV2 = 2
	// CompletionResultHashVersionV3 binds the observed runtime INCLUDING the
	// executor-observed enforcement receipt (Control). New completions write
	// v3. Verification dispatches on the STORED ResultHashVersion so a v2
	// receipt is always checked with the frozen v2 algorithm.
	CompletionResultHashVersionV3 = 3

	completionResultDigestV2Version = "kiwi-ci/completion-result/v2"
	completionResultDigestV3Version = "kiwi-ci/completion-result/v3"
	completionErrorDigestVersion    = "kiwi-ci/completion-result-error/v1"
)

// ObservedRuntimeDigestV1Version tags the FROZEN historical observed-runtime
// digest encoding (every field except the Control receipt).
const ObservedRuntimeDigestV1Version = "kiwi-ci/observed-runtime/v1"

// ObservedRuntimeDigestV2Version tags the current observed-runtime digest
// encoding (v1 fields PLUS the executor-observed Control receipt).
const ObservedRuntimeDigestV2Version = "kiwi-ci/observed-runtime/v2"

// CompletionResultDigestV1 returns the LEGACY completion result hash, byte for
// byte the computation every server wrote before the versioned digest: SHA-256
// over the status, a NUL, the error string, a NUL and the canonical JSON of
// the outputs (encoding/json sorts map keys and the marshal error is ignored,
// exactly like the historical completionResultHash helper). It exists so a
// stored v1 receipt can be resolved against a retried completion after the
// upgrade; current completions must use CompletionResultDigestV3.
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

// CompletionResultDigestV2 is the FROZEN v2 completion identity digest
// (tagged "kiwi-ci/completion-result/v2") using the historical
// observed-runtime/v1 encoding (no Control receipt). New completions must
// use CompletionResultDigestV3; this function exists so stored v2 receipts
// can be matched exactly as their producer wrote them.
//
// It is a SHA-256 over a length-prefixed encoding carrying, in stable order:
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
		writeLenPrefixed(h, "sha256:"+ObservedRuntimeDigestV1(observed))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CompletionResultDigestV3 is the current completion identity digest
// (tagged "kiwi-ci/completion-result/v3"). Same field order as v2 except the
// nested observed-runtime digest is v2 and therefore binds Control.
func CompletionResultDigestV3(status model.Status, errMsg string, outputs map[string]string, observed *model.ObservedRuntime) string {
	h := sha256.New()
	writeLenPrefixed(h, completionResultDigestV3Version)
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

// ObservedRuntimeDigestV1 is the FROZEN historical observed-runtime digest
// ("kiwi-ci/observed-runtime/v1"): every field except the Control receipt.
// CompletionResultDigestV2 embeds this. Never change it.
func ObservedRuntimeDigestV1(observed *model.ObservedRuntime) string {
	if observed == nil {
		return ""
	}
	h := sha256.New()
	writeLenPrefixed(h, ObservedRuntimeDigestV1Version)
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

// ObservedRuntimeDigest is the current observed-runtime digest
// ("kiwi-ci/observed-runtime/v2"): v1 fields PLUS the executor-observed
// enforcement receipt (Control). CompletionResultDigestV3 embeds this so a
// retry cannot replay with contradictory sandbox/network/quota observations.
func ObservedRuntimeDigest(observed *model.ObservedRuntime) string {
	if observed == nil {
		return ""
	}
	h := sha256.New()
	writeLenPrefixed(h, ObservedRuntimeDigestV2Version)
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
	if observed.Control == nil {
		writeLenPrefixed(h, "")
	} else {
		writeLenPrefixed(h, observed.Control.Runtime)
		writeLenPrefixed(h, boolToken(observed.Control.SandboxStarted))
		writeLenPrefixed(h, string(observed.Control.NetworkEnforced))
		writeLenPrefixed(h, boolToken(observed.Control.RootFilesystemReadOnly))
		writeLenPrefixed(h, boolToken(observed.Control.WorkspaceQuotaEnforced))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func boolToken(b bool) string {
	if b {
		return "1"
	}
	return "0"
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

// CurrentCompletionResultHashVersion is the version new completion receipts
// write. Verification always dispatches on the STORED version so an older
// receipt keeps matching under the algorithm its producer used.
const CurrentCompletionResultHashVersion = CompletionResultHashVersionV3

// ReplayRequiresHistoricalObservedRuntime reports whether replay matching a
// stored receipt of this version needs historical observed-runtime recovery
// (reading the job row / attempt evidence). Only the true legacy v1 path
// needs it: v1 bound only status/error/outputs, so the nil-or-equal runtime
// rule must be checked against the stored attempt. Frozen v2 already binds
// runtime (observed-runtime/v1) and v3 binds runtime+Control — their
// receipts are self-sufficient and must not depend on another subsystem
// (provenance, DB) for an identical replay. Adding v4 must use this helper,
// never `version < Current`.
func ReplayRequiresHistoricalObservedRuntime(storedVersion int) bool {
	return storedVersion < CompletionResultHashVersionV2
}

// CurrentCompletionResultDigest is the digest new completion receipts store.
func CurrentCompletionResultDigest(status model.Status, errMsg string, outputs map[string]string, observed *model.ObservedRuntime) string {
	return CompletionResultDigestV3(status, errMsg, outputs, observed)
}

// CompletionReceiptReplayMatches reports whether a completion request replays
// the stored receipt identity (job, generation, runner).
//
// The request payload is re-hashed under the STORED ResultHashVersion — never
// under the current algorithm alone — so a receipt written by an older
// binary keeps matching across upgrades (compatibility firewall). Version
// contract:
//
//   - v3: CompletionResultDigestV3 (status, error, outputs, runtime incl. Control)
//   - v2: FROZEN CompletionResultDigestV2 (status, error, outputs, runtime/v1)
//   - v1/legacy: status/error/outputs only, plus nil-or-equal runtime evidence
//     compared with the FROZEN runtime/v1 encoding (Control was not part of
//     that contract).
func CompletionReceiptReplayMatches(stored model.CompletionReceipt, requestHash string, requestVersion int, status model.Status, errMsg string, outputs map[string]string, requestObserved, storedObserved *model.ObservedRuntime) bool {
	if requestVersion <= 0 {
		requestVersion = CompletionResultHashVersionV2
	}
	switch stored.ResultHashVersion {
	case CompletionResultHashVersionV3:
		if stored.ResultHash == requestHash && requestVersion >= CompletionResultHashVersionV3 {
			return true
		}
		return stored.ResultHash == CompletionResultDigestV3(status, errMsg, outputs, requestObserved)
	case CompletionResultHashVersionV2:
		// Exact identity replay (same request hash at v2 or newer), or a
		// HEAD recomputation under the FROZEN v2 algorithm so an older
		// receipt keeps matching across upgrades.
		if stored.ResultHash == requestHash && requestVersion >= CompletionResultHashVersionV2 {
			return true
		}
		return stored.ResultHash == CompletionResultDigestV2(status, errMsg, outputs, requestObserved)
	default:
		matched := stored.ResultHash == CompletionResultDigestV1(status, errMsg, outputs) || stored.ResultHash == requestHash
		if !matched {
			return false
		}
		return completionLegacyRuntimeEvidenceCompatible(requestObserved, storedObserved)
	}
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
	// Legacy receipts bound runtime without Control; compare the frozen v1
	// encoding so a retry that now carries Control still matches when the
	// historical fields agree.
	return ObservedRuntimeDigestV1(request) == ObservedRuntimeDigestV1(stored)
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

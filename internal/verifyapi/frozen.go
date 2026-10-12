package verifyapi

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// FROZEN canonical encoding.
//
// The acceptance MAC input and the v2 content digests are built with the
// length-prefixed field encoding below — never with encoding/json over Go
// structs. json.Marshal is opportunistic: field order follows the struct
// definition, so an innocent field insert or reorder silently changes every
// digest and MAC. The encoding here is part of the durable contract: the
// field list and order below are FROZEN and may only change together with a
// version bump (AcceptanceVersionV2 / the frozen domain string).
//
// Wire shape of one frozen buffer:
//
//	domain-tag (length-prefixed UTF-8)
//	field*
//
// where every field is a length-prefixed byte string (uint64 BE length, then
// the bytes). Numbers and timestamps are rendered to their canonical text
// form before being written as strings. Maps are emitted with sorted keys.

// frozenBuffer accumulates a FROZEN canonical encoding.
type frozenBuffer struct {
	buf []byte
}

// str appends one length-prefixed UTF-8 field.
func (f *frozenBuffer) str(s string) {
	f.raw([]byte(s))
}

// raw appends one length-prefixed byte field.
func (f *frozenBuffer) raw(b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	f.buf = append(f.buf, n[:]...)
	f.buf = append(f.buf, b...)
}

// int64 appends the canonical decimal form of v as one field.
func (f *frozenBuffer) int64(v int64) {
	f.str(fmt.Sprintf("%d", v))
}

// bool appends "true"/"false" as one field.
func (f *frozenBuffer) bool(v bool) {
	if v {
		f.str("true")
		return
	}
	f.str("false")
}

// time appends the RFC3339Nano UTC rendering of t as one field. The zero
// instant renders as the empty string so a missing timestamp is distinct
// from any real one.
func (f *frozenBuffer) time(t time.Time) {
	if t.IsZero() {
		f.str("")
		return
	}
	f.str(t.UTC().Format(time.RFC3339Nano))
}

// timePtr appends an optional timestamp (empty field when nil/zero).
func (f *frozenBuffer) timePtr(t *time.Time) {
	if t == nil {
		f.str("")
		return
	}
	f.time(*t)
}

// strings appends a list as: count, then each element length-prefixed.
func (f *frozenBuffer) strings(items []string) {
	f.int64(int64(len(items)))
	for _, s := range items {
		f.str(s)
	}
}

// digests appends a digest list as: count, then each digest.
func (f *frozenBuffer) digests(items []Digest) {
	f.int64(int64(len(items)))
	for _, d := range items {
		f.str(string(d))
	}
}

// sortedMap appends a string map with keys in sorted order: count, then
// key/value pairs. Sorting makes the encoding independent of map iteration.
func (f *frozenBuffer) sortedMap(m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f.int64(int64(len(keys)))
	for _, k := range keys {
		f.str(k)
		f.str(m[k])
	}
}

// domain opens a frozen buffer with its domain tag.
func frozenDomain(tag string) *frozenBuffer {
	f := &frozenBuffer{}
	f.str(tag)
	return f
}

// frozenDigestLabel is the per-type label mixed into every v2 content digest
// so two different types can never collide even if their field lists match.
const frozenDigestLabel = "kiwi-ci/frozen-digest/v1"

// frozenHash returns the domain-separated SHA-256 of the frozen buffer.
func (f *frozenBuffer) frozenHash(label string) (Digest, error) {
	h := sha256.New()
	h.Write([]byte(frozenDigestLabel + "/" + label + "\n"))
	h.Write(f.buf)
	return Digest(hex.EncodeToString(h.Sum(nil))), nil
}

// ---- frozen encoders for the digested contract types ----
//
// Field order is FROZEN. Do not reorder, insert, or remove fields without
// bumping AcceptanceVersionV2 and the acceptance domain.

// encodeObligationFrozen is the v2 canonical encoding of a verification
// obligation.
func encodeObligationFrozen(o VerificationObligation) *frozenBuffer {
	f := frozenDomain("obligation/v2")
	f.str(o.ObligationID)
	f.str(o.Subject)
	encodeSubjectRefFrozen(f, o.SubjectRef)
	f.str(string(o.ImmutableCandidateDigest))
	f.str(string(o.SourceSnapshotDigest))
	f.str(string(o.VerificationContractDigest))
	f.strings(o.RequiredChecks)
	f.str(o.RequiredAssurance)
	f.timePtr(o.Freshness.NotBefore)
	f.int64(o.Freshness.MaxAgeSeconds)
	f.timePtr(o.Freshness.NotAfter)
	f.sortedMap(o.OpaqueCorrelationMetadata)
	f.time(o.IssuedAt)
	return f
}

// encodeSubjectRefFrozen appends the (possibly absent) authority subject.
func encodeSubjectRefFrozen(f *frozenBuffer, s *SubjectRef) {
	if s == nil {
		f.str("")
		return
	}
	f.str(s.AuthorityNamespace)
	f.str(s.TenantID)
	f.str(s.ProjectID)
	f.str(s.RepositoryID)
}

// encodeOutcomeFrozen is the v2 canonical encoding of a verification outcome
// (used for both the submitted claim digest and the authoritative outcome
// digest — the surrounding label separates the two).
func encodeOutcomeFrozen(v VerificationOutcome) *frozenBuffer {
	f := frozenDomain("outcome/v2")
	f.str(v.VerificationID)
	f.str(v.ObligationID)
	f.str(string(v.CandidateDigest))
	f.str(string(v.SnapshotDigest))
	f.str(string(v.ContractDigest))
	f.str(string(v.Outcome))
	f.str(v.AssuranceProfile)
	f.strings(v.CompletedChecks)
	f.strings(v.ExecutionIDs)
	f.str(string(v.EvidenceRoot))
	encodeResourcesFrozen(f, v.Resources)
	f.time(v.StartedAt)
	f.time(v.CompletedAt)
	f.strings(v.ProvenanceRefs)
	return f
}

// encodeResourcesFrozen appends the resource-fact block in frozen order.
func encodeResourcesFrozen(f *frozenBuffer, r ResourceFacts) {
	f.int64(r.QueueLatencyNS)
	f.int64(r.ExecutionLatencyNS)
	f.int64(r.WallTimeNS)
	f.int64(r.CPUTimeNS)
	f.int64(r.PeakMemoryBytes)
	f.int64(r.IOBytes)
	f.int64(r.CacheHits)
	f.int64(r.CacheMisses)
	f.str(r.RunnerClass)
	f.int64(int64(r.RetryCount))
	f.bool(r.Cancelled)
	f.bool(r.DuplicateAvoided)
	f.bool(r.Speculative)
	f.str(r.VerificationGroupID)
	f.str(r.CandidateID)
	// Measured is substrate-filled at record time and is deliberately NOT
	// part of the frozen identity: it never participates in a digest.
	if r.Measured == nil {
		f.str("")
		return
	}
	f.int64(r.Measured.DurationNS)
	f.int64(r.Measured.WallTimeNS)
}

// encodeEvidenceFrozen is the v2 canonical encoding of resolved evidence.
func encodeEvidenceFrozen(e VerifiedEvidence) *frozenBuffer {
	f := frozenDomain("evidence/v2")
	f.strings(e.ExecutionIDs)
	f.str(string(e.EvidenceRoot))
	f.digests(e.AttestationDigests)
	if e.Attested == nil {
		f.str("")
	} else {
		f.str("window")
		f.time(e.Attested.StartedAt)
		f.time(e.Attested.FinishedAt)
	}
	f.str(e.JobStatus)
	f.strings(e.CompletedChecks)
	encodeChecksFrozen(f, e.VerifiedChecks)
	encodeAssuranceFrozen(f, e.Assurance)
	if e.ObservedControls == nil {
		f.str("")
	} else {
		f.str("observed")
		f.str(e.ObservedControls.Runtime)
		f.bool(e.ObservedControls.SandboxStarted)
		f.str(string(e.ObservedControls.NetworkEnforced))
		f.bool(e.ObservedControls.RootFilesystemReadOnly)
		f.bool(e.ObservedControls.WorkspaceQuotaEnforced)
	}
	f.str(e.VerifierIdentity)
	f.time(e.VerifiedAt)
	return f
}

// encodeChecksFrozen appends the evidence-derived verified check list.
func encodeChecksFrozen(f *frozenBuffer, checks []VerifiedCheck) {
	f.int64(int64(len(checks)))
	for _, c := range checks {
		f.str(c.Name)
		f.str(string(c.Outcome))
		f.str(string(c.EvidenceDigest))
		f.str(c.ExecutionID)
	}
}

// encodeAssuranceFrozen appends the derived assurance profile.
func encodeAssuranceFrozen(f *frozenBuffer, a model.ExecutionAssurance) {
	f.str(a.Name())
}

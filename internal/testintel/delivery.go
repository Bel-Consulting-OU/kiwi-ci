package testintel

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// Durable test-report delivery identity.
//
// The runner posts /tests once and only warns on failure, and the server used
// to mint a fresh report ID per request, so a committed-but-unacknowledged
// upload followed by a retry double-inserted the report and double-folded the
// repository history. The delivery identity below is the stable,
// content-derived name of one report delivery; the server records it next to
// the report and folds history in ONE transaction, so a replay of the same
// bytes is an idempotent success and a reused name with different bytes is an
// explicit conflict.
//
// The digest is taken over the exact JSON payload bytes the runner sends in
// the "report" field (deterministic for one model.TestReport value, and
// re-sent byte-identically by retries). The delivery ID binds the job, the
// lease generation and the content digest, so the same report can never be
// replayed across lease generations of the same job, and the same delivery
// name can never be replayed with different content.

// ReportContentDigest returns the hex SHA-256 of one canonical report payload
// (the JSON bytes of the "report" field). The server recomputes this digest
// from the bytes it actually received and refuses to trust a client-supplied
// digest that disagrees.
func ReportContentDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// ReportDeliveryID derives the stable delivery identity of one report
// upload: hex SHA-256 of (jobID, lease generation, content digest), each
// length-delimited by a NUL byte so the parts can never be confused for one
// another. Retrying the same report under the same lease computes the same
// ID; a different report or lease generation computes a different one.
func ReportDeliveryID(jobID string, leaseGeneration int64, contentDigest string) string {
	h := sha256.New()
	h.Write([]byte(jobID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(leaseGeneration, 10)))
	h.Write([]byte{0})
	h.Write([]byte(contentDigest))
	return hex.EncodeToString(h.Sum(nil))
}

// DeliveryReportID derives the deterministic report ID for a delivery in
// stores that have no delivery table (the in-memory dev-mode server). It is a
// 128-bit hex ID in the same shape as newID(), derived from the delivery's
// FULL identity — job, lease generation and delivery ID, each NUL-delimited
// so the parts can never be confused for one another. The delivery table keys
// on (job_id, lease_generation, delivery_id), so scoping the synthesized
// report ID identically means two different jobs (or generations) that reuse
// one delivery ID can never collide on a single record, while a retried
// delivery still maps to exactly one record.
func DeliveryReportID(jobID string, leaseGeneration int64, deliveryID string) string {
	h := sha256.New()
	h.Write([]byte("kiwi-ci/report-delivery"))
	h.Write([]byte{0})
	h.Write([]byte(jobID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(leaseGeneration, 10)))
	h.Write([]byte{0})
	h.Write([]byte(deliveryID))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// ValidReportDeliveryID reports whether a client-supplied delivery ID is
// acceptable: 1..128 characters of an opaque-but-safe alphabet. The runner
// always sends a 64-character hex SHA-256; the validation exists so an
// adversarial client cannot store unbounded or hazardous keys.
func ValidReportDeliveryID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

package storage

// SQL-shape pins for the durable queue-deadline predicate every claim
// re-asserts (Round-11 finding B). The behaviour is covered end to end by the
// scheduler's PostgreSQL integration test; these assert the SHAPE so a future
// edit cannot quietly drop the deadline predicate from either claim path (the
// atomic claim used in production and the legacy non-atomic claim).

import (
	"strings"
	"testing"
)

func TestClaimQueueDeadlinePredicateSQLShape(t *testing.T) {
	if !strings.Contains(queuedClaimDeadlinePredicateSQL, "queue_deadline IS NULL") {
		t.Fatalf("deadline predicate = %q, want the NULL-means-unbounded arm", queuedClaimDeadlinePredicateSQL)
	}
	if !strings.Contains(queuedClaimDeadlinePredicateSQL, "queue_deadline > clock_timestamp()") {
		t.Fatalf("deadline predicate = %q, want the DATABASE-clock comparison", queuedClaimDeadlinePredicateSQL)
	}

	claims := map[string]string{
		"AcquireLease":       acquireLeaseClaimSQL,
		"AcquireLeaseAtomic": acquireLeaseAtomicClaimSQL,
	}
	for name, sql := range claims {
		if !strings.Contains(sql, queuedClaimDeadlinePredicateSQL) {
			t.Fatalf("%s claim SQL is missing the durable deadline predicate:\n%s", name, sql)
		}
		if !strings.Contains(sql, "status='queued'") {
			t.Fatalf("%s claim SQL no longer gates on queued status:\n%s", name, sql)
		}
		if !strings.Contains(sql, "(lease_expires_at IS NULL OR lease_expires_at < clock_timestamp())") {
			t.Fatalf("%s claim SQL lost the lease-expiry predicate:\n%s", name, sql)
		}
	}
	// The atomic claim keeps the TTL-derived database-clock expiry arm.
	if !strings.Contains(acquireLeaseAtomicClaimSQL, "$6::bigint") ||
		!strings.Contains(acquireLeaseAtomicClaimSQL, "clock_timestamp() + ($6::bigint * interval '1 microsecond')") {
		t.Fatalf("atomic claim SQL lost the TTL expiry arm:\n%s", acquireLeaseAtomicClaimSQL)
	}
	// The legacy claim keeps the quarantine and parent-run guards.
	if !strings.Contains(acquireLeaseClaimSQL, "repo_identity_quarantined") ||
		!strings.Contains(acquireLeaseClaimSQL, LeaseParentRunEligibleSQL) {
		t.Fatalf("legacy claim SQL lost its fail-closed guards:\n%s", acquireLeaseClaimSQL)
	}
}

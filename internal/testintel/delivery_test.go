package testintel

import (
	"strings"
	"testing"
)

// TestReportDeliveryIDStableAndContentBound pins the durable-delivery
// identity: the same (job, generation, digest) always derives the same
// 64-character hex ID, and changing ANY part derives a different one.
func TestReportDeliveryIDStableAndContentBound(t *testing.T) {
	digest := ReportContentDigest([]byte(`{"tests":1}`))
	if len(digest) != 64 {
		t.Fatalf("content digest = %d chars, want 64", len(digest))
	}
	id := ReportDeliveryID("job-1", 3, digest)
	if len(id) != 64 {
		t.Fatalf("delivery id = %d chars, want 64", len(id))
	}
	if again := ReportDeliveryID("job-1", 3, digest); again != id {
		t.Fatalf("delivery id not stable: %s vs %s", id, again)
	}
	if other := ReportDeliveryID("job-1", 4, digest); other == id {
		t.Fatal("lease generation is not part of the delivery identity")
	}
	if other := ReportDeliveryID("job-2", 3, digest); other == id {
		t.Fatal("job id is not part of the delivery identity")
	}
	if other := ReportDeliveryID("job-1", 3, ReportContentDigest([]byte(`{"tests":2}`))); other == id {
		t.Fatal("content digest is not part of the delivery identity")
	}
	// The NUL-delimited parts cannot be confused for one another: shifting
	// bytes between job id and generation must not collide.
	if ReportDeliveryID("a\x001", 0, digest) == ReportDeliveryID("a", 1, digest) {
		t.Fatal("delivery id parts are delimiter-ambiguous")
	}
}

// TestDeliveryReportIDDeterministic pins the memory-mode deterministic report
// ID: stable per full delivery identity and distinct across any part change.
func TestDeliveryReportIDDeterministic(t *testing.T) {
	id := DeliveryReportID("job-1", 5, "abc")
	if len(id) != 32 {
		t.Fatalf("deterministic report id = %d chars, want 32", len(id))
	}
	if again := DeliveryReportID("job-1", 5, "abc"); again != id {
		t.Fatalf("deterministic report id changed: %s vs %s", id, again)
	}
	if other := DeliveryReportID("job-1", 5, "abd"); other == id {
		t.Fatal("different deliveries derived the same report id")
	}
	// G1-B: the report ID is scoped by job and generation exactly like the
	// durable delivery key, so two jobs (or generations) reusing one delivery
	// ID can never collide on a single memory-mode record.
	if other := DeliveryReportID("job-2", 5, "abc"); other == id {
		t.Fatal("two jobs reusing a delivery id collided on one report id")
	}
	if other := DeliveryReportID("job-1", 6, "abc"); other == id {
		t.Fatal("two generations reusing a delivery id collided on one report id")
	}
	// NUL-delimited parts cannot be confused for one another.
	if DeliveryReportID("a\x001", 0, "x") == DeliveryReportID("a", 1, "x") {
		t.Fatal("delivery report id parts are delimiter-ambiguous")
	}
}

// TestValidReportDeliveryID pins the client-supplied delivery name bounds.
func TestValidReportDeliveryID(t *testing.T) {
	for _, ok := range []string{"a", strings.Repeat("f", 64), "A.b_c:d-e"} {
		if !ValidReportDeliveryID(ok) {
			t.Fatalf("delivery id %q rejected", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("f", 129), "has space", "sl/ash", "semi;colon", "nul\x00byte", "unicodé"} {
		if ValidReportDeliveryID(bad) {
			t.Fatalf("delivery id %q accepted", bad)
		}
	}
}

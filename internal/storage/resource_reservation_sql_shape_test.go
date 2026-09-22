package storage

// Unit pins for the generated SQL of the reservation guards (K6-A), the
// legacy service-envelope policy (K6-C) and the live-row predicate (K6-B).
// The behaviour is covered by the real-PostgreSQL integration tests
// (postgres_reservation_guard_it_test.go,
// postgres_reservation_selfheal_it_test.go); these assert the SHAPE so a
// future edit cannot quietly reintroduce a character-class-only cast guard, a
// SUM that counts orphan rows, or an envelope read without the conservative
// legacy arm.

import (
	"strings"
	"testing"
)

func TestResourceRequestSQLGuardShape(t *testing.T) {
	sql := resourceRequestSQL

	// Every dimension is type-guarded by jsonb_typeof, never by a
	// character-class regex on the text alone. Four per dimension: the own
	// read, the envelope read, the own read repeated by the legacy arm, and
	// the legacy arm's services-array type check.
	if got := strings.Count(sql, "jsonb_typeof("); got != 16 {
		t.Fatalf("jsonb_typeof guards = %d, want 16 (4 dimensions x own + envelope + legacy own + legacy services)", got)
	}
	if strings.Contains(sql, "^[0-9.eE+-]+$") {
		t.Fatal("the magnitude-unsafe character-class regex guard is back")
	}
	// The integer dimensions require a plain non-negative digit string (Go
	// decode parity) and every domain is bounded.
	for _, want := range []string{
		"'^[0-9]+$'",
		"BETWEEN 0 AND 1.7976931348623157e308", // cpu: float64 domain
		"BETWEEN 0 AND 9223372036854775807",    // memory/disk: BIGINT
		"BETWEEN 0 AND 2147483647",             // pids: INTEGER
		"::double precision",
		"::bigint",
		"::int",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("resourceRequestSQL is missing the guard %q", want)
		}
	}
	if got := strings.Count(sql, "BETWEEN 0 AND 9223372036854775807"); got != 6 {
		t.Fatalf("BIGINT bounds = %d, want 6 (memory and disk x own, legacy own, envelope)", got)
	}
	// The legacy arm: envelope key absence + container runtime + a declared
	// service, charged the own request a second time.
	if !strings.Contains(sql, "j.payload ? 'service_envelope_request'") {
		t.Fatal("resourceRequestSQL no longer branches on the envelope key's presence")
	}
	if !strings.Contains(sql, "compiled_job_payload,effective_job,job,services") ||
		!strings.Contains(sql, "compiled_job_payload,effective_job,job,runtime") {
		t.Fatal("resourceRequestSQL is missing the legacy compiled-job paths")
	}
	if strings.Count(sql, "compiled_job_payload,effective_job,job,services") != 8 {
		t.Fatalf("services path occurrences = %d, want 8 (2 per dimension: type check + length)", strings.Count(sql, "compiled_job_payload,effective_job,job,services"))
	}
}

func TestLiveReservationExistsSQLShape(t *testing.T) {
	for _, want := range []string{
		"j.id = r.job_id",
		"j.status = 'running'",
		"COALESCE(j.lease_runner_id, '') <> ''",
		"j.lease_generation = r.generation",
	} {
		if !strings.Contains(liveReservationExistsSQL, want) {
			t.Fatalf("liveReservationExistsSQL is missing %q", want)
		}
	}
}

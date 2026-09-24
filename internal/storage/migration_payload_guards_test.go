package storage

// Unit pins (no PostgreSQL) for the G5-A migration payload-cast guards. These
// are deliberately string-level: a regression that reintroduces a bare cast
// into 0009/0010/0022 must fail here even before an integration run.

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

func TestMigrationPayloadCastGuards(t *testing.T) {
	cases := []struct {
		file  string
		wants []string
		// absent are substrings that must NOT appear (the pre-fix hazard).
		absent []string
	}{
		{
			file: "0009_lease_claim.sql",
			wants: []string{
				"jsonb_typeof(payload->'disabled') = 'boolean'",
				"jsonb_typeof(payload->'draining') = 'boolean'",
			},
			absent: []string{"SET disabled = COALESCE((payload->>'disabled')::boolean"},
		},
		{
			file: "0010_generation_outbox_artifact_consistency.sql",
			wants: []string{
				"jsonb_typeof(payload->'lease_generation') = 'number'",
				"'^-?[0-9]+$'",
				"BETWEEN (-9223372036854775808)::numeric AND (9223372036854775807)::numeric",
			},
			absent: []string{"job_generation = COALESCE((payload->>'lease_generation')::bigint"},
		},
		{
			file: "0022_jobs_recovery_queue_deadline_backfill.sql",
			wants: []string{
				"jsonb_typeof(payload->'queue_deadline') = 'string'",
				"~ '^(?!0000)",
				// Real calendar validation, not just the date prefix.
				"(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])",
				"(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)",
				"-02-(?:0[1-9]|1[0-9]|2[0-8])",
				"-02-29)T",
				"[0-5][0-9]:[0-5][0-9]",
			},
			absent: []string{`~ '^\d{4}-\d{2}-\d{2}'`},
		},
	}
	for _, tc := range cases {
		raw, err := migrations.FS.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		sql := string(raw)
		for _, want := range tc.wants {
			if !strings.Contains(sql, want) {
				t.Errorf("%s missing guard %q", tc.file, want)
			}
		}
		for _, absent := range tc.absent {
			if strings.Contains(sql, absent) {
				t.Errorf("%s still carries the pre-fix unguarded cast %q", tc.file, absent)
			}
		}
	}
}

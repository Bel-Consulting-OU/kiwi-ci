package testintel

import (
	"encoding/json"
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Shared report-ingestion limits. These are the ONE definition of the size
// contract every layer must agree on:
//
//   - the JUnit parser (AggregateMasked/ParseMasked) enforces the per-file,
//     per-job total, case-count and retained-message limits while reading the
//     workspace;
//   - the runner's pre-upload check serializes the aggregated report and
//     rejects a payload/request over the shared budget BEFORE the upload
//     call;
//   - the /tests endpoint decodes with an endpoint-specific cap equal to
//     MaxTestReportRequestBytes (the generic 8 MiB decode cap of every other
//     endpoint is untouched).
//
// The budget is deliberately a practical AGGREGATE one: at most
// MaxJobReportBytes of matched input and MaxJobCases retained cases per job,
// instead of the old 500,000-cases x 64 KiB theoretical ceiling (which no
// server endpoint could ever receive). A report the parser accepts therefore
// always fits the endpoint's request budget, so Kiwi can no longer parse a
// report it can never receive.
const (
	// MaxReportFileBytes is the largest single JUnit XML file the parser
	// opens (enforced before any content is read).
	MaxReportFileBytes = 8 << 20 // 8 MiB per file
	// MaxJobReportBytes is the largest SUM of matched JUnit XML bytes one job
	// may aggregate across all of its report patterns.
	MaxJobReportBytes = 16 << 20 // 16 MiB total input per job
	// MaxReportCases is the largest number of test cases in ONE JUnit file.
	MaxReportCases = 50_000
	// MaxJobCases is the largest number of test cases in one job's aggregated
	// report, across every matched file.
	MaxJobCases = 100_000
	// MaxMessageBytes bounds the retained failure/error text per case: the
	// combined message + body of a <failure> or <error> is truncated to this
	// many bytes before it is stored or uploaded.
	MaxMessageBytes = 64 << 10 // 64 KiB per retained message
	// MaxReportFiles bounds how many files all patterns of one job may match
	// together.
	MaxReportFiles = 1024

	// MaxTestReportRequestBytes is the shared TOTAL-bytes limit of one
	// report delivery: the serialized report plus the /tests request
	// envelope. The /tests endpoint decodes with exactly this cap, and the
	// runner pre-check measures the exact request body against it.
	MaxTestReportRequestBytes = 16 << 20 // 16 MiB request body
	// MaxTestReportEnvelopeBytes is the reserved allowance for the request
	// fields around "report" (runner_id, lease_token, lease_generation,
	// delivery_id, content_digest, JSON punctuation). The report PAYLOAD
	// budget below leaves this much room, so a payload at its limit always
	// yields a request body within MaxTestReportRequestBytes.
	MaxTestReportEnvelopeBytes = 4 << 10 // 4 KiB envelope allowance
	// MaxTestReportPayloadBytes is the largest serialized model.TestReport
	// payload the parser produces and the runner uploads. It is exactly the
	// request budget minus the envelope allowance, so the parser, the
	// runner's pre-check and the endpoint decode cap all reject the same
	// boundary.
	MaxTestReportPayloadBytes = MaxTestReportRequestBytes - MaxTestReportEnvelopeBytes

	// Testcase identity bounds. model.TestResult.Name/.Class and the suite
	// identity (a report's JobKey, which migration 0026 uses as the `suite`
	// column) are unbounded producer strings, but PostgreSQL indexes them:
	// test_history_aggregates is a b-tree primary key on
	// (repo_id, suite, test_class, test_name), and a tuple whose key exceeds
	// the page limit (about 2704 bytes on an 8 KiB page) makes an otherwise
	// valid report fail the aggregate upsert. The three columns are
	// therefore bounded to 512 bytes each: 4 x 512 bytes plus per-column
	// tuple headers stays far below the b-tree key limit even if the
	// canonical repository identity is itself a few hundred bytes, while
	// every realistic JUnit class/test name (Java nested classes, Go
	// package paths, table-driven case names) fits comfortably. The bounds
	// are enforced identically by the parser and by
	// ValidateReportPayload, so a direct /tests submission cannot bypass
	// them; an over-limit identity rejects the report with a clear
	// ErrLimitExceeded reason instead of reaching SQL.
	MaxTestNameBytes  = 512
	MaxTestClassBytes = 512
	MaxTestSuiteBytes = 512
)

// ValidateReportPayload is the SHARED, authoritative enforcement of the
// report contract on an already-aggregated report:
//
//   - every declared counter lies in [0, MaxJobCases];
//   - Failures+Errors+Skipped <= Tests (the three outcomes partition Tests,
//     so their sum — not each counter individually — must fit);
//   - len(Cases) <= Tests (a report may declare more tests than it
//     materialized, never fewer than its cases);
//   - Failures+Errors >= the materialized failing cases and Skipped >= the
//     materialized skipped cases (case-derived lower bounds; the model
//     collapses <failure> and <error> into one non-passing case, so the
//     failing observations are bounded as a pair);
//   - no case is both Passed and Skipped;
//   - identities, durations and retained message bytes are bounded, and the
//     serialized payload fits MaxTestReportPayloadBytes.
//
// It is called by the parser after aggregation, by the runner's pre-upload
// check and by the /tests handler after decoding, so a report just over any
// shared limit is rejected with the same ErrLimitExceeded reason at every
// layer. The numeric policy matters even though the JUnit parser sanitizes: a
// lease-authenticated runner can POST a model.TestReport directly to /tests,
// and its counters and durations flow into SQL, metrics and EWMA state, so
// this validator is the trust boundary regardless of the producer. The parser
// additionally enforces the input-side limits (per-file bytes, per-file
// cases, matched files and total input bytes) that only exist while reading
// files, and truncates retained messages to MaxMessageBytes rather than
// rejecting a producer's oversized failure text.
// hasForbiddenControlByte reports whether s contains a byte XML 1.0 cannot
// represent: a C0 control character other than tab (0x09), newline (0x0A) or
// carriage return (0x0D). NUL is the dangerous case (PostgreSQL text cannot
// store U+0000, so a report that reaches SQL fails with 22P05), but every
// other forbidden control byte is rejected too, because the XML parser already
// refuses it: without this check a direct /tests submission could carry a byte
// the JUnit parser can never produce, so parser, validator and the in-memory
// store would disagree about what a valid report is.
func hasForbiddenControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\t' || c == '\n' || c == '\r':
		case c < 0x20:
			return true
		}
	}
	return false
}

func ValidateReportPayload(rep model.TestReport) error {
	// Counter bounds. Every declared counter is an int that flows into SQL
	// int columns, the aggregate fold and metrics, so it must be inside the
	// job's case budget: MaxJobCases bounds every counter both ways
	// (negative counts are producer garbage and 64-bit values above the
	// budget would overflow the SQL int column or fabricate history no
	// materialized case explains).
	for _, c := range []struct {
		name  string
		value int
	}{
		{"tests", rep.Tests},
		{"failures", rep.Failures},
		{"errors", rep.Errors},
		{"skipped", rep.Skipped},
	} {
		if c.value < 0 {
			return fmt.Errorf("%w: report declares a negative %s counter (%d)", ErrLimitExceeded, c.name, c.value)
		}
		if c.value > MaxJobCases {
			return fmt.Errorf("%w: report declares %s=%d, over the %d-case job budget", ErrLimitExceeded, c.name, c.value, MaxJobCases)
		}
	}
	// Counter RELATIONS. The three outcome counters partition the tests, so
	// their SUM (not each individually) must fit inside tests: failures=8,
	// errors=8, skipped=8 with tests=10 is contradictory even though every
	// individual counter is within tests.
	if int64(rep.Failures)+int64(rep.Errors)+int64(rep.Skipped) > int64(rep.Tests) {
		return fmt.Errorf("%w: failures+errors+skipped (%d+%d+%d) exceeds tests (%d)", ErrLimitExceeded, rep.Failures, rep.Errors, rep.Skipped, rep.Tests)
	}
	// The declared test count is authoritative: a report may declare more
	// tests than it materialized (truncated case lists are legal), but never
	// fewer than the cases it actually carries.
	if len(rep.Cases) > rep.Tests {
		return fmt.Errorf("%w: %d materialized cases exceed the declared tests counter (%d)", ErrLimitExceeded, len(rep.Cases), rep.Tests)
	}
	if !validDuration(rep.Duration) {
		return fmt.Errorf("%w: report duration %v is not finite, non-negative and at most %v seconds", ErrLimitExceeded, rep.Duration, float64(maxReportDuration))
	}
	if len(rep.JobKey) > MaxTestSuiteBytes {
		return fmt.Errorf("%w: suite identity is %d bytes, over the %d-byte suite budget", ErrLimitExceeded, len(rep.JobKey), MaxTestSuiteBytes)
	}
	if hasForbiddenControlByte(rep.JobKey) {
		return fmt.Errorf("%w: suite identity contains a NUL or control byte", ErrLimitExceeded)
	}
	if len(rep.Cases) > MaxJobCases {
		return fmt.Errorf("%w: %d cases exceeds the %d-case job budget", ErrLimitExceeded, len(rep.Cases), MaxJobCases)
	}
	// CASE-DERIVED LOWER BOUNDS. The materialized cases are what the
	// historical fold observes, so no counter may be SMALLER than the cases
	// that explain it. A skipped case (Passed=false, Skipped=true) is a skip
	// and nothing else; a case with Passed=false and Skipped=false is a
	// FAILURE or an ERROR — model.TestResult deliberately collapses the
	// JUnit <failure>/<error> distinction into one non-passing outcome, so
	// the faithful lower bound is the PAIR bound
	// Failures+Errors >= failing cases (a direct submission can neither
	// under-state the failing observations nor claim a failing case is a
	// pass), together with Skipped >= skipped cases. The parser's suite
	// derivation satisfies exactly this bound.
	var skippedCases, failingCases int
	for i, c := range rep.Cases {
		if c.Passed && c.Skipped {
			return fmt.Errorf("%w: case %d is both passed and skipped", ErrLimitExceeded, i)
		}
		if c.Skipped {
			skippedCases++
		} else if !c.Passed {
			failingCases++
		}
		if len(c.Name) > MaxTestNameBytes {
			return fmt.Errorf("%w: case %d name is %d bytes, over the %d-byte name budget", ErrLimitExceeded, i, len(c.Name), MaxTestNameBytes)
		}
		if hasForbiddenControlByte(c.Name) {
			return fmt.Errorf("%w: case %d name contains a NUL or control byte", ErrLimitExceeded, i)
		}
		if len(c.Class) > MaxTestClassBytes {
			return fmt.Errorf("%w: case %d class is %d bytes, over the %d-byte class budget", ErrLimitExceeded, i, len(c.Class), MaxTestClassBytes)
		}
		if hasForbiddenControlByte(c.Class) {
			return fmt.Errorf("%w: case %d class contains a NUL or control byte", ErrLimitExceeded, i)
		}
		if !validDuration(c.Duration) {
			return fmt.Errorf("%w: case %d duration %v is not finite, non-negative and at most %v seconds", ErrLimitExceeded, i, c.Duration, float64(maxReportDuration))
		}
		if len(c.Message) > MaxMessageBytes {
			return fmt.Errorf("%w: case %d message is %d bytes, over the %d-byte message budget", ErrLimitExceeded, i, len(c.Message), MaxMessageBytes)
		}
		if hasForbiddenControlByte(c.Message) {
			return fmt.Errorf("%w: case %d message contains a NUL or control byte", ErrLimitExceeded, i)
		}
	}
	if skippedCases > rep.Skipped {
		return fmt.Errorf("%w: %d materialized skipped cases exceed the skipped counter (%d)", ErrLimitExceeded, skippedCases, rep.Skipped)
	}
	if int64(failingCases) > int64(rep.Failures)+int64(rep.Errors) {
		return fmt.Errorf("%w: %d materialized failing cases exceed failures+errors (%d+%d)", ErrLimitExceeded, failingCases, rep.Failures, rep.Errors)
	}
	payload, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	if len(payload) > MaxTestReportPayloadBytes {
		return fmt.Errorf("%w: serialized report is %d bytes, over the %d-byte payload budget", ErrLimitExceeded, len(payload), MaxTestReportPayloadBytes)
	}
	return nil
}

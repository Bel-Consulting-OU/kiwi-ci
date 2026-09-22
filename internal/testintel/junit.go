// Package testintel parses test reports (JUnit XML), aggregates them into
// per-job report models, and maintains flaky-test history with deterministic
// duration-balanced sharding.
package testintel

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// The hard ingestion limits live in limits.go: MaxReportFileBytes,
// MaxJobReportBytes, MaxReportCases, MaxJobCases, MaxMessageBytes and
// MaxReportFiles, plus the shared request/payload budgets the server and the
// runner enforce. Every layer (parser, runner pre-check, /tests decode) uses
// those constants, so there is exactly one size contract.
//
// Sanitize, don't reject: producer-declared METADATA that exceeds a shared
// budget is clamped at the parser-side aggregation points (budgetCounters,
// clampDuration) exactly like a negative counter or an oversized failure
// message is sanitized. AggregateMasked validates its own output with the
// shared validator (limits.go) and the runner warn-only discards the WHOLE
// aggregated report set when that validation fails, so an absurd declared
// counter must cost the producer its excess claim, never the cases the
// report did materialize. ValidateReportPayload itself stays strict for a
// direct /tests submission, where the declared values ARE the payload and no
// parser has sanitized them.
const (
	// maxReportDuration is the largest suite/case/report duration (in
	// seconds, about 31.7 years) accepted from a report. A single
	// non-finite, negative or larger value is dropped to 0 (see
	// sanitizeDuration); a SUM of individually valid durations (many suites
	// in one file, or many files in one job) is clamped to this shared
	// maximum at the aggregation points (see clampDuration), because a job
	// may legitimately merge many suites whose separate times each sit at
	// the bound.
	maxReportDuration = 1e9
)

// Suite is one <testsuite> element. Counts are the attributes when present
// and are recomputed from the cases when a producer omits them.
type Suite struct {
	Name     string  `json:"name,omitempty"`
	Tests    int     `json:"tests"`
	Failures int     `json:"failures,omitempty"`
	Errors   int     `json:"errors,omitempty"`
	Skipped  int     `json:"skipped,omitempty"`
	Time     float64 `json:"time,omitempty"`
	Cases    []Case  `json:"cases,omitempty"`
}

// Case is one <testcase> element. Failure and Error share the Failure shape
// (message attribute plus body chardata); Skipped carries an optional
// message attribute.
type Case struct {
	Name      string   `xml:"name,attr"`
	Class     string   `xml:"classname,attr"`
	Time      float64  `xml:"time,attr"`
	Failure   *Failure `xml:"failure"`
	Error     *Failure `xml:"error"`
	Skipped   *Skipped `xml:"skipped"`
	SystemErr string   `xml:"system-err"`
}

// Failure is a <failure> or <error> element.
type Failure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

// Skipped is a <skipped> element.
type Skipped struct {
	Message string `xml:"message,attr"`
}

// Report is the merged result of parsing one or more JUnit files.
type Report struct {
	Suites   []Suite
	Tests    int
	Failures int
	Errors   int
	Skipped  int
	Duration float64
	Cases    []Case
}

// ErrLimitExceeded reports that a report exceeded an ingestion limit.
var ErrLimitExceeded = errors.New("test report exceeds limits")

// Parse parses one JUnit file into a Report. The file must be a regular
// file (symlinks, sockets and devices are rejected) no larger than
// MaxReportFileBytes.
func Parse(path string) (Report, error) {
	return ParseMasked(path, nil)
}

// ParseMasked parses one JUnit file, applying mask to failure/error
// messages and system-err excerpts before they are retained. A nil mask
// keeps content verbatim.
func ParseMasked(path string, mask func(string) string) (Report, error) {
	var out Report
	fi, err := os.Lstat(path)
	if err != nil {
		return out, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return out, fmt.Errorf("test report %s: symlinks are not allowed", path)
	}
	if fi.Size() > MaxReportFileBytes {
		return out, fmt.Errorf("%w: %s larger than %d bytes", ErrLimitExceeded, path, MaxReportFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	// Stat after open: the descriptor describes the actual object, so even
	// if the path was swapped for a device between Lstat and Open the
	// regular-file check still holds.
	st, err := f.Stat()
	if err != nil {
		return out, err
	}
	if !st.Mode().IsRegular() {
		return out, fmt.Errorf("test report %s: not a regular file", path)
	}
	return parseReport(f, path, mask)
}

// parseReport decodes one already-opened, verified regular JUnit file. It is
// the shared body of ParseMasked and of the root-anchored aggregate path:
// parseReport never opens, stats or closes anything, so callers that reach a
// file through a held workspace descriptor keep that no-follow contract.
func parseReport(r io.Reader, name string, mask func(string) string) (Report, error) {
	var out Report
	dec := xml.NewDecoder(r)
	cases := 0
	seen := false
	for {
		tok, derr := dec.Token()
		if derr == io.EOF {
			break
		}
		if derr != nil {
			return out, fmt.Errorf("parse %s: %w", name, derr)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "testsuites", "testsuite":
			seen = true
			suites, serr := readSuiteElement(dec, se, mask, &cases)
			if serr != nil {
				return out, fmt.Errorf("parse %s: %w", name, serr)
			}
			for _, s := range suites {
				appendSuite(&out, s)
			}
		case "testcase":
			seen = true
			c, cerr := readCase(dec, se, mask, &cases)
			if cerr != nil {
				return out, fmt.Errorf("parse %s: %w", name, cerr)
			}
			s := Suite{Name: name, Tests: 1, Time: c.Time, Cases: []Case{c}}
			// Skipped wins over a co-occurring failure/error: the case is
			// modeled as skipped (model.TestResult.Skipped=true), so the
			// declared counters must classify it the same way or the report
			// would contradict the shared validator's case-derived bounds.
			switch {
			case c.Skipped != nil:
				s.Skipped = 1
			case c.Failure != nil:
				s.Failures = 1
			case c.Error != nil:
				s.Errors = 1
			}
			appendSuite(&out, s)
		default:
			if err := dec.Skip(); err != nil {
				return out, fmt.Errorf("parse %s: %w", name, err)
			}
		}
	}
	if !seen {
		return out, fmt.Errorf("parse %s: not a JUnit report (no testsuite/testcase elements)", name)
	}
	finalizeReport(&out)
	return out, nil
}

// readSuiteElement reads one <testsuite> element (recursing into nested
// suites) or a <testsuites> wrapper, returning every suite it contains.
func readSuiteElement(dec *xml.Decoder, se xml.StartElement, mask func(string) string, cases *int) ([]Suite, error) {
	if se.Name.Local == "testsuites" {
		var suites []Suite
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				switch t.Name.Local {
				case "testsuite":
					nested, nerr := readSuiteElement(dec, t, mask, cases)
					if nerr != nil {
						return nil, nerr
					}
					suites = append(suites, nested...)
				case "testcase":
					c, cerr := readCase(dec, t, mask, cases)
					if cerr != nil {
						return nil, cerr
					}
					s := Suite{Name: "testsuites", Tests: 1, Time: c.Time, Cases: []Case{c}}
					// Skipped wins over a co-occurring failure/error (see the
					// case-level synthesis above).
					switch {
					case c.Skipped != nil:
						s.Skipped = 1
					case c.Failure != nil:
						s.Failures = 1
					case c.Error != nil:
						s.Errors = 1
					}
					suites = append(suites, s)
				default:
					if err := dec.Skip(); err != nil {
						return nil, err
					}
				}
			case xml.EndElement:
				if t.Name.Local == "testsuites" {
					return suites, nil
				}
			}
		}
	}
	var s Suite
	s.Name = attrValue(se, "name")
	// The suite name is an indexed identity component in the persisted
	// aggregates (migration 0026 keys on (repo_id, suite, test_class,
	// test_name)), so it obeys the same shared byte budget as the case
	// identities. The file-path-derived suite names of case-level reports
	// are not affected: only a producer-declared testsuite name is checked.
	if len(s.Name) > MaxTestSuiteBytes {
		return nil, fmt.Errorf("%w: testsuite name is %d bytes, over the %d-byte suite budget", ErrLimitExceeded, len(s.Name), MaxTestSuiteBytes)
	}
	s.Tests, _ = attrInt(se, "tests")
	s.Failures, _ = attrInt(se, "failures")
	s.Errors, _ = attrInt(se, "errors")
	s.Skipped, _ = attrInt(se, "skipped")
	s.Time, _ = attrFloat(se, "time")
	var extra []Suite
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "testcase":
				c, cerr := readCase(dec, t, mask, cases)
				if cerr != nil {
					return nil, cerr
				}
				s.Cases = append(s.Cases, c)
			case "testsuite":
				nested, nerr := readSuiteElement(dec, t, mask, cases)
				if nerr != nil {
					return nil, nerr
				}
				extra = append(extra, nested...)
			default:
				if err := dec.Skip(); err != nil {
					return nil, err
				}
			}
		case xml.EndElement:
			if t.Name.Local == "testsuite" {
				finalizeSuite(&s)
				return append([]Suite{s}, extra...), nil
			}
		}
	}
}

// caseXML is the decode mirror of Case used by readCase. It differs only in
// carrying the time attribute as a string: decoding straight into Case.Time
// would make encoding/xml reject the whole report for a malformed or
// out-of-range duration, while every other duration in a report is dropped
// to 0 by the numeric policy. The remaining fields are identical to Case.
type caseXML struct {
	Name      string   `xml:"name,attr"`
	Class     string   `xml:"classname,attr"`
	Time      string   `xml:"time,attr"`
	Failure   *Failure `xml:"failure"`
	Error     *Failure `xml:"error"`
	Skipped   *Skipped `xml:"skipped"`
	SystemErr string   `xml:"system-err"`
}

// readCase decodes one <testcase> element, applies the duration policy,
// masking and truncation, and enforces the per-report case limit.
func readCase(dec *xml.Decoder, se xml.StartElement, mask func(string) string, cases *int) (Case, error) {
	var cx caseXML
	if err := dec.DecodeElement(&cx, &se); err != nil {
		return Case{}, err
	}
	// Identity strings are indexed (migration 0026's
	// (repo_id, suite, test_class, test_name) primary key), so they are
	// bounded, not truncated: a truncated identity would silently merge two
	// distinct tests into one aggregate row, which is worse than rejecting
	// the report. The validator enforces the same bounds on the model, so a
	// parser-accepted report always passes validation.
	if len(cx.Name) > MaxTestNameBytes {
		return Case{}, fmt.Errorf("%w: testcase name is %d bytes, over the %d-byte name budget", ErrLimitExceeded, len(cx.Name), MaxTestNameBytes)
	}
	if len(cx.Class) > MaxTestClassBytes {
		return Case{}, fmt.Errorf("%w: testcase class is %d bytes, over the %d-byte class budget", ErrLimitExceeded, len(cx.Class), MaxTestClassBytes)
	}
	c := Case{
		Name:      cx.Name,
		Class:     cx.Class,
		Failure:   cx.Failure,
		Error:     cx.Error,
		Skipped:   cx.Skipped,
		SystemErr: cx.SystemErr,
	}
	if cx.Time != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(cx.Time), 64); err == nil {
			c.Time = sanitizeDuration(f)
		}
	}
	// Order matters: mask the raw producer text FIRST, then bound the
	// retained parts. Masking a truncated string could leave a secret that
	// straddled the byte boundary unmasked in what is kept, and the two
	// parts are bounded as the ONE joined text the model retains (see
	// truncateFailure). applyMask already truncates after masking.
	if mask != nil {
		applyMask(&c, mask)
	} else {
		truncateCase(&c)
	}
	*cases++
	if *cases > MaxReportCases {
		return c, fmt.Errorf("%w: more than %d cases", ErrLimitExceeded, MaxReportCases)
	}
	return c, nil
}

// appendSuite merges one suite into the report totals. The suite is
// finalized here a second time (idempotently, see budgetCounters), and the
// report duration stays inside the shared maximum while merging because one
// file may sum many individually valid suite times.
func appendSuite(out *Report, s Suite) {
	finalizeSuite(&s)
	out.Suites = append(out.Suites, s)
	out.Tests += s.Tests
	out.Failures += s.Failures
	out.Errors += s.Errors
	out.Skipped += s.Skipped
	out.Duration = clampDuration(out.Duration + s.Time)
	out.Cases = append(out.Cases, s.Cases...)
}

// counterFloors carries the case-derived lower bounds budgetCounters must
// preserve: the materialized case count, the exclusive failure/error
// classification floors and the failing/skipped floors the shared validator
// enforces.
type counterFloors struct {
	cases    int // materialized cases: tests >= cases
	failures int // failure-only materialized cases: failures >= failures
	errors   int // error-only materialized cases: errors >= errors
	failing  int // any materialized failing case: failures+errors >= failing
	skipped  int // materialized skipped cases: skipped >= skipped
}

// budgetCounters is the ONE implementation of the parser-side counter
// policy, shared by the per-suite (finalizeSuite), per-file (finalizeReport)
// and per-job (AggregateMasked) aggregation points so none of them can
// reconcile differently. It derives the counters from the materialized
// cases, CLAMPS every producer-declared counter into the shared job budget
// [0, MaxJobCases], and reconciles the declared values into the relation the
// shared ValidateReportPayload enforces, so the parser can never emit a
// report its own validator rejects and the runner never discards an
// aggregate it parsed itself.
//
// Sanitize, don't reject: a counter above MaxJobCases is producer garbage
// exactly like a negative counter or an oversized failure message, so it is
// clamped into the budget instead of being allowed to fail the parse.
// ValidateReportPayload itself stays strict for a direct /tests submission,
// where the declared values are the payload and no parser has sanitized
// them. A negative producer counter is dropped to zero exactly like an
// invalid duration.
//
// The clamp runs AFTER the floors deliberately: the floors are materialized
// evidence, and clamping one down would leave the report smaller than the
// cases it carries (the validator rejects "materialized cases exceed the
// declared tests counter"). Every caller guarantees fl.cases <= MaxJobCases
// — readCase rejects a file over MaxReportCases and AggregateMasked rejects
// a job the moment its materialized cases would exceed MaxJobCases — so the
// clamp can only ever remove declared excess, never a floor. A materialized
// case list genuinely over the job budget is an input-size breach enforced
// per case at ingestion, NOT a declared counter for this policy to
// sanitize.
//
// The reconciliation exists because the declared counters and the
// materialized cases can disagree in two ways:
//
//   - skipped wins over a co-occurring failure/error (the model folds such a
//     case as skipped, see the case-level synthesis), so a case the producer
//     counted as a failure is a skip here;
//   - the model collapses <failure> and <error> into ONE non-passing
//     observation, so a producer that counts one failing case in BOTH
//     declared counters still explains only one materialized case.
//
// Either makes failures+errors+skipped exceed tests. The rule:
//
//  1. Tests is raised to the number of materialized cases; a report may
//     declare more tests than it materialized, never fewer.
//  2. Each declared failure/error counter is raised to its exclusive
//     classification floor (failure-only cases for Failures, error-only cases
//     for Errors), and the PAIR floor — failures+errors must cover every
//     non-skipped failing case, however it was spelled — is topped up on
//     Failures (deterministic; the fold observes the pair, not the
//     classification).
//  3. Skipped is raised to the skipped case count and clamped to
//     tests - failing cases: a declared skip can never displace a
//     materialized failure. The floor always fits because skipped and
//     failing cases are disjoint materialized cases (skipped + failing <=
//     len(Cases) <= tests).
//  4. If the declared pair still exceeds tests - skipped, the excess is
//     conceded by Errors first, then Failures, never below the case-derived
//     floors. Errors is the deterministic concession order; the exclusive
//     floors keep a failure-only or error-only case's own counter, so only
//     the unsupported claim is dropped.
//
// The result always satisfies the validator's counter relation and
// case-derived lower bounds: failures+errors+skipped <= tests, with
// failures+errors >= the materialized failing cases and skipped >= the
// materialized skipped cases. Every step is a monotone clamp against a
// case-derived floor, so budgetCounters is IDEMPOTENT: a suite is finalized
// once when its element closes and again in appendSuite, and the second pass
// must not change the reconciliation.
func budgetCounters(tests, failures, errors, skipped int, fl counterFloors) (int, int, int, int) {
	if tests < 0 {
		tests = 0
	}
	if failures < 0 {
		failures = 0
	}
	if errors < 0 {
		errors = 0
	}
	if skipped < 0 {
		skipped = 0
	}
	if tests < fl.cases {
		tests = fl.cases
	}
	if failures < fl.failures {
		failures = fl.failures
	}
	if errors < fl.errors {
		errors = fl.errors
	}
	// The pair top-up compares budget-clamped operands: two MaxInt producer
	// counters would overflow an int, and any operand above MaxJobCases is
	// about to be clamped anyway. Because the pair floor is itself a
	// materialized count bounded by MaxJobCases, an operand at the budget
	// already covers the floor, so the condition and the top-up are
	// identical to the raw comparison while never overflowing (and the
	// top-up then only ever operates on in-budget values).
	if pair := min(failures, MaxJobCases) + min(errors, MaxJobCases); pair < fl.failing {
		failures += fl.failing - pair
	}
	if skipped < fl.skipped {
		skipped = fl.skipped
	}
	// The shared budget clamp, AFTER the floors (see the doc comment).
	tests = min(tests, MaxJobCases)
	failures = min(failures, MaxJobCases)
	errors = min(errors, MaxJobCases)
	skipped = min(skipped, MaxJobCases)
	if maxSkip := tests - fl.failing; skipped > maxSkip {
		// maxSkip >= fl.skipped: skipped and failing cases are disjoint
		// materialized cases, so fl.skipped <= fl.cases-fl.failing and the
		// clamp never cuts tests below fl.cases.
		skipped = maxSkip
	}
	if over := failures + errors - (tests - skipped); over > 0 {
		if drop := min(over, errors-fl.errors); drop > 0 {
			errors -= drop
			over -= drop
		}
		if over > 0 {
			// Feasible: tests-skipped >= fl.failing >=
			// fl.failures+fl.errors, so the remaining excess never exceeds
			// Failures' reducible claim.
			failures -= min(over, failures-fl.failures)
		}
	}
	return tests, failures, errors, skipped
}

// finalizeSuite prepares one parsed suite before it is merged into a report:
// it derives the case-derived floors from the materialized cases (skipped
// wins over a co-occurring failure/error: the model marks such a case
// Skipped and the fold ignores it) and applies budgetCounters, which also
// clamps the producer-declared counters into the shared job budget. It is
// idempotent, because appendSuite finalizes the suite a second time.
func finalizeSuite(s *Suite) {
	var failOnly, errOnly, failing, skip int
	for _, c := range s.Cases {
		switch {
		case c.Skipped != nil:
			skip++
		case c.Failure != nil && c.Error != nil:
			failing++
		case c.Failure != nil:
			failOnly++
			failing++
		case c.Error != nil:
			errOnly++
			failing++
		}
	}
	s.Tests, s.Failures, s.Errors, s.Skipped = budgetCounters(s.Tests, s.Failures, s.Errors, s.Skipped, counterFloors{
		cases:    len(s.Cases),
		failures: failOnly,
		errors:   errOnly,
		failing:  failing,
		skipped:  skip,
	})
}

// finalizeReport applies the same budget policy to one file's report totals
// after every suite was merged: the declared counters are clamped into the
// job budget (with the file's materialized cases as floors) and the summed
// duration is clamped to the shared maximum. finalizeSuite keeps each suite
// internally consistent, but one file may merge many suites and
// AggregateMasked sums many files, so every aggregation level clamps before
// handing the next level a report.
func finalizeReport(out *Report) {
	var failing, skipped int
	for _, c := range out.Cases {
		switch {
		case c.Skipped != nil:
			skipped++
		case c.Failure != nil || c.Error != nil:
			failing++
		}
	}
	out.Tests, out.Failures, out.Errors, out.Skipped = budgetCounters(out.Tests, out.Failures, out.Errors, out.Skipped, counterFloors{
		cases:   len(out.Cases),
		failing: failing,
		skipped: skipped,
	})
	out.Duration = clampDuration(out.Duration)
}

// clampDuration bounds a SUM of individually valid durations (a file's suite
// times, or a job's file totals) to the shared maximum. Many suites may each
// be validly near maxReportDuration while their sum is far above it, and the
// shared validator measures exactly this bound on the report total: like the
// counter clamp, the total is pinned at the budget instead of rejecting the
// parse. A single declared value above the bound is still producer garbage
// and is dropped to 0 by sanitizeDuration.
func clampDuration(total float64) float64 {
	return min(total, maxReportDuration)
}

func applyMask(c *Case, mask func(string) string) {
	if c.Failure != nil {
		c.Failure.Message = mask(c.Failure.Message)
		c.Failure.Body = mask(c.Failure.Body)
	}
	if c.Error != nil {
		c.Error.Message = mask(c.Error.Message)
		c.Error.Body = mask(c.Error.Body)
	}
	c.SystemErr = mask(c.SystemErr)
	truncateCase(c)
}

func truncateCase(c *Case) {
	truncateFailure(c.Failure)
	truncateFailure(c.Error)
}

// truncateFailure bounds ONE <failure>/<error> element to the shared message
// budget. The contract is the JOINED text the model retains (message + "\n" +
// body, see retainedFailureText): the budget applies to the combination, not
// to each part, because the validator measures exactly the joined value. The
// separator is therefore charged against the budget too — that one byte is
// what used to let a 40 KiB message plus a 40 KiB body survive the per-part
// caps, join to 64 KiB + 1 byte and then be rejected by this package's own
// validator. Message is kept as the priority (it is the producer's summary)
// and only the remainder is left to the body.
func truncateFailure(f *Failure) {
	if f == nil {
		return
	}
	if len(f.Message) > MaxMessageBytes {
		f.Message = f.Message[:MaxMessageBytes]
	}
	keep := MaxMessageBytes - len(f.Message)
	if f.Body != "" && len(f.Message) > 0 {
		keep-- // the join's newline separator
	}
	if keep < 0 {
		keep = 0
	}
	if len(f.Body) > keep {
		f.Body = f.Body[:keep]
	}
}

// retainedFailureText combines a failure/error message and body into the ONE
// retained text model.TestResult carries, in the order the contract
// requires: combine (and mask, which the caller already applied) FIRST, then
// truncate ONCE to MaxMessageBytes. Joining and trimming before the cut is
// what makes the retained value always exactly within the budget the
// validator enforces, whatever the part sizes.
func retainedFailureText(message, body string) string {
	combined := strings.TrimSpace(message + "\n" + body)
	if len(combined) > MaxMessageBytes {
		combined = combined[:MaxMessageBytes]
	}
	return combined
}

func attrValue(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func attrInt(se xml.StartElement, name string) (int, bool) {
	v := attrValue(se, name)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

func attrFloat(se xml.StartElement, name string) (float64, bool) {
	v := attrValue(se, name)
	if v == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || !validDuration(f) {
		return 0, false
	}
	return f, true
}

// validDuration is the numeric policy for suite and case durations: only
// finite, non-negative values within maxReportDuration are usable. NaN,
// ±Inf, negatives and absurdly large values are producer garbage: a NaN
// makes every later comparison false and would survive arithmetic into
// totals, and Inf/negative values poison duration balancing.
func validDuration(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 && f <= maxReportDuration
}

// sanitizeDuration applies the numeric policy by dropping an invalid
// duration to 0 instead of failing the report: durations are producer
// metadata, so a malformed value must not reject an otherwise valid report,
// but it must never reach sums or the API either. Zero is the same default a
// missing time attribute gets, so dropping records nothing invalid.
func sanitizeDuration(f float64) float64 {
	if !validDuration(f) {
		return 0
	}
	return f
}

// Within reports whether path (already cleaned) is lexically inside
// workspace: the relative path must not escape with ".." and must not be
// absolute.
func Within(workspace, path string) bool {
	rel, err := filepath.Rel(workspace, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Aggregate parses every JUnit file matching the given workspace-relative
// globs and merges them into one per-job report for flaky-test history and
// future test splitting. It is equivalent to AggregateMasked with a nil
// mask. Patterns are resolved component by component beneath the workspace
// root without ever following a symlink; matched files are opened through a
// held workspace root descriptor with the no-follow discipline, so a
// symlinked parent directory or final file can never make the host collector
// read outside the workspace.
func Aggregate(workspace string, patterns []string) (model.TestReport, error) {
	return AggregateMasked(workspace, patterns, nil)
}

// AggregateMasked is Aggregate with a secret-masking hook applied to
// failure/error messages and system-err excerpts. The mask must be safe for
// concurrent use when the caller shares it with other goroutines; the runner
// passes secrets.Masker.Mask, which takes a read lock. A file matched by
// several patterns is parsed exactly once: the candidate set is deduplicated
// by workspace-relative path before the file cap, byte accounting and case
// accounting run, so overlapping globs can neither double-count nor double-
// parse a report.
func AggregateMasked(workspace string, patterns []string, mask func(string) string) (model.TestReport, error) {
	root, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return model.TestReport{}, fmt.Errorf("test reports: open workspace %s: %w", workspace, err)
	}
	defer root.Close()
	var files []string
	// Overlapping patterns are deduplicated by workspace-relative path
	// before the file is materialized: "reports/*.xml" and
	// "reports/unit.xml" would otherwise parse unit.xml twice, doubling its
	// counters, cases and byte accounting. The candidate paths are already
	// root-relative and cleaned (reportCandidates), so the path is the
	// identity.
	seen := make(map[string]bool)
	for _, p := range patterns {
		matches, err := reportCandidates(root, p)
		if err != nil {
			return model.TestReport{}, err
		}
		for _, m := range matches {
			if seen[m] {
				continue
			}
			seen[m] = true
			files = append(files, m)
		}
	}
	sort.Strings(files)
	if len(files) > MaxReportFiles {
		return model.TestReport{}, fmt.Errorf("%w: %d matched report files exceeds the %d file cap", ErrLimitExceeded, len(files), MaxReportFiles)
	}
	// Size every match through the no-follow workspace root before any
	// content is parsed: the total-byte cap must hold even when the leading
	// files would each parse cleanly. Each descriptor is closed immediately
	// so a large match set cannot exhaust file descriptors.
	var total int64
	for _, rel := range files {
		f, size, err := openReport(root, rel)
		if err != nil {
			return model.TestReport{}, err
		}
		f.Close()
		total += size
		if total > MaxJobReportBytes {
			return model.TestReport{}, fmt.Errorf("%w: matched reports exceed %d bytes total", ErrLimitExceeded, MaxJobReportBytes)
		}
	}
	out := model.TestReport{}
	for _, rel := range files {
		f, _, err := openReport(root, rel)
		if err != nil {
			return model.TestReport{}, err
		}
		rep, err := parseReport(f, rel, mask)
		f.Close()
		if err != nil {
			return model.TestReport{}, err
		}
		if out.Path == "" {
			out.Path = rel
		} else {
			out.Path += ", " + rel
		}
		out.Tests += rep.Tests
		out.Failures += rep.Failures
		out.Errors += rep.Errors
		out.Skipped += rep.Skipped
		out.Duration += rep.Duration
		for _, c := range rep.Cases {
			r := model.TestResult{Name: c.Name, Class: c.Class, Duration: c.Time, Passed: c.Failure == nil && c.Error == nil && c.Skipped == nil, Skipped: c.Skipped != nil}
			if c.Failure != nil {
				r.Message = retainedFailureText(c.Failure.Message, c.Failure.Body)
			} else if c.Error != nil {
				r.Message = retainedFailureText(c.Error.Message, c.Error.Body)
			}
			if len(out.Cases) >= MaxJobCases {
				return model.TestReport{}, fmt.Errorf("%w: more than %d cases per job", ErrLimitExceeded, MaxJobCases)
			}
			out.Cases = append(out.Cases, r)
		}
	}
	// Job-level budget sanitization, the same sanitize-not-reject policy as
	// finalizeSuite/finalizeReport: each file's totals were clamped already,
	// but a job sums many files, so the declared counters are clamped into
	// the job budget again with the job's OWN materialized cases as floors,
	// and the summed duration is clamped to the shared maximum. Without this
	// clamp an over-declared counter or a summed suite duration would make
	// the aggregate fail its own validation just below, and the runner would
	// warn-only discard the whole report set.
	var failingCases, skippedCases int
	for _, c := range out.Cases {
		switch {
		case c.Skipped:
			skippedCases++
		case !c.Passed:
			failingCases++
		}
	}
	out.Tests, out.Failures, out.Errors, out.Skipped = budgetCounters(out.Tests, out.Failures, out.Errors, out.Skipped, counterFloors{
		cases:   len(out.Cases),
		failing: failingCases,
		skipped: skippedCases,
	})
	out.Duration = clampDuration(out.Duration)
	// The serialized form is what the runner uploads and what the /tests
	// endpoint must decode: enforce the shared payload contract HERE, with
	// the exact encoding the runner sends, so the parser can never accept a
	// report the endpoint would have to reject for size. The payload budget
	// already reserves the request-envelope allowance, so an at-limit payload
	// always fits MaxTestReportRequestBytes.
	if err := ValidateReportPayload(out); err != nil {
		return model.TestReport{}, err
	}
	return out, nil
}

// openReport opens one workspace-relative report candidate through the held
// workspace root and returns the descriptor plus its verified size. OpenRel
// rejects absolute paths, parent traversal, symlinked parents and symlinked
// final components (its O_NOFOLLOW open plays the role of ParseMasked's
// final-component Lstat symlink check), and fstat-verifies the descriptor is
// a regular file, so every check the path-based ParseMasked makes still holds
// here without any path-component race. The per-file byte cap is enforced
// before the caller reads any content; the caller owns the returned
// descriptor.
func openReport(root *safefs.WorkspaceRoot, rel string) (*os.File, int64, error) {
	f, err := root.OpenRel(rel)
	if err != nil {
		return nil, 0, fmt.Errorf("test report %s: %w", rel, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("test report %s: %w", rel, err)
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, 0, fmt.Errorf("test report %s: not a regular file", rel)
	}
	if st.Size() > MaxReportFileBytes {
		f.Close()
		return nil, 0, fmt.Errorf("%w: %s larger than %d bytes", ErrLimitExceeded, rel, MaxReportFileBytes)
	}
	return f, st.Size(), nil
}

// reportCandidates expands one workspace-relative glob pattern into
// candidate paths by walking the workspace one component at a time,
// anchored at the canonical workspace root: a pattern component is matched
// with filepath.Match against the entries of one directory, so "*" can
// never cross a separator and a pattern can never name an absolute path or
// a path above the workspace. Unlike filepath.Glob it never follows a
// symlink: a symlink in any matched component fails the expansion (fail
// closed) instead of being resolved, because resolving it would read files
// outside the workspace. The returned paths are workspace-relative,
// slash-separated names; the caller opens each through
// safefs.WorkspaceRoot.OpenRel, which re-verifies no-follow at read time.
//
// The component walk uses os.Lstat/os.ReadDir on names below the canonical
// root purely to enumerate candidates; a directory swapped for a symlink
// while the walk runs can at most add names, never content: OpenRel refuses
// the open, and no file is ever read by path.
func reportCandidates(root *safefs.WorkspaceRoot, pattern string) ([]string, error) {
	pat, err := reportPattern(pattern)
	if err != nil {
		return nil, err
	}
	comps := strings.Split(pat, "/")
	current := []string{""}
	for i, comp := range comps {
		last := i == len(comps)-1
		next := make([]string, 0, len(current))
		for _, base := range current {
			if !strings.ContainsAny(comp, "*?[") {
				rel := joinRel(base, comp)
				info, err := os.Lstat(rootAbs(root, rel))
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					return nil, err
				}
				if info.Mode()&os.ModeSymlink != 0 {
					return nil, fmt.Errorf("test report %s: symlinks are not allowed", rel)
				}
				if !last && !info.IsDir() {
					continue
				}
				next = append(next, rel)
				continue
			}
			entries, err := os.ReadDir(rootAbs(root, base))
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			for _, e := range entries {
				ok, merr := filepath.Match(comp, e.Name())
				if merr != nil {
					return nil, fmt.Errorf("test report pattern %q: %w", pattern, merr)
				}
				if !ok {
					continue
				}
				rel := joinRel(base, e.Name())
				if e.Type()&os.ModeSymlink != 0 {
					return nil, fmt.Errorf("test report %s: symlinks are not allowed", rel)
				}
				if !last && !e.IsDir() {
					continue
				}
				next = append(next, rel)
			}
		}
		current = next
	}
	sort.Strings(current)
	return current, nil
}

// reportPattern validates a job's workspace-relative glob pattern before it
// is expanded. Absolute patterns, backslashes, NUL bytes and ".."
// components are rejected up front so no pattern can even name a path
// outside the workspace; "." and empty patterns are rejected because they
// name no file. The pattern is normalized with path.Clean after the
// traversal check so cleaning can never hide a "..".
func reportPattern(pattern string) (string, error) {
	if pattern == "" {
		return "", fmt.Errorf("test report pattern is empty")
	}
	if strings.ContainsRune(pattern, '\x00') || strings.Contains(pattern, "\\") {
		return "", fmt.Errorf("test report pattern %q contains an invalid character", pattern)
	}
	if strings.HasPrefix(pattern, "/") || filepath.IsAbs(pattern) {
		return "", fmt.Errorf("test report pattern %q must be workspace-relative", pattern)
	}
	for _, comp := range strings.Split(pattern, "/") {
		if comp == ".." {
			return "", fmt.Errorf("test report pattern %q escapes the workspace", pattern)
		}
	}
	clean := path.Clean(pattern)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("test report pattern %q does not name a file", pattern)
	}
	return clean, nil
}

func rootAbs(root *safefs.WorkspaceRoot, rel string) string {
	if rel == "" {
		return root.Canonical
	}
	return filepath.Join(root.Canonical, filepath.FromSlash(rel))
}

func joinRel(base, name string) string {
	if base == "" {
		return name
	}
	return base + "/" + name
}

package testintel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestSharedReportLimitsCoherence pins the arithmetic of the ONE size
// contract: the request budget is the payload budget plus the reserved
// envelope, the per-file cap fits the per-job total, the per-file case cap
// fits the per-job case cap, and the aggregate budget is the practical
// (smaller) one the reviewer asked for rather than the old
// 500k-cases x 64KiB theoretical ceiling.
func TestSharedReportLimitsCoherence(t *testing.T) {
	if MaxReportFileBytes > MaxJobReportBytes {
		t.Fatalf("per-file byte cap %d exceeds the per-job total %d", MaxReportFileBytes, MaxJobReportBytes)
	}
	if MaxReportCases > MaxJobCases {
		t.Fatalf("per-file case cap %d exceeds the per-job cap %d", MaxReportCases, MaxJobCases)
	}
	if got := MaxTestReportPayloadBytes + MaxTestReportEnvelopeBytes; got != MaxTestReportRequestBytes {
		t.Fatalf("payload(%d) + envelope(%d) = %d, want the request budget %d", MaxTestReportPayloadBytes, MaxTestReportEnvelopeBytes, got, MaxTestReportRequestBytes)
	}
	if MaxJobCases >= 500_000 {
		t.Fatalf("per-job case cap %d is not the practical aggregate budget (must stay below the old 500k ceiling)", MaxJobCases)
	}
	if MaxTestReportRequestBytes > 64<<20 {
		t.Fatalf("request budget %d is not a practical aggregate budget", MaxTestReportRequestBytes)
	}
	if MaxMessageBytes <= 0 || MaxReportFiles <= 0 {
		t.Fatalf("degenerate limits: message %d files %d", MaxMessageBytes, MaxReportFiles)
	}
}

// TestSharedLimitsDefinedOnce asserts the documented constants live in ONE
// place: no other production file of the package may spell the numeric
// limits, so the parser, the runner and the endpoint can never drift by
// editing a local literal.
func TestSharedLimitsDefinedOnce(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	literals := []string{"8 << 20", "16 << 20", "4 << 10", "50_000", "100_000", "64 << 10", "64 << 20", "256 << 20", "500_000"}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "limits.go" {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, lit := range literals {
			if strings.Contains(string(raw), lit) {
				t.Errorf("%s spells the shared limit literal %q; the limit belongs to limits.go only", name, lit)
			}
		}
	}
	// The parser must reference the exported constants, not copies.
	parser, err := os.ReadFile("junit.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MaxReportFileBytes", "MaxJobReportBytes", "MaxReportCases", "MaxJobCases", "MaxMessageBytes", "MaxReportFiles", "ValidateReportPayload"} {
		if !strings.Contains(string(parser), want) {
			t.Errorf("junit.go does not reference the shared constant %s", want)
		}
	}
}

// TestParseTruncatesMessagesAtSharedLimit pins the producer-metadata policy:
// an oversized failure message is truncated to MaxMessageBytes (never
// retained whole), so the parsed report always stays inside the shared
// message budget.
func TestParseTruncatesMessagesAtSharedLimit(t *testing.T) {
	ws := t.TempDir()
	msg := strings.Repeat("m", MaxMessageBytes+100)
	xml := fmt.Sprintf(`<testsuite name="s" tests="1"><testcase name="t"><failure message="%s">body</failure></testcase></testsuite>`, msg)
	if err := os.WriteFile(filepath.Join(ws, "r.xml"), []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Aggregate(ws, []string{"r.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(rep.Cases) != 1 {
		t.Fatalf("cases = %d", len(rep.Cases))
	}
	if got := rep.Cases[0].Message; len(got) > MaxMessageBytes {
		t.Fatalf("retained message = %d bytes, over the %d-byte budget", len(got), MaxMessageBytes)
	}
}

// TestIdentityLimitsRejectedIdenticallyByParserAndValidator pins the D4-B
// contract: the testcase identity strings (and a producer-declared testsuite
// name) that PostgreSQL indexes are bounded by the shared limits at the
// parser AND at ValidateReportPayload, with the same ErrLimitExceeded reason.
// Exactly-at-the-boundary values are accepted by both.
func TestIdentityLimitsRejectedIdenticallyByParserAndValidator(t *testing.T) {
	over := strings.Repeat("n", MaxTestNameBytes+1)
	at := strings.Repeat("n", MaxTestNameBytes)

	ws := t.TempDir()
	writeFixture(t, ws, "over.xml", `<testsuite name="s"><testcase name="`+over+`"/></testsuite>`)
	writeFixture(t, ws, "at.xml", `<testsuite name="s"><testcase name="`+at+`"/></testsuite>`)

	_, perr := Aggregate(ws, []string{"over.xml"})
	if !errors.Is(perr, ErrLimitExceeded) || !strings.Contains(perr.Error(), "name budget") {
		t.Fatalf("parser oversized name = %v, want ErrLimitExceeded name-budget reason", perr)
	}
	verr := ValidateReportPayload(model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: over, Passed: true}}})
	if !errors.Is(verr, ErrLimitExceeded) || !strings.Contains(verr.Error(), "name budget") {
		t.Fatalf("validator oversized name = %v, want ErrLimitExceeded name-budget reason", verr)
	}
	if _, err := Aggregate(ws, []string{"at.xml"}); err != nil {
		t.Fatalf("parser rejected the boundary name: %v", err)
	}
	if err := ValidateReportPayload(model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: at, Passed: true}}}); err != nil {
		t.Fatalf("validator rejected the boundary name: %v", err)
	}

	// Class.
	overClass := strings.Repeat("c", MaxTestClassBytes+1)
	atClass := strings.Repeat("c", MaxTestClassBytes)
	writeFixture(t, ws, "overclass.xml", `<testsuite name="s"><testcase name="t" classname="`+overClass+`"/></testsuite>`)
	writeFixture(t, ws, "atclass.xml", `<testsuite name="s"><testcase name="t" classname="`+atClass+`"/></testsuite>`)
	if _, err := Aggregate(ws, []string{"overclass.xml"}); !errors.Is(err, ErrLimitExceeded) || !strings.Contains(err.Error(), "class budget") {
		t.Fatalf("parser oversized class = %v, want ErrLimitExceeded class-budget reason", err)
	}
	if err := ValidateReportPayload(model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Class: overClass, Passed: true}}}); !errors.Is(err, ErrLimitExceeded) || !strings.Contains(err.Error(), "class budget") {
		t.Fatalf("validator oversized class = %v, want ErrLimitExceeded class-budget reason", err)
	}
	if _, err := Aggregate(ws, []string{"atclass.xml"}); err != nil {
		t.Fatalf("parser rejected the boundary class: %v", err)
	}
	if err := ValidateReportPayload(model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Class: atClass, Passed: true}}}); err != nil {
		t.Fatalf("validator rejected the boundary class: %v", err)
	}

	// Suite: the parser checks a producer-declared testsuite name, the
	// validator checks the report's suite identity (JobKey), which is what
	// the aggregate table stores.
	overSuite := strings.Repeat("s", MaxTestSuiteBytes+1)
	atSuite := strings.Repeat("s", MaxTestSuiteBytes)
	writeFixture(t, ws, "oversuite.xml", `<testsuite name="`+overSuite+`"><testcase name="t"/></testsuite>`)
	writeFixture(t, ws, "atsuite.xml", `<testsuite name="`+atSuite+`"><testcase name="t"/></testsuite>`)
	if _, err := Aggregate(ws, []string{"oversuite.xml"}); !errors.Is(err, ErrLimitExceeded) || !strings.Contains(err.Error(), "suite budget") {
		t.Fatalf("parser oversized suite = %v, want ErrLimitExceeded suite-budget reason", err)
	}
	if _, err := Aggregate(ws, []string{"atsuite.xml"}); err != nil {
		t.Fatalf("parser rejected the boundary suite name: %v", err)
	}
	if err := ValidateReportPayload(model.TestReport{Tests: 1, JobKey: overSuite, Cases: []model.TestResult{{Name: "t", Passed: true}}}); !errors.Is(err, ErrLimitExceeded) || !strings.Contains(err.Error(), "suite budget") {
		t.Fatalf("validator oversized suite identity = %v, want ErrLimitExceeded suite-budget reason", err)
	}
	if err := ValidateReportPayload(model.TestReport{Tests: 1, JobKey: atSuite, Cases: []model.TestResult{{Name: "t", Passed: true}}}); err != nil {
		t.Fatalf("validator rejected the boundary suite identity: %v", err)
	}
}

// TestOversizedIdentityFailsBeforeSQL pins the ingestion order: a direct
// /tests payload carrying a runaway testcase name is refused by the shared
// validator with a clear 4xx BEFORE any store call. The validator error is
// asserted directly here; the endpoint's ordering is covered by the
// delivery tests (the handler calls ValidateReportPayload before authorizing
// and inserting).
func TestOversizedIdentityFailsBeforeSQL(t *testing.T) {
	err := ValidateReportPayload(model.TestReport{
		Tests: 1,
		Cases: []model.TestResult{{Name: strings.Repeat("x", MaxTestNameBytes+1), Passed: true}},
	})
	if err == nil || !strings.Contains(err.Error(), "name budget") {
		t.Fatalf("err = %v, want a clear name-budget rejection", err)
	}
}

// TestValidateReportPayloadRejectsCaseOverBudget is the shared case-count
// boundary: a report one case over MaxJobCases is refused with
// ErrLimitExceeded by the same validator the runner and the endpoint call.
func TestValidateReportPayloadRejectsCaseOverBudget(t *testing.T) {
	cases := make([]model.TestResult, MaxJobCases+1)
	for i := range cases {
		cases[i] = model.TestResult{Name: "t", Passed: true}
	}
	err := ValidateReportPayload(model.TestReport{Tests: len(cases), Cases: cases})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
	if !strings.Contains(err.Error(), "case") {
		t.Fatalf("err = %v, want the case-count reason", err)
	}
}

// TestValidateReportPayloadRejectsMessageOverBudget is the shared message
// boundary for payloads that did NOT pass through the truncating parser (a
// hand-crafted or adversarial client): the over-limit message is refused.
func TestValidateReportPayloadRejectsMessageOverBudget(t *testing.T) {
	over := model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Passed: true, Message: strings.Repeat("x", MaxMessageBytes+1)}}}
	err := ValidateReportPayload(over)
	if !errors.Is(err, ErrLimitExceeded) || !strings.Contains(err.Error(), "message") {
		t.Fatalf("err = %v, want an ErrLimitExceeded message reason", err)
	}
	at := model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Passed: true, Message: strings.Repeat("x", MaxMessageBytes)}}}
	if err := ValidateReportPayload(at); err != nil {
		t.Fatalf("a message exactly at the budget must pass: %v", err)
	}
}

// TestAggregateRejectsSerializedPayloadOverBudget is the parser-side payload
// boundary: two files whose RAW bytes stay under MaxJobReportBytes and whose
// case counts stay under the caps still produce a serialized report over
// MaxTestReportPayloadBytes (JSON field overhead per tiny case), and the
// parser must reject it rather than produce a report the /tests endpoint
// could never receive.
func TestAggregateRejectsSerializedPayloadOverBudget(t *testing.T) {
	ws := t.TempDir()
	// Pick a name length where the JSON form of the aggregate exceeds the
	// payload budget while the raw XML stays inside the byte cap. The premise
	// is verified below with the exact marshal the validator uses.
	const nameLen = 144
	perFile := MaxJobCases / 2
	probe := make([]model.TestResult, MaxJobCases)
	for i := range probe {
		probe[i] = model.TestResult{Name: strings.Repeat("n", nameLen)}
	}
	payload, merr := json.Marshal(model.TestReport{Cases: probe})
	if merr != nil {
		t.Fatal(merr)
	}
	if len(payload) <= MaxTestReportPayloadBytes {
		t.Fatalf("test premise broken: serialized probe is %d bytes, not over the %d-byte payload budget", len(payload), MaxTestReportPayloadBytes)
	}
	var sb strings.Builder
	sb.WriteString(`<testsuite name="s">`)
	for i := 0; i < perFile; i++ {
		sb.WriteString(`<testcase name="` + strings.Repeat("n", nameLen) + `"/>`)
	}
	sb.WriteString(`</testsuite>`)
	body := sb.String()
	if total := int64(2 * len(body)); total > MaxJobReportBytes {
		t.Fatalf("test premise broken: raw total %d exceeds the %d-byte cap", total, MaxJobReportBytes)
	}
	for i := 0; i < 2; i++ {
		if err := os.WriteFile(filepath.Join(ws, fmt.Sprintf("r%d.xml", i)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Aggregate(ws, []string{"*.xml"})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
	if !strings.Contains(err.Error(), "payload budget") {
		t.Fatalf("err = %v, want the serialized-payload reason", err)
	}
}

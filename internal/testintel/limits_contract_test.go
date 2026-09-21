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

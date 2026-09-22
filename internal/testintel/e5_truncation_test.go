package testintel

import (
	"errors"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestE5CombinedFailureIsTruncatedOnceAtTheSharedLimit is the E5-C regression:
// a failure whose message and body are EACH well under MaxMessageBytes but
// whose JOINED text is over it used to be truncated per part, joined with the
// separator newline and end up one byte over the shared budget, so the parser
// rejected its own output. Combining first and truncating ONCE keeps the
// retained value exactly at the budget and the validator accepts it.
func TestE5CombinedFailureIsTruncatedOnceAtTheSharedLimit(t *testing.T) {
	half := MaxMessageBytes/2 + 4*1024 // two halves joined well over the budget
	msg := strings.Repeat("m", half)
	body := strings.Repeat("b", half)
	ws := t.TempDir()
	writeFixture(t, ws, "combined.xml",
		`<testsuite name="s" tests="1"><testcase name="t"><failure message="`+msg+`">`+body+`</failure></testcase></testsuite>`)

	rep, err := Aggregate(ws, []string{"combined.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(rep.Cases) != 1 {
		t.Fatalf("cases = %d", len(rep.Cases))
	}
	got := rep.Cases[0].Message
	if len(got) != MaxMessageBytes {
		t.Fatalf("retained message = %d bytes, want exactly the %d-byte budget", len(got), MaxMessageBytes)
	}
	// The retained text is the join of the masked parts, truncated once: the
	// message part survives whole and the body contributes the remainder.
	if !strings.HasPrefix(got, msg+"\n") {
		t.Fatalf("retained message does not start with the whole message part: %q...", got[:min(len(got), 32)])
	}
	if err := ValidateReportPayload(rep); err != nil {
		t.Fatalf("the parser's own output must pass the shared validator: %v", err)
	}

	// The same size ratio through the single-file Parse path: the case parts
	// are bounded together, with the separator charged against the budget.
	parsed, err := Parse(writeFixture(t, ws, "combined2.xml",
		`<testsuite name="s" tests="1"><testcase name="t"><failure message="`+msg+`">`+body+`</failure></testcase></testsuite>`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f := parsed.Suites[0].Cases[0].Failure; len(f.Message)+1+len(f.Body) > MaxMessageBytes {
		t.Fatalf("case parts joined to %d bytes, over the %d-byte budget", len(f.Message)+1+len(f.Body), MaxMessageBytes)
	}
}

// TestE5FarOverLimitFailureTruncatesNotRejects proves an arbitrarily larger
// combined failure is truncated (never rejected) to exactly the shared
// message budget at ingestion, so the retained case always validates.
func TestE5FarOverLimitFailureTruncatesNotRejects(t *testing.T) {
	msg := strings.Repeat("m", 200<<10)
	body := strings.Repeat("b", 200<<10)
	ws := t.TempDir()
	writeFixture(t, ws, "huge.xml",
		`<testsuite name="s" tests="1"><testcase name="t"><failure message="`+msg+`">`+body+`</failure></testcase></testsuite>`)
	rep, err := Aggregate(ws, []string{"huge.xml"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if got := rep.Cases[0].Message; len(got) != MaxMessageBytes {
		t.Fatalf("retained message = %d bytes, want %d", len(got), MaxMessageBytes)
	}
	if err := ValidateReportPayload(rep); err != nil {
		t.Fatalf("aggregate over the combined limit must validate after truncation: %v", err)
	}
	// A report that reaches the validator WITHOUT the parser's truncation
	// (a direct /tests submission) is still rejected.
	over := model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Passed: false, Message: strings.Repeat("x", MaxMessageBytes+1)}}}
	if err := ValidateReportPayload(over); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("over-limit direct message = %v, want ErrLimitExceeded", err)
	}
}

// TestE5FailureMaskingPrecedesTruncation pins the required order — combine and
// MASK first, then truncate ONCE: the retained message must equal the masked
// joined text cut at the budget, so a mask that expands the text is still
// bounded and a secret inside the retained region is masked exactly once.
func TestE5FailureMaskingPrecedesTruncation(t *testing.T) {
	msg := strings.Repeat("z", 40<<10)
	body := strings.Repeat("z", 40<<10)
	ws := t.TempDir()
	writeFixture(t, ws, "masked.xml",
		`<testsuite name="s" tests="1"><testcase name="t"><failure message="`+msg+`">`+body+`</failure></testcase></testsuite>`)

	// An expanding, per-byte mask: every 'z' doubles. Masking the joined text
	// before the cut is what the retained value must reflect.
	mask := func(s string) string { return strings.ReplaceAll(s, "z", "zz") }
	rep, err := AggregateMasked(ws, []string{"masked.xml"}, mask)
	if err != nil {
		t.Fatalf("aggregate masked: %v", err)
	}
	want := strings.Repeat("z", 2*(len(msg)+1+len(body)))
	if len(want) > MaxMessageBytes {
		want = want[:MaxMessageBytes]
	}
	if got := rep.Cases[0].Message; got != want {
		t.Fatalf("retained message = %d bytes, want the masked joined text cut once to %d (got %d)", len(got), len(want), len(got))
	}
	if err := ValidateReportPayload(rep); err != nil {
		t.Fatalf("masked aggregate must validate: %v", err)
	}

	// A secret that ENDS exactly at the byte boundary must be masked in what
	// is kept: truncating first would retain an unmasked fragment ("SEC") of
	// it, masking first retains the whole mask ("***").
	raw := strings.Repeat("y", MaxMessageBytes-3) + "SECRET"
	masked, err := ParseMasked(writeFixture(t, ws, "straddle.xml",
		`<testsuite name="s" tests="1"><testcase name="t"><failure message="`+raw+`"></failure></testcase></testsuite>`),
		func(s string) string { return strings.ReplaceAll(s, "SECRET", "***") })
	if err != nil {
		t.Fatalf("parse masked: %v", err)
	}
	wantStraddle := strings.Repeat("y", MaxMessageBytes-3) + "***"
	if got := masked.Suites[0].Cases[0].Failure; got.Message != wantStraddle {
		t.Fatalf("masked boundary message = %q..., want the whole mask retained (tail %q)", got.Message[:16], got.Message[len(got.Message)-3:])
	}
}

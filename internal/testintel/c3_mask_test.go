package testintel

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// c3Secret is a resolved secret value of the kind the runner registers in
// its masker (for example the lease token injected for an id_token job)
// before test reports are collected.
const c3Secret = "c3-lease-secret-9f2b"

// c3Report carries the secret in every content surface a JUnit producer can
// put a secret into: a failure message attribute, a failure body, an error
// body and system-err.
const c3Report = `<testsuite name="suite" tests="2" failures="1" errors="1">
  <testcase name="fails" classname="pkg.T" time="0.1">
    <failure message="boom ` + c3Secret + `">stack line with ` + c3Secret + `</failure>
  </testcase>
  <testcase name="errors" classname="pkg.T" time="0.2">
    <error message="oops">error body ` + c3Secret + `</error>
    <system-err>stderr excerpt ` + c3Secret + `</system-err>
  </testcase>
</testsuite>`

func c3Masker(t *testing.T) *secrets.Masker {
	t.Helper()
	m := &secrets.Masker{}
	if err := m.AddStrict(c3Secret); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestAggregateMaskedRedactsSecretSurfaces proves the runner's fixed call
// path (AggregateMasked with secrets.Masker.Mask) persists no secret from
// the failure message attribute, the failure body or the error body, and
// that the serialized report the read tier serves cannot contain it either.
func TestAggregateMaskedRedactsSecretSurfaces(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "report.xml", c3Report)
	masker := c3Masker(t)
	rep, err := AggregateMasked(ws, []string{"*.xml"}, masker.Mask)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tests != 2 || rep.Failures != 1 || rep.Errors != 1 || len(rep.Cases) != 2 {
		t.Fatalf("report = %+v", rep)
	}
	failure, errored := rep.Cases[0], rep.Cases[1]
	if failure.Name != "fails" || errored.Name != "errors" {
		t.Fatalf("case order = %q, %q", failure.Name, errored.Name)
	}
	if strings.Contains(failure.Message, c3Secret) {
		t.Fatalf("failure message/body leaked secret: %q", failure.Message)
	}
	if strings.Contains(errored.Message, c3Secret) {
		t.Fatalf("error body leaked secret: %q", errored.Message)
	}
	if !strings.Contains(failure.Message, "boom") || !strings.Contains(failure.Message, "stack line with") {
		t.Fatalf("failure message lost its non-secret content: %q", failure.Message)
	}
	if !strings.Contains(failure.Message, "***") {
		t.Fatalf("failure message was not redacted in place: %q", failure.Message)
	}
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), c3Secret) {
		t.Fatalf("serialized report leaks secret: %s", blob)
	}
}

// TestParseMaskedRedactsSystemErr covers the remaining surface directly:
// the aggregate model does not mirror system-err today, but the parser must
// never retain the secret in the parsed case either.
func TestParseMaskedRedactsSystemErr(t *testing.T) {
	ws := t.TempDir()
	p := writeFixture(t, ws, "syserr.xml", c3Report)
	rep, err := ParseMasked(p, c3Masker(t).Mask)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Cases {
		if strings.Contains(c.SystemErr, c3Secret) {
			t.Fatalf("system-err leaked secret: %q", c.SystemErr)
		}
		if c.Failure != nil && (strings.Contains(c.Failure.Message, c3Secret) || strings.Contains(c.Failure.Body, c3Secret)) {
			t.Fatalf("failure leaked secret: %+v", c.Failure)
		}
		if c.Error != nil && (strings.Contains(c.Error.Message, c3Secret) || strings.Contains(c.Error.Body, c3Secret)) {
			t.Fatalf("error leaked secret: %+v", c.Error)
		}
	}
	if !strings.Contains(rep.Cases[1].SystemErr, "***") {
		t.Fatalf("system-err was not redacted in place: %q", rep.Cases[1].SystemErr)
	}
}

// TestAggregateWithoutMaskLeaksSecret is the control for the masking tests:
// with the nil mask (the runner's old behavior, Aggregate) the same fixture
// retains the secret, proving the fixture exercises a real leak rather than
// an empty assertion.
func TestAggregateWithoutMaskLeaksSecret(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "report.xml", c3Report)
	rep, err := Aggregate(ws, []string{"*.xml"})
	if err != nil {
		t.Fatal(err)
	}
	leaked := false
	for _, c := range rep.Cases {
		if strings.Contains(c.Message, c3Secret) {
			leaked = true
		}
	}
	if !leaked {
		t.Fatal("control fixture does not carry the secret; masking tests prove nothing")
	}
	masker := c3Masker(t)
	masked, err := AggregateMasked(ws, []string{"*.xml"}, masker.Mask)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range masked.Cases {
		if strings.Contains(c.Message, c3Secret) {
			t.Fatalf("masked aggregate leaked: %q", c.Message)
		}
	}
}

// TestAggregateMaskedConcurrentMasker runs the real masking path with one
// shared masker while another goroutine extends it. The runner hands the
// same masker to the executor (which registers step secrets) and to the log
// path, so the aggregate call must be safe under the race detector.
func TestAggregateMaskedConcurrentMasker(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "report.xml", c3Report)
	masker := c3Masker(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep, err := AggregateMasked(ws, []string{"*.xml"}, masker.Mask)
			if err != nil {
				t.Errorf("aggregate: %v", err)
				return
			}
			for _, c := range rep.Cases {
				if strings.Contains(c.Message, c3Secret) {
					t.Errorf("leak under concurrency: %q", c.Message)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 64; i++ {
			_ = masker.AddStrict(fmt.Sprintf("step-secret-%d", i))
		}
	}()
	wg.Wait()
}

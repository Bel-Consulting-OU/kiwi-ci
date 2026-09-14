package testintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzJUnit drives the JUnit XML report parser with arbitrary documents. A
// hostile or corrupted report must never panic, with or without secret
// masking.
func FuzzJUnit(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><testsuite name="s" tests="1"><testcase name="ok"/></testsuite>`))
	f.Add([]byte(`<testsuites><testsuite name="a" tests="1" failures="1"><testcase name="f"><failure message="boom">stack</failure></testcase></testsuite></testsuites>`))
	f.Add([]byte("<not-junit/>"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "report.xml")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ParseMasked(path, nil); err == nil {
			// Successful parses must also succeed with a mask applied and
			// must respect the message truncation contract.
			rep, err := ParseMasked(path, strings.ToUpper)
			if err != nil {
				t.Fatalf("masked reparse failed where unmasked succeeded: %v", err)
			}
			for _, c := range rep.Cases {
				if c.Failure != nil && len(c.Failure.Message) > maxMessageLen {
					t.Fatalf("failure message exceeds mask limit: %d", len(c.Failure.Message))
				}
			}
		}
	})
}

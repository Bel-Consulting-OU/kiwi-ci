package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheckAcceptsCanonicalUTC(t *testing.T) {
	values := []string{
		"2006-01-02T15:04:05Z",
		"1970-01-01T00:00:00Z",
		"2000-02-29T00:00:00Z", // leap day in a leap year
		"2026-09-18T12:39:10Z",
	}
	for _, value := range values {
		if err := check(value); err != nil {
			t.Errorf("check(%q) = %v, want nil", value, err)
		}
	}
}

func TestCheckRejects(t *testing.T) {
	values := []string{
		"",                            // empty
		"2006-13-45T99:99:99Z",        // impossible month/day/time (shape passes)
		"2006-02-30T00:00:00Z",        // impossible calendar day
		"2100-02-29T00:00:00Z",        // non-leap century
		"2006-01-02T24:00:00Z",        // hour out of range
		"2006-01-02T15:04:05+00:00",   // zero offset spelled numerically
		"2006-01-02T15:04:05-00:00",   // negative zero offset
		"2006-01-02T15:04:05+02:00",   // non-UTC offset
		"2006-01-02T15:04:05-02:00",   // non-UTC negative offset (char set allows it)
		"2006-01-02T15:04:05.500Z",    // fractional seconds
		"2006-01-02T15:04:05",         // missing zone
		"2006-01-02",                  // date only
		"2006-1-2T15:04:05Z",          // unpadded fields
		"2006-01-02T15:04:05z",        // lowercase zone
		"2006-01-02T15:04:05Z\n",      // trailing newline
		"2006-01-02T15:04:05Z -X foo", // trailing linker-flag injection attempt
		"2006-01-02T15:04:05Z;id",     // shell metacharacters
		" 2006-01-02T15:04:05Z",       // leading space
		"2006-01-02T15:04:05Zx",       // trailing junk
		"not-a-date",                  // garbage
	}
	for _, value := range values {
		if err := check(value); err == nil {
			t.Errorf("check(%q) = nil, want error", value)
		}
	}
}

// TestRunExitCodes pins the CLI contract: 0 for a canonical value, 1 for a
// rejected value (with a one-line reason), 2 for wrong usage.
func TestRunExitCodes(t *testing.T) {
	var stderr bytes.Buffer
	if got := run([]string{"2026-09-18T12:39:10Z"}, &stderr); got != 0 {
		t.Fatalf("run(canonical) = %d, want 0", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("run(canonical) stderr = %q, want empty", stderr.String())
	}

	stderr.Reset()
	if got := run([]string{"2006-02-30T00:00:00Z"}, &stderr); got != 1 {
		t.Fatalf("run(impossible date) = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "rfc3339check:") {
		t.Fatalf("stderr = %q, want the rfc3339check reason line", stderr.String())
	}

	for _, args := range [][]string{nil, {"a", "b"}} {
		stderr.Reset()
		if got := run(args, &stderr); got != 2 {
			t.Fatalf("run(%v) = %d, want 2", args, got)
		}
		if !strings.Contains(stderr.String(), "usage: rfc3339check") {
			t.Fatalf("stderr = %q, want the usage line", stderr.String())
		}
	}
}

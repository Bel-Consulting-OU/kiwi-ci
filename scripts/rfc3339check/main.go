// Command rfc3339check validates a build timestamp the way scripts/release.sh
// requires it: exactly the canonical RFC3339 UTC form the pipeline emits
// (YYYY-MM-DDTHH:MM:SSZ), naming a real calendar instant.
//
// A shape regex alone accepts impossible dates such as 2006-13-45T99:99:99Z,
// and time.RFC3339 parsing alone accepts numeric offsets and fractional
// seconds, so this helper does both: time.Parse must succeed AND the parsed
// value must re-format, in UTC, to exactly the input string. That rejects
// non-UTC offsets (+02:00, -00:00), fractional seconds, and any other
// non-canonical spelling, while accepting only values such as
// 2006-01-02T15:04:05Z.
//
// Usage:
//
//	go run ./scripts/rfc3339check <value>
//
// Exit status is 0 only for an accepted value; otherwise the helper prints a
// one-line reason to stderr and exits non-zero (1 for a bad value, 2 for
// wrong usage).
package main

import (
	"fmt"
	"os"
	"time"
)

// canonicalLayout is the exact form recorded as internal/version.BuildDate:
// RFC3339 in UTC with second precision and the literal "Z" suffix. The bare
// trailing "Z" is a literal in a Go layout, not a zone token.
const canonicalLayout = "2006-01-02T15:04:05Z"

// check returns nil when value parses as RFC3339 and is spelled exactly as
// the canonical UTC layout, and a descriptive error otherwise.
func check(value string) error {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fmt.Errorf("%q is not a valid RFC3339 timestamp: %v", value, err)
	}
	if canonical := t.UTC().Format(canonicalLayout); canonical != value {
		return fmt.Errorf("%q is not the canonical UTC form %s (canonical spelling: %q)", value, canonicalLayout, canonical)
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: rfc3339check YYYY-MM-DDTHH:MM:SSZ")
		os.Exit(2)
	}
	if err := check(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "rfc3339check: %v\n", err)
		os.Exit(1)
	}
}

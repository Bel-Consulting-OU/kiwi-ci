package pipeline

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func Load(path string) (*Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Spec, error) {
	return parseSpec(b, false)
}

// ParseWithComponents is the server-side enqueue resolution parse: the
// ORIGINAL document is parsed with the full strict parser (node-level
// alias/merge/tag/duplicate/size checks and known-field validation with
// line numbers) BEFORE any normalization, with ONE relaxation — a job that
// declares `component:` (plus `with:`) may omit its own steps, because the
// component fragment supplies them. Everything else is validated exactly as
// in Parse; the caller resolves the components and must re-validate the
// assembled spec with Parse.
func ParseWithComponents(b []byte) (*Spec, error) {
	return parseSpec(b, true)
}

func parseSpec(b []byte, relaxComponentJobs bool) (*Spec, error) {
	if len(b) > maxPipelineBytes {
		return nil, fmt.Errorf("pipeline exceeds %d byte limit", maxPipelineBytes)
	}
	var s Spec
	if err := parseYAML(b, &s); err != nil {
		return nil, fmt.Errorf("parse pipeline: %w", err)
	}
	if s.Version == 0 {
		s.Version = 1
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("unsupported pipeline version %d", s.Version)
	}
	if len(s.Jobs) == 0 {
		return nil, fmt.Errorf("pipeline has no jobs")
	}
	if err := validateSpec(&s, relaxComponentJobs); err != nil {
		return nil, err
	}
	canonicalizeSpec(&s)
	return &s, nil
}

// canonicalizeSpec normalizes the parsed spec in place so later consumers and
// digests observe a canonical form: secret declarations are sorted (they are
// a set; the server deduplicates on use).
func canonicalizeSpec(s *Spec) {
	if len(s.Secrets) > 1 {
		sort.Strings(s.Secrets)
	}
}

// ParseRetention converts an artifact retention string into a duration.
// Empty returns 0 (caller's default), "forever"/"infinite"/"never" returns a
// negative value (no expiry), and anything else must be a Go duration.
func ParseRetention(s string) (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return 0, nil
	case "forever", "infinite", "never":
		return -1, nil
	}
	return time.ParseDuration(strings.TrimSpace(s))
}

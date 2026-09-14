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
	if err := Validate(&s); err != nil {
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

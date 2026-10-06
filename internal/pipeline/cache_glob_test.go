package pipeline

import (
	"strings"
	"testing"
)

// TestAdmissionRejectsMalformedHashFilesGlob proves a hash_files pattern the
// glob engine cannot parse is rejected at admission with a clear error
// instead of being admitted and failing (or being silently discarded) at
// cache-key time.
func TestAdmissionRejectsMalformedHashFilesGlob(t *testing.T) {
	for name, yaml := range map[string]string{
		"unterminated class":  doc("    cache:\n      - paths: [a]\n        hash_files: [\"[bad\"]\n    steps:\n      - run: r\n"),
		"dangling escape eol": doc("    cache:\n      - paths: [a]\n        hash_files: [\"x[\"]\n    steps:\n      - run: r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "invalid glob syntax") {
				t.Fatalf("Parse = %v, want invalid-glob rejection", err)
			}
		})
	}
	// paths are literal prefixes, not globs: glob metacharacters there must
	// not trigger the grammar check.
	if _, err := Parse([]byte(doc("    cache:\n      - paths: [\"[not-a-glob\"]\n    steps:\n      - run: r\n"))); err != nil {
		t.Fatalf("literal path rejected: %v", err)
	}
	// A valid glob is admitted.
	if _, err := Parse([]byte(doc("    cache:\n      - paths: [a]\n        hash_files: [\"**/*.sum\"]\n    steps:\n      - run: r\n"))); err != nil {
		t.Fatalf("valid glob rejected: %v", err)
	}
}

// TestCompiledAdmissionRejectsMalformedHashFilesGlob proves the
// post-interpolation compiled validation applies the same glob grammar
// check: a matrix value that interpolates into a malformed pattern is
// rejected before the job can run.
func TestCompiledAdmissionRejectsMalformedHashFilesGlob(t *testing.T) {
	cj := CompiledJob{ID: "x", BaseID: "x", Job: Job{
		Cache: []Cache{{Paths: []string{"a"}, HashFiles: []string{"[bad"}}},
		Steps: []Step{{Run: "true"}},
	}}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "invalid glob syntax") {
		t.Fatalf("ValidateCompiledJob = %v, want invalid-glob rejection", err)
	}
	// The error names the offending pattern.
	err := ValidateCompiledJob(cj)
	if err == nil || !strings.Contains(err.Error(), "[bad") {
		t.Fatalf("ValidateCompiledJob error = %v, want the pattern named", err)
	}
	ok := CompiledJob{ID: "x", BaseID: "x", Job: Job{
		Cache: []Cache{{Paths: []string{"a"}, HashFiles: []string{"**/*.sum"}}},
		Steps: []Step{{Run: "true"}},
	}}
	if err := ValidateCompiledJob(ok); err != nil {
		t.Fatalf("valid compiled glob rejected: %v", err)
	}
}

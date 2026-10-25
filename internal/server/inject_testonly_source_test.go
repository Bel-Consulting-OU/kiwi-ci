package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompleteSemanticsInjectIsTestOnlySource: the completion-semantics
// inject helper must live in a _test.go file. Shipping it in a production
// .go file linked it into the kiwi binary (strings on dist/kiwi found
// jobExecutionSemanticsForTest) — a test fixture must never be part of the
// server the runner talks to.
func TestCompleteSemanticsInjectIsTestOnlySource(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, name := range entries {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "func maybeInjectCompleteSemantics") ||
			strings.Contains(string(b), "func (s *Server) jobExecutionSemanticsForTest") {
			t.Fatalf("production source file %q contains the test-only completion-semantics inject helper", name)
		}
		if strings.Contains(string(b), "maybeInjectCompleteSemantics(") {
			// A production file may not even *call* the helper.
			t.Fatalf("production source file %q calls maybeInjectCompleteSemantics", name)
		}
		found++
	}
	if found == 0 {
		t.Fatal("no production .go files scanned (glob broken?)")
	}
}

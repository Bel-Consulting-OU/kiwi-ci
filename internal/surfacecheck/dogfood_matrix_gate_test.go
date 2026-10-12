package surfacecheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/scenarios"
)

// TestDogfoodMatrixGateMatchesRegistry is the CI surface-check twin of
// scenarios.TestDogfoodMatrixMatchesRegistry: docs/DOGFOOD_MATRIX.md's
// "Implemented scenario IDs" list must equal the scenario registry's
// Implemented set. The dogfood matrix is a verification surface like any
// other — a doc that claims proofs the registry does not implement (or
// hides proofs the registry does) is drift, and surface-check must catch it
// even when the dogfood package tests are not in the invoked set. The check
// body is scenarios.CheckMatrixImplementedIDs, so the two gates cannot
// disagree about what "match" means.
func TestDogfoodMatrixGateMatchesRegistry(t *testing.T) {
	root := repoRoot(t)
	docPath := filepath.Join(root, "docs", "DOGFOOD_MATRIX.md")
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("dogfood matrix gate: read %s: %v", docPath, err)
	}
	if len(scenarios.Registry) == 0 {
		t.Fatal("dogfood matrix gate: scenario registry is empty")
	}
	drift := scenarios.CheckMatrixImplementedIDs(string(raw))
	if len(drift) > 0 {
		t.Fatalf("dogfood matrix gate: DOGFOOD_MATRIX.md drifted from the scenario registry (%d):\n  %s",
			len(drift), joinLines(drift))
	}
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n  "
		}
		out += l
	}
	return out
}

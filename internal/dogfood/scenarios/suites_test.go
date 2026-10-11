package scenarios

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSuiteMembershipMatchesRegistry pins the suite catalog to the registry:
// every suite ID exists, every MandatoryForPR scenario is owned by the fast
// suite, and every implemented scenario is owned by at least one suite. A
// scenario that runs nowhere is a coverage hole; a suite that names a
// non-registry ID is a phantom.
func TestSuiteMembershipMatchesRegistry(t *testing.T) {
	inRegistry := map[ScenarioID]bool{}
	implemented := map[ScenarioID]bool{}
	for _, e := range Registry {
		inRegistry[e.ID] = true
		if e.Implemented {
			implemented[e.ID] = true
		}
	}

	inSuite := map[ScenarioID]map[string]bool{}
	fast := map[ScenarioID]bool{}
	for _, s := range Suites {
		if s.Name == "" || s.Tier == "" {
			t.Errorf("suite %q: empty name or tier", s.Name)
		}
		seen := map[ScenarioID]bool{}
		for _, id := range s.ScenarioIDs {
			if !inRegistry[id] {
				t.Errorf("suite %s names %s, which is not in Registry", s.Name, id)
				continue
			}
			if seen[id] {
				t.Errorf("suite %s lists %s twice", s.Name, id)
			}
			seen[id] = true
			if inSuite[id] == nil {
				inSuite[id] = map[string]bool{}
			}
			inSuite[id][s.Name] = true
			if s.Name == SuiteFast {
				fast[id] = true
			}
		}
	}

	for _, e := range Registry {
		if e.MandatoryForPR && !fast[e.ID] {
			t.Errorf("MandatoryForPR %s is not in the fast suite", e.ID)
		}
		if e.Implemented && len(inSuite[e.ID]) == 0 {
			t.Errorf("Implemented %s is in no suite", e.ID)
		}
	}
}

// TestRequiredTestPrefixesMatchScenarioIDs pins the TestDF… naming bridge
// dogfood-run.sh --require uses: DF-BOOT-001 → TestDFBOOT001.
func TestRequiredTestPrefixesMatchScenarioIDs(t *testing.T) {
	got := RequiredTestPrefixes(SuiteFast)
	if len(got) == 0 {
		t.Fatal("fast suite has no required test prefixes")
	}
	want := map[string]bool{}
	for _, e := range Registry {
		if e.MandatoryForPR {
			want[ScenarioTestPrefix(e.ID)] = true
		}
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("fast prefix %s is not a MandatoryForPR scenario", p)
		}
		delete(want, p)
	}
	for p := range want {
		t.Errorf("MandatoryForPR prefix %s missing from RequiredTestPrefixes(fast)", p)
	}
	if RequiredTestPrefixes("no-such-suite") != nil {
		t.Error("unknown suite must yield nil")
	}
}

// TestDogfoodMatrixMatchesRegistry keeps docs/DOGFOOD_MATRIX.md honest: the
// doc's "Implemented scenario IDs" list must be exactly the registry's
// Implemented set. A registry ID missing from the doc is an undocumented
// proof; a doc ID that is not Implemented in the registry is a claimed proof
// that does not run.
func TestDogfoodMatrixMatchesRegistry(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "docs", "DOGFOOD_MATRIX.md"))
	if err != nil {
		t.Fatalf("read DOGFOOD_MATRIX.md: %v", err)
	}
	doc := string(raw)

	// The implemented list lives under its own heading so the check stays
	// mechanical and the rest of the matrix may name planned IDs freely.
	const heading = "## Implemented scenario IDs"
	start := strings.Index(doc, heading)
	if start < 0 {
		t.Fatalf("DOGFOOD_MATRIX.md has no %q section", heading)
	}
	rest := doc[start+len(heading):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	idRe := regexp.MustCompile(`DF-[A-Z0-9]+-\d+`)
	docIDs := map[string]bool{}
	for _, m := range idRe.FindAllString(rest, -1) {
		docIDs[m] = true
	}
	if len(docIDs) == 0 {
		t.Fatal("Implemented scenario IDs section lists no IDs")
	}

	regImplemented := map[string]bool{}
	for _, e := range Registry {
		if e.Implemented {
			regImplemented[string(e.ID)] = true
		}
	}

	for id := range regImplemented {
		if !docIDs[id] {
			t.Errorf("Implemented registry ID %s is missing from DOGFOOD_MATRIX.md implemented list", id)
		}
	}
	for id := range docIDs {
		if !regImplemented[id] {
			t.Errorf("DOGFOOD_MATRIX.md claims %s is implemented, but the registry does not", id)
		}
	}
}

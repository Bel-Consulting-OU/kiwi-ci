package version

// Contract-versions documentation match guard. The registry
// (ContractVersions) is the single source of truth; docs/CONTRACTS.md is
// generated from RenderContractTable so the public table cannot drift:
//
//	KIWI_GEN=1 go test ./internal/version -run TestGenerateContractVersionsDoc -count=1
//
// The generator writes the file only under KIWI_GEN=1; the normal
// TestDocsMatchContractVersions run asserts the committed file is exactly the
// generated content and that the prose contracts name the current key
// versions.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRootForVersion(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// TestGenerateContractVersionsDoc rewrites docs/CONTRACTS.md from the
// registry. Set KIWI_GEN=1 to regenerate; a normal run is a no-op skip so
// the file cannot be overwritten accidentally.
func TestGenerateContractVersionsDoc(t *testing.T) {
	if os.Getenv("KIWI_GEN") != "1" {
		t.Skip("set KIWI_GEN=1 to regenerate docs/CONTRACTS.md from version.ContractVersions")
	}
	path := filepath.Join(repoRootForVersion(t), "docs", "CONTRACTS.md")
	if err := os.WriteFile(path, []byte(RenderContractTable()), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s", path)
}

// TestDocsMatchContractVersions keeps the public contract-version docs honest:
// docs/CONTRACTS.md must equal the registry-generated content exactly (prose
// cannot drift), and the key version strings the prose contracts claim (evidence
// schema, completion hash, runner API) must match the registry values.
func TestDocsMatchContractVersions(t *testing.T) {
	root := repoRootForVersion(t)
	want := RenderContractTable()
	raw, err := os.ReadFile(filepath.Join(root, "docs", "CONTRACTS.md"))
	if err != nil {
		t.Fatalf("read docs/CONTRACTS.md: %v (run KIWI_GEN=1 go test ./internal/version -run TestGenerateContractVersionsDoc -count=1)", err)
	}
	if string(raw) != want {
		t.Fatalf("docs/CONTRACTS.md does not match version.ContractVersions; regenerate with KIWI_GEN=1 go test ./internal/version -run TestGenerateContractVersionsDoc -count=1 and commit the result")
	}

	// Key version strings must appear in the generated table — named
	// explicitly so a generator regression cannot silently drop them.
	for _, key := range []string{"evidence_schema", "completion_result_hash", "runner_api_protocol"} {
		row := fmt.Sprintf("| `%s` | `%s` |", key, ContractVersions[key])
		if !strings.Contains(want, row) {
			t.Errorf("docs/CONTRACTS.md missing key version row %q", row)
		}
	}
	if ContractVersions["evidence_schema"] != "6" {
		t.Fatalf("evidence_schema = %q, want 6", ContractVersions["evidence_schema"])
	}
	if ContractVersions["completion_result_hash"] != "3" {
		t.Fatalf("completion_result_hash = %q, want 3", ContractVersions["completion_result_hash"])
	}
	if ContractVersions["runner_api_protocol"] != "3" {
		t.Fatalf("runner_api_protocol = %q, want 3", ContractVersions["runner_api_protocol"])
	}

	// The prose evidence contract names the attestation schema version; it
	// must not lag the registry (a bump without a doc edit fails here), and
	// no prose doc may claim a retired schema number as current.
	for _, doc := range []string{"docs/evidence-contract.md", "docs/releases.md"} {
		b, err := os.ReadFile(filepath.Join(root, doc))
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		text := string(b)
		if doc == "docs/evidence-contract.md" {
			schemaClaim := fmt.Sprintf("schemaVersion = %s", ContractVersions["evidence_schema"])
			if !strings.Contains(text, schemaClaim) {
				t.Errorf("%s does not mention %q; update it to match ContractVersions", doc, schemaClaim)
			}
		}
		if strings.Contains(text, "schemaVersion = 5") {
			t.Errorf("%s still claims schemaVersion = 5; current is %s", doc, ContractVersions["evidence_schema"])
		}
	}
}

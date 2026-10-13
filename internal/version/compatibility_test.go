package version

// Compatibility-document match guard. CompatibilityDocument() is the single
// source of truth; docs/compatibility.json and docs/compatibility.md are
// generated from it so the public compatibility surface cannot drift:
//
//	KIWI_GEN=1 go test ./internal/version -run TestGenerateCompatibilityDocs -count=1
//
// The generator writes the files only under KIWI_GEN=1; the normal
// TestDocsMatchCompatibility run asserts the committed files are exactly the
// generated content.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateCompatibilityDocs rewrites docs/compatibility.json and
// docs/compatibility.md from CompatibilityDocument(). Set KIWI_GEN=1 to
// regenerate; a normal run is a no-op skip so the files cannot be
// overwritten accidentally.
func TestGenerateCompatibilityDocs(t *testing.T) {
	if os.Getenv("KIWI_GEN") != "1" {
		t.Skip("set KIWI_GEN=1 to regenerate docs/compatibility.json and docs/compatibility.md from version.BuildCompatibilityDocument")
	}
	root := repoRootForVersion(t)
	jsonPath := filepath.Join(root, "docs", "compatibility.json")
	mdPath := filepath.Join(root, "docs", "compatibility.md")
	if err := os.WriteFile(jsonPath, RenderCompatibilityJSON(), 0o644); err != nil {
		t.Fatalf("write %s: %v", jsonPath, err)
	}
	t.Logf("wrote %s", jsonPath)
	if err := os.WriteFile(mdPath, []byte(RenderCompatibilityDoc()), 0o644); err != nil {
		t.Fatalf("write %s: %v", mdPath, err)
	}
	t.Logf("wrote %s", mdPath)
}

// TestDocsMatchCompatibility keeps the public compatibility docs honest:
// docs/compatibility.json and docs/compatibility.md must equal the generated
// content byte-for-byte (prose cannot drift), and the document itself must
// be a well-formed view of ContractVersions.
func TestDocsMatchCompatibility(t *testing.T) {
	root := repoRootForVersion(t)

	rawJSON, err := os.ReadFile(filepath.Join(root, "docs", "compatibility.json"))
	if err != nil {
		t.Fatalf("read docs/compatibility.json: %v (run KIWI_GEN=1 go test ./internal/version -run TestGenerateCompatibilityDocs -count=1)", err)
	}
	if !bytes.Equal(rawJSON, RenderCompatibilityJSON()) {
		t.Fatalf("docs/compatibility.json does not match version.RenderCompatibilityJSON; regenerate with KIWI_GEN=1 go test ./internal/version -run TestGenerateCompatibilityDocs -count=1 and commit the result")
	}

	rawMD, err := os.ReadFile(filepath.Join(root, "docs", "compatibility.md"))
	if err != nil {
		t.Fatalf("read docs/compatibility.md: %v (run KIWI_GEN=1 go test ./internal/version -run TestGenerateCompatibilityDocs -count=1)", err)
	}
	if string(rawMD) != RenderCompatibilityDoc() {
		t.Fatalf("docs/compatibility.md does not match version.RenderCompatibilityDoc; regenerate with KIWI_GEN=1 go test ./internal/version -run TestGenerateCompatibilityDocs -count=1 and commit the result")
	}

	// The JSON on disk must parse back into the same document shape the
	// generator builds (a pretty-printer regression cannot silently emit
	// something unparseable).
	var onDisk CompatibilityDocument
	if err := json.Unmarshal(rawJSON, &onDisk); err != nil {
		t.Fatalf("docs/compatibility.json does not parse: %v", err)
	}
	assertCompatibilityDocumentShape(t, onDisk)
}

// TestCompatibilityDocumentShape is the structural firewall on the generated
// document: every ContractVersions key appears in produces and consumes, the
// current value is the last consumes entry, historical accepts are strictly
// older and never equal to the current value, and the storage floor fields
// are populated from StorageSchemaVersion.
func TestCompatibilityDocumentShape(t *testing.T) {
	assertCompatibilityDocumentShape(t, BuildCompatibilityDocument())

	// The markdown companion must name every key so a dropped row is
	// visible in review, not only in the JSON.
	md := RenderCompatibilityDoc()
	for k, v := range ContractVersions {
		row := "| `" + k + "` | `" + v + "` |"
		if !strings.Contains(md, row) {
			t.Errorf("RenderCompatibilityDoc missing contract row %q", row)
		}
	}
	for _, field := range []string{"storage_schema", "minimum_reader", "minimum_writer"} {
		if !strings.Contains(md, "| `"+field+"` |") {
			t.Errorf("RenderCompatibilityDoc missing floor field %q", field)
		}
	}
}

func assertCompatibilityDocumentShape(t *testing.T, doc CompatibilityDocument) {
	t.Helper()
	if doc.Comment == "" {
		t.Error("compatibility document has no comment")
	}
	if len(doc.Produces) != len(ContractVersions) {
		t.Errorf("produces has %d rows, ContractVersions has %d", len(doc.Produces), len(ContractVersions))
	}
	for k, want := range ContractVersions {
		got, ok := doc.Produces[k]
		if !ok {
			t.Errorf("produces missing key %q", k)
			continue
		}
		if got != want {
			t.Errorf("produces[%q] = %q, ContractVersions = %q", k, got, want)
		}
		list, ok := doc.Consumes[k]
		if !ok || len(list) == 0 {
			t.Errorf("consumes missing key %q", k)
			continue
		}
		if list[len(list)-1] != want {
			t.Errorf("consumes[%q] = %v, current value %q must be the last entry", k, list, want)
		}
		for _, older := range list[:len(list)-1] {
			if older == want {
				t.Errorf("consumes[%q] = %v repeats the current value %q among historical accepts", k, list, want)
			}
		}
		// Historical accepts must be exactly the declared exception list.
		hist := compatibilityHistoricalAccepts[k]
		if len(list)-1 != len(hist) {
			t.Errorf("consumes[%q] = %v has %d historical entries, compatibilityHistoricalAccepts has %d", k, list, len(list)-1, len(hist))
			continue
		}
		for i, older := range list[:len(list)-1] {
			if older != hist[i] {
				t.Errorf("consumes[%q] historical[%d] = %q, want %q (oldest-first, matching compatibilityHistoricalAccepts)", k, i, older, hist[i])
			}
		}
	}
	if doc.StorageSchema != StorageSchemaVersion {
		t.Errorf("storage_schema = %q, want StorageSchemaVersion %q", doc.StorageSchema, StorageSchemaVersion)
	}
	if doc.MinimumReader != StorageSchemaVersion {
		t.Errorf("minimum_reader = %q, want StorageSchemaVersion %q", doc.MinimumReader, StorageSchemaVersion)
	}
	if doc.MinimumWriter != StorageSchemaVersion {
		t.Errorf("minimum_writer = %q, want StorageSchemaVersion %q", doc.MinimumWriter, StorageSchemaVersion)
	}
	// A key in consumes that ContractVersions does not know is a
	// generation bug (orphan historical accept).
	for k := range doc.Consumes {
		if _, ok := ContractVersions[k]; !ok {
			t.Errorf("consumes has unbound key %q (not in ContractVersions)", k)
		}
	}
}

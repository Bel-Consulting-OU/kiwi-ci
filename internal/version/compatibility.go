package version

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CompatibilityDocument is the machine-readable compatibility contract
// generated from ContractVersions (the authoritative registry). It names
// what this build PRODUCES (the current encoding of every durable contract),
// what it CONSUMES (the current encoding plus any historical encoding the
// readers still accept), and the persisted-state schema floor
// (storage_schema / minimum_reader / minimum_writer).
//
// docs/compatibility.json is the exact RenderCompatibilityJSON() bytes and
// docs/compatibility.md is the exact RenderCompatibilityDoc() bytes; both
// are regenerated under KIWI_GEN=1 and byte-checked by the normal test run
// (see compatibility_docs_test.go). Prose elsewhere must not restate these
// values as an independent authority.
type CompatibilityDocument struct {
	// Comment explains the document's authority. Frozen prose, not data.
	Comment string `json:"comment"`
	// Produces is ContractVersions: every durable encoding this build
	// writes under its current identifier. An algorithm under an existing
	// identifier is frozen; a new encoding gets a new version.
	Produces map[string]string `json:"produces"`
	// Consumes lists, per contract key, every encoding this build's
	// readers still accept. The current produces value is always present;
	// older entries appear only where a reader still implements them
	// (see compatibilityHistoricalAccepts).
	Consumes map[string][]string `json:"consumes"`
	// StorageSchema is the persisted state snapshot schema version
	// (StorageSchemaVersion).
	StorageSchema string `json:"storage_schema"`
	// MinimumReader is the oldest persisted-state schema whose reader can
	// still consume this build's writes. Append-only state keeps this at
	// the floor: a writer never emits a schema an older reader cannot
	// decode.
	MinimumReader string `json:"minimum_reader"`
	// MinimumWriter is the oldest persisted-state schema this build can
	// read. A writer below this floor must be upgraded before its state is
	// handed to this binary.
	MinimumWriter string `json:"minimum_writer"`
}

// compatibilityHistoricalAccepts lists encodings OLDER than the current
// ContractVersions value that this build still reads. A key absent from this
// map is consumed only under its current produces value. Adding a historical
// accept is a compatibility widening (safe); removing one is a break and
// needs a new version identifier instead.
//
// Values are listed oldest-first and must each differ from the current
// produces value (TestCompatibilityDocumentShape enforces both rules).
var compatibilityHistoricalAccepts = map[string][]string{
	// CompletionReceiptReplayMatches dispatches on the STORED hash version
	// and still resolves v1 (legacy) and v2 (runtime-bound) receipts.
	"completion_result_hash": {"1", "2"},
	// provenance.VerifyExecutionAttestation accepts schema 4 (legacy
	// name vocabulary) and 5 (facts-first, frozen meanings) alongside the
	// current schema 6.
	"evidence_schema": {"4", "5"},
}

// BuildCompatibilityDocument builds the compatibility contract document from
// the registry. Deterministic: map keys are sorted by the JSON encoder, and
// the consumes lists are historical-then-current in a fixed order.
func BuildCompatibilityDocument() CompatibilityDocument {
	produces := make(map[string]string, len(ContractVersions))
	for k, v := range ContractVersions {
		produces[k] = v
	}
	consumes := make(map[string][]string, len(ContractVersions))
	for k, current := range ContractVersions {
		list := append([]string(nil), compatibilityHistoricalAccepts[k]...)
		consumes[k] = append(list, current)
	}
	return CompatibilityDocument{
		Comment:       "Generated from internal/version.ContractVersions as the produces/consumes map. Do not hand-edit compatibility.json — run KIWI_GEN=1 go test ./internal/version -run TestGenerateCompatibilityDocs. produces is what this build writes; consumes is what this build still reads (historical encodings first, current last); storage_schema/minimum_reader/minimum_writer pin the persisted-state schema floor.",
		Produces:      produces,
		Consumes:      consumes,
		StorageSchema: StorageSchemaVersion,
		MinimumReader: StorageSchemaVersion,
		MinimumWriter: StorageSchemaVersion,
	}
}

// RenderCompatibilityJSON returns the pretty-printed JSON encoding of
// CompatibilityDocument, terminated by a newline. docs/compatibility.json is
// exactly these bytes.
func RenderCompatibilityJSON() []byte {
	b, err := json.MarshalIndent(BuildCompatibilityDocument(), "", "  ")
	if err != nil {
		// CompatibilityDocument is plain strings/slices/maps of strings:
		// MarshalIndent cannot fail on it. A panic here would be a
		// programming error in this file, not a caller-input problem.
		panic(fmt.Sprintf("version: RenderCompatibilityJSON: %v", err))
	}
	return append(b, '\n')
}

// RenderCompatibilityDoc returns the human-readable companion to
// RenderCompatibilityJSON: a markdown summary of produces/consumes and the
// storage floor. docs/compatibility.md is exactly these bytes.
func RenderCompatibilityDoc() string {
	doc := BuildCompatibilityDocument()
	keys := make([]string, 0, len(doc.Produces))
	for k := range doc.Produces {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# Kiwi compatibility contract\n\n")
	b.WriteString("Generated from `internal/version.ContractVersions` as the produces/consumes compatibility map.\n")
	b.WriteString("Do not hand-edit compatibility.md — run `KIWI_GEN=1 go test ./internal/version -run TestGenerateCompatibilityDocs`.\n")
	b.WriteString("The machine-readable twin is [`compatibility.json`](compatibility.json).\n\n")
	b.WriteString("## Produces / consumes\n\n")
	b.WriteString("| Contract | Produces | Consumes |\n|---|---|---|\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` |\n", k, doc.Produces[k], strings.Join(doc.Consumes[k], "`, `"))
	}
	b.WriteString("\n`produces` is the encoding this build writes under the current identifier.\n")
	b.WriteString("`consumes` lists every encoding this build still reads, oldest first; the\n")
	b.WriteString("current value is always the last entry. An algorithm under an existing\n")
	b.WriteString("identifier is frozen — a new encoding gets a new version (see\n")
	b.WriteString("`testdata/compat/` and `testdata/contracts/` for the producer-byte corpora).\n\n")
	b.WriteString("## Persisted-state schema floor\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| `storage_schema` | `%s` |\n", doc.StorageSchema)
	fmt.Fprintf(&b, "| `minimum_reader` | `%s` |\n", doc.MinimumReader)
	fmt.Fprintf(&b, "| `minimum_writer` | `%s` |\n", doc.MinimumWriter)
	b.WriteString("\nThe floor is append-only: a writer never emits a schema an older reader\n")
	b.WriteString("cannot decode, and this build reads state written at the floor. PostgreSQL\n")
	b.WriteString("migrations are separately append-only (see `docs/upgrades.md`).\n")
	return b.String()
}

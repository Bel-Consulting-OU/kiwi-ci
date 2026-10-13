package version

import (
	"fmt"
	"sort"
	"strings"
)

// RenderContractTable returns the canonical markdown table of every durable
// contract version. docs/CONTRACTS.md is generated from this (see
// TestGenerateContractVersionsDoc / TestDocsMatchContractVersions); prose
// elsewhere must not restate the numbers as an independent authority.
func RenderContractTable() string {
	keys := make([]string, 0, len(ContractVersions))
	for k := range ContractVersions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Kiwi contract versions\n\n")
	b.WriteString("Generated from `internal/version.ContractVersions` as the contract-version table.\n")
	b.WriteString("Do not hand-edit `docs/CONTRACTS.md` — run `KIWI_GEN=1 go test ./internal/version -run TestGenerateContractVersionsDoc`.\n\n")
	b.WriteString("| Contract | Version / tag |\n|---|---|\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", k, ContractVersions[k])
	}
	b.WriteString("\nAlgorithms under an existing identifier are frozen. Introduce a new\n")
	b.WriteString("version instead of changing an old encoding (see the completion-hash v2/v3\n")
	b.WriteString("split and the historical compatibility corpus in `testdata/contracts/`).\n")
	return b.String()
}

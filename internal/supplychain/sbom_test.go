package supplychain

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testCreated = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

func testEntries() []ArtifactEntry {
	return []ArtifactEntry{
		{Path: "dist/app", SHA256: strings.Repeat("a", 64), Size: 1234},
		{Path: "dist/checksums.txt", SHA256: strings.Repeat("b", 64), Size: 42},
	}
}

func TestGenerateSPDXJSONShape(t *testing.T) {
	b, err := GenerateSPDXJSON("kiwi", "1.2.3", "https://example.com/repo", "deadbeef", testEntries(), testCreated)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["SPDXID"] != "SPDXRef-DOCUMENT" {
		t.Fatalf("unexpected SPDXID %v", doc["SPDXID"])
	}
	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("unexpected spdxVersion %v", doc["spdxVersion"])
	}
	if doc["name"] != "kiwi" || doc["dataLicense"] != "CC0-1.0" {
		t.Fatalf("unexpected name/license: %v %v", doc["name"], doc["dataLicense"])
	}
	creation, ok := doc["creationInfo"].(map[string]any)
	if !ok {
		t.Fatal("missing creationInfo")
	}
	if creation["created"] != "2026-09-14T12:00:00Z" {
		t.Fatalf("unexpected created %v", creation["created"])
	}
	creators, ok := creation["creators"].([]any)
	if !ok || len(creators) != 1 || creators[0] != "Tool: kiwi-ci" {
		t.Fatalf("unexpected creators %v", creation["creators"])
	}
	packages, ok := doc["packages"].([]any)
	if !ok || len(packages) != 1 {
		t.Fatalf("unexpected packages %v", doc["packages"])
	}
	pkg := packages[0].(map[string]any)
	refs, ok := pkg["externalRefs"].([]any)
	if !ok || len(refs) != 1 {
		t.Fatalf("unexpected externalRefs %v", pkg["externalRefs"])
	}
	ref := refs[0].(map[string]any)
	if ref["referenceCategory"] != "PACKAGE-MANAGER" || ref["referenceType"] != "purl" {
		t.Fatalf("unexpected external ref %v", ref)
	}
	if loc := ref["referenceLocator"].(string); !strings.Contains(loc, "pkg:generic/kiwi@1.2.3") {
		t.Fatalf("unexpected purl %q", loc)
	}
	files, ok := doc["files"].([]any)
	if !ok || len(files) != 2 {
		t.Fatalf("unexpected files %v", doc["files"])
	}
	first := files[0].(map[string]any)
	if first["fileName"] != "./dist/app" {
		t.Fatalf("unexpected fileName %v", first["fileName"])
	}
	checksums := first["checksums"].([]any)
	cs := checksums[0].(map[string]any)
	if cs["algorithm"] != "SHA256" || cs["checksumValue"] != strings.Repeat("a", 64) {
		t.Fatalf("unexpected checksum %v", cs)
	}
}

func TestGenerateSPDXJSONDeterministic(t *testing.T) {
	a, err := GenerateSPDXJSON("kiwi", "1.2.3", "https://example.com/repo", "deadbeef", testEntries(), testCreated)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSPDXJSON("kiwi", "1.2.3", "https://example.com/repo", "deadbeef", testEntries(), testCreated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("spdx output must be byte-identical across runs")
	}
}

func TestGenerateCycloneDXJSONShape(t *testing.T) {
	b, err := GenerateCycloneDXJSON("kiwi", "1.2.3", "https://example.com/repo", "deadbeef", testEntries(), testCreated)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.5" {
		t.Fatalf("unexpected bom format/version: %v %v", doc["bomFormat"], doc["specVersion"])
	}
	sn := doc["serialNumber"].(string)
	if !strings.HasPrefix(sn, "urn:uuid:") {
		t.Fatalf("unexpected serial number %q", sn)
	}
	meta, ok := doc["metadata"].(map[string]any)
	if !ok || meta["timestamp"] != "2026-09-14T12:00:00Z" {
		t.Fatalf("unexpected metadata %v", doc["metadata"])
	}
	components, ok := doc["components"].([]any)
	if !ok || len(components) != 2 {
		t.Fatalf("unexpected components %v", doc["components"])
	}
	first := components[0].(map[string]any)
	if first["type"] != "file" || first["name"] != "dist/app" {
		t.Fatalf("unexpected component %v", first)
	}
	hashes := first["hashes"].([]any)
	h := hashes[0].(map[string]any)
	if h["alg"] != "SHA-256" || h["content"] != strings.Repeat("a", 64) {
		t.Fatalf("unexpected hash %v", h)
	}
}

func TestGenerateCycloneDXJSONDeterministic(t *testing.T) {
	a, err := GenerateCycloneDXJSON("kiwi", "1.2.3", "https://example.com/repo", "deadbeef", testEntries(), testCreated)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateCycloneDXJSON("kiwi", "1.2.3", "https://example.com/repo", "deadbeef", testEntries(), testCreated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("cyclonedx output must be byte-identical across runs")
	}
}

func TestParseSBOMFormat(t *testing.T) {
	for in, want := range map[string]SBOMFormat{
		"spdx-json":       SBOMSPDX,
		"SPDX-JSON":       SBOMSPDX,
		" cyclonedx-json": SBOMCycloneDX,
	} {
		got, err := ParseSBOMFormat(in)
		if err != nil || got != want {
			t.Fatalf("ParseSBOMFormat(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "spdx", "cyclonedx", "spdx-json-extra"} {
		if got, err := ParseSBOMFormat(in); err == nil {
			t.Fatalf("ParseSBOMFormat(%q) = %q, want error", in, got)
		}
	}
}

func TestAttachSBOM(t *testing.T) {
	name, err := AttachSBOM([]byte(`{"spdxVersion":"SPDX-2.3"}`), SBOMSPDX)
	if err != nil || name != "sbom.spdx.json" {
		t.Fatalf("AttachSBOM spdx = %q, %v", name, err)
	}
	name, err = AttachSBOM([]byte(`{"bomFormat":"CycloneDX"}`), SBOMCycloneDX)
	if err != nil || name != "sbom.cdx.json" {
		t.Fatalf("AttachSBOM cyclonedx = %q, %v", name, err)
	}
	if _, err := AttachSBOM([]byte(`{"bomFormat":"CycloneDX"}`), SBOMFormat("bogus")); err == nil {
		t.Fatal("unknown format must error")
	}
	if _, err := AttachSBOM(nil, SBOMSPDX); err == nil {
		t.Fatal("empty sbom must error")
	}
	if _, err := AttachSBOM([]byte(`not json`), SBOMSPDX); err == nil {
		t.Fatal("invalid json must error")
	}
}

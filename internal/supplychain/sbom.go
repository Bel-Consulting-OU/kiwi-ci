// Package supplychain implements SBOM generation (SPDX 2.3 and CycloneDX
// 1.5 JSON) and a bounded, self-contained Sigstore-style DSSE attestation
// signer and bundle verifier built only on the standard library.
package supplychain

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type SBOMFormat string

const (
	SBOMSPDX      SBOMFormat = "spdx-json"
	SBOMCycloneDX SBOMFormat = "cyclonedx-json"
)

// ArtifactEntry describes one file captured inside an artifact.
type ArtifactEntry struct {
	Path   string
	SHA256 string
	Size   int64
}

// ParseSBOMFormat converts a pipeline-level sbom value into an SBOMFormat.
func ParseSBOMFormat(s string) (SBOMFormat, error) {
	f := SBOMFormat(strings.ToLower(strings.TrimSpace(s)))
	switch f {
	case SBOMSPDX, SBOMCycloneDX:
		return f, nil
	}
	return "", fmt.Errorf("supplychain: invalid sbom format %q (want spdx-json or cyclonedx-json)", s)
}

type spdxDocument struct {
	SPDXID            string       `json:"SPDXID"`
	SPDXVersion       string       `json:"spdxVersion"`
	Name              string       `json:"name"`
	DataLicense       string       `json:"dataLicense"`
	DocumentNamespace string       `json:"documentNamespace"`
	CreationInfo      spdxCreation `json:"creationInfo"`
	Packages          []spdxPkg    `json:"packages"`
	Files             []spdxFile   `json:"files"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPkg struct {
	SPDXID           string       `json:"SPDXID"`
	Name             string       `json:"name"`
	VersionInfo      string       `json:"versionInfo,omitempty"`
	DownloadLocation string       `json:"downloadLocation"`
	FilesAnalyzed    bool         `json:"filesAnalyzed"`
	ExternalRefs     []spdxExtRef `json:"externalRefs,omitempty"`
}

type spdxExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxFile struct {
	SPDXID    string         `json:"SPDXID"`
	FileName  string         `json:"fileName"`
	Checksums []spdxChecksum `json:"checksums"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// GenerateSPDXJSON renders a deterministic SPDX 2.3 JSON document. When the
// optional created timestamp is omitted the current UTC time is used.
func GenerateSPDXJSON(name, version, repoURL, commit string, entries []ArtifactEntry, created ...time.Time) ([]byte, error) {
	when := time.Now().UTC()
	if len(created) > 0 {
		when = created[0].UTC()
	}
	doc := spdxDocument{
		SPDXID:            "SPDXRef-DOCUMENT",
		SPDXVersion:       "SPDX-2.3",
		Name:              name,
		DataLicense:       "CC0-1.0",
		DocumentNamespace: documentNamespace(name, version, repoURL, commit),
		CreationInfo:      spdxCreation{Created: when.Format(time.RFC3339), Creators: []string{"Tool: kiwi-ci"}},
		Packages: []spdxPkg{{
			SPDXID:           "SPDXRef-Package-" + name,
			Name:             name,
			VersionInfo:      version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    true,
			ExternalRefs: []spdxExtRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  "pkg:generic/" + escapePurl(name) + "@" + version,
			}},
		}},
	}
	for i, e := range entries {
		doc.Files = append(doc.Files, spdxFile{
			SPDXID:   fmt.Sprintf("SPDXRef-File-%d", i),
			FileName: "./" + strings.TrimPrefix(e.Path, "/"),
			Checksums: []spdxChecksum{{
				Algorithm:     "SHA256",
				ChecksumValue: e.SHA256,
			}},
		})
	}
	return json.MarshalIndent(doc, "", "  ")
}

type cdxDocument struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []cdxTool `json:"tools"`
}

type cdxTool struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

type cdxComponent struct {
	Type   string    `json:"type"`
	Name   string    `json:"name"`
	BOMRef string    `json:"bom-ref,omitempty"`
	Hashes []cdxHash `json:"hashes,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// GenerateCycloneDXJSON renders a deterministic CycloneDX 1.5 JSON document.
// When the optional created timestamp is omitted the current UTC time is used.
func GenerateCycloneDXJSON(name, version, repoURL, commit string, entries []ArtifactEntry, created ...time.Time) ([]byte, error) {
	when := time.Now().UTC()
	if len(created) > 0 {
		when = created[0].UTC()
	}
	doc := cdxDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + deterministicUUID(name, version, repoURL, commit),
		Version:      1,
		Metadata:     cdxMetadata{Timestamp: when.Format(time.RFC3339), Tools: []cdxTool{{Vendor: "kiwi-ci", Name: "kiwi"}}},
	}
	for _, e := range entries {
		doc.Components = append(doc.Components, cdxComponent{
			Type:   "file",
			Name:   e.Path,
			BOMRef: "pkg:file:" + e.Path,
			Hashes: []cdxHash{{Alg: "SHA-256", Content: e.SHA256}},
		})
	}
	return json.MarshalIndent(doc, "", "  ")
}

// AttachSBOM validates an SBOM payload and returns its conventional file
// name next to the artifact archive.
func AttachSBOM(sbom []byte, format SBOMFormat) (string, error) {
	if len(sbom) == 0 || !json.Valid(sbom) {
		return "", fmt.Errorf("supplychain: sbom payload is empty or not valid JSON")
	}
	switch format {
	case SBOMSPDX:
		return "sbom.spdx.json", nil
	case SBOMCycloneDX:
		return "sbom.cdx.json", nil
	default:
		return "", fmt.Errorf("supplychain: unknown sbom format %q", format)
	}
}

func documentNamespace(name, version, repoURL, commit string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{name, version, repoURL, commit}, "\x00")))
	return "https://kiwi-ci.dev/sbom/" + hex.EncodeToString(sum[:8])
}

func escapePurl(s string) string {
	return strings.NewReplacer("/", "%2F", "%", "%25").Replace(s)
}

var kiwiUUIDNamespace = []byte("kiwi-ci/uuid/v5")

func deterministicUUID(parts ...string) string {
	h := sha1.New()
	h.Write(kiwiUUIDNamespace)
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

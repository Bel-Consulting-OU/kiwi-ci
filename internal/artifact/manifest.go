package artifact

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var sha256RE = regexp.MustCompile(`^[a-f0-9]{64}$`)

type ArtifactEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// SigstoreAttestation records the DSSE attestation envelope produced for the
// artifact together with the identity claims it carries.
type SigstoreAttestation struct {
	Envelope []byte `json:"envelope"`
	Digest   string `json:"digest,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	Identity string `json:"identity,omitempty"`
}

type ArtifactManifest struct {
	Version   int                  `json:"version"`
	Name      string               `json:"name"`
	RunID     string               `json:"run_id"`
	JobID     string               `json:"job_id"`
	SHA256    string               `json:"sha256"`
	Size      int64                `json:"size"`
	Entries   []ArtifactEntry      `json:"entries"`
	CreatedAt time.Time            `json:"created_at"`
	SBOMPath  string               `json:"sbom_path,omitempty"`
	Sigstore  *SigstoreAttestation `json:"sigstore,omitempty"`
}

func ValidateManifest(m ArtifactManifest) error {
	if m.Version != 1 {
		return fmt.Errorf("artifact: unsupported manifest version %d", m.Version)
	}
	if !sha256RE.MatchString(m.SHA256) {
		return fmt.Errorf("artifact: invalid archive digest")
	}
	if m.Size < 0 {
		return fmt.Errorf("artifact: negative size")
	}
	for _, e := range m.Entries {
		if e.Path == "" || !sha256RE.MatchString(e.SHA256) || e.Size < 0 {
			return fmt.Errorf("artifact: invalid entry %q", e.Path)
		}
	}
	if m.SBOMPath != "" {
		if filepath.IsAbs(m.SBOMPath) || strings.HasPrefix(m.SBOMPath, "/") {
			return fmt.Errorf("artifact: sbom path %q must be relative", m.SBOMPath)
		}
		for _, part := range strings.FieldsFunc(m.SBOMPath, func(r rune) bool { return r == '/' || r == '\\' }) {
			if part == ".." {
				return fmt.Errorf("artifact: sbom path %q contains a .. component", m.SBOMPath)
			}
		}
	}
	if m.Sigstore != nil {
		if len(m.Sigstore.Envelope) == 0 {
			return fmt.Errorf("artifact: sigstore attestation has an empty envelope")
		}
		if m.Sigstore.Digest != "" && !sha256RE.MatchString(m.Sigstore.Digest) {
			return fmt.Errorf("artifact: sigstore attestation has an invalid digest")
		}
	}
	return nil
}

func (s *Store) SaveManifest(archivePath string, m ArtifactManifest) (string, error) {
	if err := ValidateManifest(m); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	dst := archivePath + ".manifest.json"
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		return "", err
	}
	return dst, nil
}

func ReadManifest(path string) (ArtifactManifest, error) {
	var m ArtifactManifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("artifact: decode manifest: %w", err)
	}
	if err := ValidateManifest(m); err != nil {
		return m, err
	}
	return m, nil
}

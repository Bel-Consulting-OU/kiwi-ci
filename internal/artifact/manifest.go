package artifact

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
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
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if e.Path == "" || !sha256RE.MatchString(e.SHA256) || e.Size < 0 {
			return fmt.Errorf("artifact: invalid entry %q", e.Path)
		}
		clean, err := safefs.ValidateEntryName(e.Path)
		if err != nil || clean != e.Path {
			return fmt.Errorf("artifact: unsafe entry path %q", e.Path)
		}
		key := safefs.FoldPath(clean)
		if seen[key] {
			return fmt.Errorf("artifact: duplicate manifest entry %q", e.Path)
		}
		seen[key] = true
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

// VerifyArchive checks an artifact archive against its manifest: the
// archive's byte length and SHA-256 must match, every manifest entry must be
// present with the recorded size and digest, and the archive may not carry
// undeclared, duplicate or unsafe entries. The destination path is not
// trusted: this is the read-side integrity check that must run before the
// archive's contents (or its manifest entry list) are relied upon.
func VerifyArchive(archivePath string, m ArtifactManifest) error {
	if err := ValidateManifest(m); err != nil {
		return err
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != m.Size {
		return fmt.Errorf("artifact: archive size %d does not match manifest size %d", n, m.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
		return fmt.Errorf("artifact: archive digest %s does not match manifest digest %s", got, m.SHA256)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("artifact: verify archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	want := make(map[string]ArtifactEntry, len(m.Entries))
	for _, e := range m.Entries {
		want[e.Path] = e
	}
	seen := make(map[string]bool, len(m.Entries))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("artifact: verify archive: %w", err)
		}
		clean, nerr := safefs.ValidateEntryName(hdr.Name)
		if nerr != nil {
			return fmt.Errorf("artifact: verify archive: %w: %v", safefs.ErrUnsafeEntry, nerr)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		e, ok := want[clean]
		if !ok {
			return fmt.Errorf("artifact: archive contains undeclared entry %q", clean)
		}
		if seen[clean] {
			return fmt.Errorf("artifact: archive contains duplicate entry %q", clean)
		}
		seen[clean] = true
		if hdr.Size != e.Size {
			return fmt.Errorf("artifact: entry %q size %d does not match manifest size %d", clean, hdr.Size, e.Size)
		}
		if e.Mode != 0 && uint32(hdr.Mode) != e.Mode {
			return fmt.Errorf("artifact: entry %q mode %o does not match manifest mode %o", clean, hdr.Mode, e.Mode)
		}
		digest := sha256.New()
		got, err := io.Copy(digest, tr)
		if err != nil {
			return fmt.Errorf("artifact: verify entry %q: %w", clean, err)
		}
		if got != e.Size {
			return fmt.Errorf("artifact: entry %q yielded %d bytes, want %d", clean, got, e.Size)
		}
		if sum := hex.EncodeToString(digest.Sum(nil)); sum != e.SHA256 {
			return fmt.Errorf("artifact: entry %q digest %s does not match manifest digest %s", clean, sum, e.SHA256)
		}
	}
	for _, e := range m.Entries {
		if !seen[e.Path] {
			return fmt.Errorf("artifact: manifest entry %q is missing from the archive", e.Path)
		}
	}
	return nil
}

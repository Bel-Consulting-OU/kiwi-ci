package artifact

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

var sha256RE = regexp.MustCompile(`^[a-f0-9]{64}$`)

type ArtifactEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ArtifactManifest struct {
	Version   int             `json:"version"`
	Name      string          `json:"name"`
	RunID     string          `json:"run_id"`
	JobID     string          `json:"job_id"`
	SHA256    string          `json:"sha256"`
	Size      int64           `json:"size"`
	Entries   []ArtifactEntry `json:"entries"`
	CreatedAt time.Time       `json:"created_at"`
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

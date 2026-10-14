package surfacecheck

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// capabilityManifest is the release contract: every public capability must
// name its required proofs. The gate refuses a capability with no proofs and
// an empty manifest — coverage claims are not optional annotations.
type capabilityManifest struct {
	Version      int `yaml:"version"`
	Capabilities []struct {
		ID      string   `yaml:"id"`
		Summary string   `yaml:"summary"`
		Proofs  []string `yaml:"proofs"`
	} `yaml:"capabilities"`
}

var validProofKinds = map[string]bool{
	"unit": true, "component": true, "system": true, "adversarial": true, "release": true,
}

// TestCapabilityManifestCoversPublicSurface loads capabilities.yaml and
// fails closed on any capability without a required proof, an unknown proof
// kind, or a duplicate id. The release gate runs this via surface-check.
func TestCapabilityManifestCoversPublicSurface(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "capabilities.yaml"))
	if err != nil {
		t.Fatalf("capabilities.yaml: %v", err)
	}
	var m capabilityManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse capabilities.yaml: %v", err)
	}
	if m.Version != 1 {
		t.Fatalf("capabilities.yaml version = %d, want 1", m.Version)
	}
	if len(m.Capabilities) == 0 {
		t.Fatal("capabilities.yaml lists no capabilities")
	}
	seen := map[string]bool{}
	for _, c := range m.Capabilities {
		if c.ID == "" {
			t.Fatal("capability with empty id")
		}
		if seen[c.ID] {
			t.Fatalf("duplicate capability id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Summary == "" {
			t.Fatalf("capability %q has no summary", c.ID)
		}
		if len(c.Proofs) == 0 {
			t.Fatalf("capability %q has no required proofs", c.ID)
		}
		for _, p := range c.Proofs {
			if !validProofKinds[p] {
				t.Fatalf("capability %q has unknown proof kind %q", c.ID, p)
			}
		}
	}
}

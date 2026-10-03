package components

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxComponentFileBytes bounds one registry entry read at startup.
const maxComponentFileBytes = 4 << 20

// specFileExts are the component spec file extensions recognized by the
// directory loader.
var specFileExts = map[string]bool{".yaml": true, ".yml": true, ".json": true}

// NewLocalRegistryFromDir loads every component spec file (*.yaml, *.yml,
// *.json) under dir into a LocalRegistry. Specs are indexed by their
// declared name and by their path relative to dir (both bare, e.g.
// "build.yaml", and prefixed, e.g. "components/build.yaml"), so both
// `component: build.yaml` and `component: components/build.yaml` refs
// resolve. Duplicate names are rejected.
func NewLocalRegistryFromDir(dir string) (*LocalRegistry, error) {
	reg := NewLocalRegistry()
	seenNames := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Registry files must be regular files: a symlink (or device) planted
		// in a shared registry directory must never be followed and parsed.
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("component registry: stat %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("component registry: %s is not a regular file", path)
		}
		if info.Size() > maxComponentFileBytes {
			return fmt.Errorf("component registry: %s exceeds %d bytes", path, maxComponentFileBytes)
		}
		if !specFileExts[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var spec Spec
		if err := yaml.Unmarshal(b, &spec); err != nil {
			return fmt.Errorf("components: parse %s: %w", path, err)
		}
		if strings.TrimSpace(spec.Name) == "" {
			return fmt.Errorf("components: %s: component name is required", path)
		}
		if prev, dup := seenNames[spec.Name]; dup {
			return fmt.Errorf("components: duplicate component name %q (%s and %s)", spec.Name, prev, path)
		}
		seenNames[spec.Name] = path
		reg.Register(spec)
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		reg.RegisterPath(rel, spec)
		reg.RegisterPath("components/"+rel, spec)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("components: load registry dir %s: %w", dir, err)
	}
	return reg, nil
}

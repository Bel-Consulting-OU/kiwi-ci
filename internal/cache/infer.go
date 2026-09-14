package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Lockfile is one recognized dependency-lock file found at the first level
// of a workspace.
type Lockfile struct {
	Path string `json:"path"` // workspace-relative
	Name string `json:"name"`
}

// Suggest is one explainable cache candidate. It never enables anything:
// callers decide what to do with the suggestion.
type Suggest struct {
	Name        string   `json:"name"`
	KeyTemplate string   `json:"key_template"`
	Lockfile    string   `json:"lockfile,omitempty"`
	HashFiles   []string `json:"hash_files,omitempty"`
	Paths       []string `json:"paths"`
	Reason      string   `json:"reason"`
	Status      string   `json:"status"` // always "candidate"
}

// knownLockfiles maps a first-level lock file name to its cache recipe.
type lockRecipe struct {
	cacheName   string
	paths       []string
	keyTemplate string
	reason      string
}

var knownLockfiles = map[string]lockRecipe{
	"go.sum": {
		cacheName:   "GOCACHE",
		paths:       []string{".kiwi/go-cache"},
		keyTemplate: "go-{{ hashFiles 'go.sum' }}",
		reason:      "go.sum detected: cache the Go build cache in .kiwi/go-cache",
	},
	"package-lock.json": {
		cacheName:   "node_modules",
		paths:       []string{"node_modules"},
		keyTemplate: "npm-{{ hashFiles 'package-lock.json' }}",
		reason:      "package-lock.json detected: cache node_modules",
	},
	"pnpm-lock.yaml": {
		cacheName:   "node_modules",
		paths:       []string{"node_modules"},
		keyTemplate: "pnpm-{{ hashFiles 'pnpm-lock.yaml' }}",
		reason:      "pnpm-lock.yaml detected: cache node_modules",
	},
	"yarn.lock": {
		cacheName:   "node_modules",
		paths:       []string{"node_modules"},
		keyTemplate: "yarn-{{ hashFiles 'yarn.lock' }}",
		reason:      "yarn.lock detected: cache node_modules",
	},
	"Cargo.lock": {
		cacheName:   "cargo",
		paths:       []string{"target", ".kiwi/cargo-home"},
		keyTemplate: "cargo-{{ hashFiles 'Cargo.lock' }}",
		reason:      "Cargo.lock detected: cache target/ and the CARGO_HOME cache",
	},
	"poetry.lock": {
		cacheName:   "poetry",
		paths:       []string{".venv", ".kiwi/poetry-cache"},
		keyTemplate: "poetry-{{ hashFiles 'poetry.lock' }}",
		reason:      "poetry.lock detected: cache .venv and the poetry cache",
	},
	"uv.lock": {
		cacheName:   "uv",
		paths:       []string{".venv", ".kiwi/uv-cache"},
		keyTemplate: "uv-{{ hashFiles 'uv.lock' }}",
		reason:      "uv.lock detected: cache .venv and the uv cache",
	},
	"Gemfile.lock": {
		cacheName:   "bundler",
		paths:       []string{"vendor/bundle"},
		keyTemplate: "bundler-{{ hashFiles 'Gemfile.lock' }}",
		reason:      "Gemfile.lock detected: cache vendor/bundle",
	},
}

// InferLockfiles scans the first level of workspace for recognized lock
// files. It never recurses into subdirectories so monorepo tooling can
// report per-directory lock files explicitly.
func InferLockfiles(workspace string) []Lockfile {
	var out []Lockfile
	entries, err := os.ReadDir(workspace)
	if err != nil {
		return out
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := knownLockfiles[e.Name()]; !ok || seen[e.Name()] {
			continue
		}
		seen[e.Name()] = true
		out = append(out, Lockfile{Path: e.Name(), Name: e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SuggestCaches inspects the first level of workspace and returns
// explainable cache candidates derived from recognized lock files. Nothing
// is enabled: each entry is marked "candidate".
func SuggestCaches(workspace string) []Suggest {
	lockfiles := InferLockfiles(workspace)
	out := make([]Suggest, 0, len(lockfiles))
	for _, lf := range lockfiles {
		recipe := knownLockfiles[lf.Name]
		out = append(out, Suggest{
			Name:        recipe.cacheName,
			KeyTemplate: recipe.keyTemplate,
			Lockfile:    lf.Path,
			HashFiles:   []string{lf.Path},
			Paths:       append([]string(nil), recipe.paths...),
			Reason:      recipe.reason,
			Status:      "candidate",
		})
	}
	return out
}

// VerifyLockfile checks that a lock file exists as a regular first-level
// file in workspace. Used by callers that want to validate a suggestion
// before acting on it.
func VerifyLockfile(workspace, name string) error {
	if filepath.IsAbs(name) || name == "." || name == ".." {
		return fmt.Errorf("lockfile %s escapes workspace", name)
	}
	path := filepath.Join(workspace, name)
	rel, err := filepath.Rel(workspace, path)
	if err != nil || rel != filepath.Base(name) {
		return fmt.Errorf("lockfile %s escapes workspace", name)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("lockfile %s is a directory", name)
	}
	return nil
}

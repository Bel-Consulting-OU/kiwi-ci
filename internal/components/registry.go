package components

import (
	"context"
	"fmt"
	"strings"
)

// Registry resolves component references to specs plus their content digest.
// Implementations must be safe for concurrent use. Remote registries must
// enforce digest pinning: a Resolve returning a spec whose Digest does not
// match the pinned digest in the ref is an error.
type Registry interface {
	Resolve(ctx context.Context, ref string) (Spec, string /*digest*/, error)
}

// LocalRegistry is a map-based registry used by tests and by single-node
// deployments. Specs are indexed by name (for pinned remote refs) and by
// local path.
type LocalRegistry struct {
	byName map[string]Spec
	byPath map[string]Spec
}

// NewLocalRegistry returns an empty map-based registry.
func NewLocalRegistry() *LocalRegistry {
	return &LocalRegistry{byName: map[string]Spec{}, byPath: map[string]Spec{}}
}

// Register indexes a spec under its Name. Registering the same name twice
// overwrites the previous entry.
func (r *LocalRegistry) Register(spec Spec) {
	r.byName[spec.Name] = spec
}

// RegisterPath indexes a spec under a local path reference (e.g.
// "components/build.yaml").
func (r *LocalRegistry) RegisterPath(path string, spec Spec) {
	r.byPath[path] = spec
}

// Resolve implements Registry. Pinned refs (name@sha256:...) resolve by name
// and verify the computed digest against the pinned one; bare refs resolve
// as local paths.
func (r *LocalRegistry) Resolve(ctx context.Context, ref string) (Spec, string, error) {
	_ = ctx
	if err := ResolveComponentRef(ref); err != nil {
		return Spec{}, "", err
	}
	var spec Spec
	var pinned string
	if strings.Contains(ref, "@") {
		name, digest := splitRemoteRef(ref)
		ok := false
		spec, ok = r.byName[name]
		if !ok {
			return Spec{}, "", fmt.Errorf("component %q not found", name)
		}
		pinned = digest
	} else {
		var ok bool
		spec, ok = r.byPath[ref]
		if !ok {
			return Spec{}, "", fmt.Errorf("component at path %q not found", ref)
		}
	}
	digest, err := Digest(spec)
	if err != nil {
		return Spec{}, "", err
	}
	if pinned != "" && pinned != digest {
		return Spec{}, "", fmt.Errorf("component %q digest mismatch: resolved %s, pipeline pins %s", spec.Name, digest, pinned)
	}
	return spec, digest, nil
}

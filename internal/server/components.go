package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// resolveComponents resolves every job-level component reference in the spec
// server-side and merges the component fragment into the invoking job. The
// resolved pipeline is self-contained: component and with are cleared so the
// canonical pipeline text runners receive never carries a reference.
//
// Resolution is digest-pinned: remote refs must be name@sha256:<hex> and the
// registry must return a spec whose digest matches. The returned map records
// the resolved digest per job key, which enqueue stores on the model job
// (Job.ComponentDigest).
func (s *Server) resolveComponents(ctx context.Context, spec *pipeline.Spec) (map[string]string, error) {
	digests := map[string]string{}
	if s.ComponentRegistry == nil {
		for key, j := range spec.Jobs {
			if j.Component != "" {
				return nil, fmt.Errorf("job %q references component %q but the server has no component registry configured", key, j.Component)
			}
		}
		return digests, nil
	}
	for key, j := range spec.Jobs {
		if j.Component == "" {
			continue
		}
		cspec, digest, err := s.ComponentRegistry.Resolve(ctx, j.Component)
		if err != nil {
			return nil, fmt.Errorf("job %q component %q: %w", key, j.Component, err)
		}
		if err := components.Apply(cspec, &j, j.With); err != nil {
			return nil, fmt.Errorf("job %q component %q: %w", key, j.Component, err)
		}
		j.Component = ""
		j.With = nil
		spec.Jobs[key] = j
		digests[key] = digest
	}
	return digests, nil
}

// validateRunInputs checks the submission's inputs (Metadata keys of the
// form "input.<name>") against the pipeline's declared inputs: unknown
// inputs are rejected, required inputs must be present, and values must
// satisfy the declared type (string, boolean, integer, enum).
func validateRunInputs(spec *pipeline.Spec, meta map[string]string) (map[string]string, error) {
	provided := map[string]string{}
	for k, v := range meta {
		if strings.HasPrefix(k, "input.") {
			provided[strings.TrimPrefix(k, "input.")] = v
		}
	}
	return pipeline.ValidateRunInputs(spec, provided)
}

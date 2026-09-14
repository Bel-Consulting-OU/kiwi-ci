package server

import (
	"context"
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// maxPipelineBytes mirrors the pipeline parser's source limit for the
// intermediate decode.
const maxPipelineBytes = 2 << 20

// resolvePipeline is the enqueue-time pipeline resolution hook: it decodes
// the submitted pipeline, resolves component references server-side, applies
// and validates run inputs, and renders the result into the canonical
// pipeline text that every job carries and every runner recompiles.
//
// The intermediate decode intentionally skips pipeline.Parse's validation:
// a component job may legitimately have no steps of its own before its
// component fragment is merged in. The final pipeline.Parse on the canonical
// text re-applies the full admission validation, so nothing unvalidated ever
// reaches compilation.
func (s *Server) resolvePipeline(ctx context.Context, in SubmitRun) (*pipeline.Spec, string, map[string]string, error) {
	if len(in.Pipeline) > maxPipelineBytes {
		return nil, "", nil, fmt.Errorf("pipeline exceeds %d byte limit", maxPipelineBytes)
	}
	var raw pipeline.Spec
	if err := yaml.Unmarshal([]byte(in.Pipeline), &raw); err != nil {
		return nil, "", nil, fmt.Errorf("parse pipeline: %w", err)
	}
	digests, err := s.resolveComponents(ctx, &raw)
	if err != nil {
		return nil, "", nil, err
	}
	inputs, err := validateRunInputs(&raw, in.Metadata)
	if err != nil {
		return nil, "", nil, err
	}
	applyInputEnv(&raw, inputs)
	b, err := pipeline.CanonicalJSON(&raw)
	if err != nil {
		return nil, "", nil, err
	}
	spec, err := pipeline.Parse(b)
	if err != nil {
		return nil, "", nil, err
	}
	return spec, string(b), digests, nil
}

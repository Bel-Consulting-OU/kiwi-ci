package server

import (
	"context"
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// maxPipelineBytes mirrors the pipeline parser's source limit for the
// intermediate decode.
const maxPipelineBytes = 2 << 20

// resolvePipeline is the enqueue-time pipeline resolution hook: it strictly
// parses the ORIGINAL submitted document first (unknown fields, duplicate
// keys, aliases, tags and limits are rejected on the original bytes with
// line numbers, with the single relaxation that component-referencing jobs
// may omit their own steps), resolves component references server-side,
// validates and interpolates run inputs into the effective spec, and
// renders the result into the canonical pipeline text that every job
// carries and every runner recompiles.
//
// The final pipeline.Parse on the canonical text re-applies the full
// admission validation on the assembled (component-merged, input-resolved)
// spec, so nothing unvalidated ever reaches compilation. The returned spec
// carries the resolved inputs (Spec.ProvidedInputs) so the enqueue compile
// derives digests and payloads from the effective compiled result.
func (s *Server) resolvePipeline(ctx context.Context, in SubmitRun) (*pipeline.Spec, string, map[string]string, error) {
	if len(in.Pipeline) > maxPipelineBytes {
		return nil, "", nil, fmt.Errorf("pipeline exceeds %d byte limit", maxPipelineBytes)
	}
	raw, err := pipeline.ParseWithComponents([]byte(in.Pipeline))
	if err != nil {
		return nil, "", nil, err
	}
	digests, err := s.resolveComponents(ctx, raw)
	if err != nil {
		return nil, "", nil, err
	}
	inputs, err := validateRunInputs(raw, in.Metadata)
	if err != nil {
		return nil, "", nil, err
	}
	effective, err := pipeline.ResolveInputs(raw, inputs)
	if err != nil {
		return nil, "", nil, err
	}
	b, err := pipeline.CanonicalJSON(effective)
	if err != nil {
		return nil, "", nil, err
	}
	spec, err := pipeline.Parse(b)
	if err != nil {
		return nil, "", nil, err
	}
	spec.ProvidedInputs = inputs
	return spec, string(b), digests, nil
}

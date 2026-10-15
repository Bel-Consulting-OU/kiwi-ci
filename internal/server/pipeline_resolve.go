package server

import (
	"context"
	"fmt"
	"strings"

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
// validates and interpolates run inputs into the effective spec, applies
// the repository image lockfile to EVERY executable identity (job, service,
// VM — including images introduced by components), and renders the result
// into the canonical pipeline text that every job carries and every runner
// recompiles.
//
// Image locking lives HERE — not at webhook ingress. The webhook is
// transport/trigger authority; this function is execution-input authority.
// A lock fetched at the exact source revision is applied AFTER component
// expansion so component-injected images are pinned too, and BEFORE the
// canonical text/digest is produced so the compiled graph and every
// downstream digest bind the immutable identities.
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
	// Image lock is part of the compiled-graph identity: apply it to the
	// effective (component-merged, input-resolved) spec before
	// canonicalization so the graph digest binds the locked digests.
	if err := applyImageLockContent(effective, in.ImageLock); err != nil {
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

// applyImageLockContent applies a fetched lockfile document to the effective
// spec. Empty content means "no lockfile" (authoring tags stay as written
// under ordinary trusted policy). A nonempty document that is not a
// well-formed lockfile is FAIL-CLOSED. Once a lockfile EXISTS it must be
// COMPLETE: every mutable executable identity must have an entry — a lock
// that silently omits a tag (or a component-injected image) defeats its own
// meaning.
func applyImageLockContent(spec *pipeline.Spec, content string) error {
	// Only a truly absent document ("" from a 404) is "no lockfile".
	// Whitespace-only content is a present-but-empty authority document
	// and must fail closed — the same rule as a local empty lock.json.
	if content == "" {
		return nil
	}
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("image lockfile exists but is empty")
	}
	lock, err := pipeline.ParseImageLockfile([]byte(content))
	if err != nil {
		return fmt.Errorf("image lockfile: %w", err)
	}
	m := lock.LockMap()
	if err := spec.RequireComplete(m); err != nil {
		return fmt.Errorf("image lockfile: %w", err)
	}
	spec.ApplyImageLock(m)
	return nil
}

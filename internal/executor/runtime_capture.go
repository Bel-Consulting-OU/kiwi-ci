package executor

import (
	"context"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Observed-runtime capture bounds. Every capture command runs under the job
// context AND these ceilings through the shared phaseCommand helper, so a
// wedged daemon/CLI can never stall a job that already started, and capture
// failures are omissions, never job failures.
const (
	// observedCaptureTimeout bounds the WHOLE capture pass (one version probe
	// plus one inspect per distinct image), so a broken runtime cannot add
	// more than this to job startup.
	observedCaptureTimeout = 20 * time.Second
	// maxObservedServiceImages bounds how many DISTINCT service images are
	// inspected. Images beyond the bound are still recorded in
	// ServiceImages (the declared reference is known), but their digest is
	// omitted rather than spending unbounded time.
	maxObservedServiceImages = 16
	// Bounds on the recorded strings, so a hostile runtime cannot inject an
	// oversized evidence blob into the completion payload.
	observedMaxVersionBytes = 128
	observedMaxRefBytes     = 512
	observedMaxDigestBytes  = 512
)

// runtimeObserver is the optional Backend capability exposing the runtime
// facts captured while the job ran. It is deliberately separate from Backend
// so the core interface (Name/Run/ReadFile) stays small, and a backend that
// captures nothing simply does not implement it.
type runtimeObserver interface {
	ObservedRuntime() *model.ObservedRuntime
}

// observedRuntimeOf returns the backend's captured runtime facts, or nil when
// the backend does not observe them.
func observedRuntimeOf(b Backend) *model.ObservedRuntime {
	o, ok := b.(runtimeObserver)
	if !ok {
		return nil
	}
	return o.ObservedRuntime()
}

// clampObserved trims and truncates one captured string to a bound. A value
// that is empty or cannot be represented is dropped ("").
func clampObserved(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	// The completion wire is validated server-side: a value that is not
	// valid UTF-8 or carries control characters would be refused as
	// malformed, so the capture drops it instead of failing the completion.
	if strings.ContainsAny(s, "\x00\n\r") || !utf8.ValidString(s) {
		return ""
	}
	return s
}

// captureContainerObservedRuntime collects the container runtime facts after
// the job container started: GOOS/GOARCH, the docker server version, and the
// image digests of the main image and every declared service image. It is
// best-effort: every probe that errors or times out contributes an omission,
// and the returned struct is always non-nil with the facts that could be
// established.
func captureContainerObservedRuntime(ctx context.Context, docker, mainImage string, serviceImages map[string]string) *model.ObservedRuntime {
	obs := &model.ObservedRuntime{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		RuntimeName: "docker",
		MainImage:   clampObserved(mainImage, observedMaxRefBytes),
		CapturedAt:  time.Now().UTC(),
	}
	cctx, cancel := context.WithTimeout(ctx, observedCaptureTimeout)
	defer cancel()
	if out, err := phaseCommand(cctx, runtimeProbeTimeout, docker, "version", "--format", "{{.Server.Version}}"); err == nil {
		obs.RuntimeVersion = clampObserved(string(out), observedMaxVersionBytes)
	}
	obs.MainImageDigest = dockerImageDigest(cctx, docker, mainImage)
	// Service images: deduplicate by reference (one inspect per distinct
	// image) and inspect in deterministic name order, so the same job always
	// produces the same capture. Once the distinct-image bound is reached
	// every remaining reference is still recorded but its digest is omitted.
	names := make([]string, 0, len(serviceImages))
	for name := range serviceImages {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]string{}
	inspected := 0
	for _, name := range names {
		ref := serviceImages[name]
		if ref == "" {
			continue
		}
		digest, ok := seen[ref]
		if !ok {
			if inspected < maxObservedServiceImages {
				digest = dockerImageDigest(cctx, docker, ref)
				inspected++
			}
			seen[ref] = digest
		}
		if obs.ServiceImages == nil {
			obs.ServiceImages = map[string]string{}
		}
		obs.ServiceImages[name] = clampObserved(ref, observedMaxRefBytes)
		if digest != "" {
			if obs.ServiceImageDigests == nil {
				obs.ServiceImageDigests = map[string]string{}
			}
			obs.ServiceImageDigests[name] = digest
		}
	}
	return obs
}

// dockerImageDigest resolves one image reference to a content digest: a
// digest-pinned reference records its pinned digest without any daemon call
// (the pin is what the run enforced), otherwise a bounded
// `docker image inspect --format '{{index .RepoDigests 0}}'` is attempted.
// Any error, timeout or empty output omits the digest — a tag is never
// promoted to a digest.
func dockerImageDigest(ctx context.Context, docker, ref string) string {
	if d, ok := pinnedDigest(ref); ok {
		return d
	}
	if docker == "" || ref == "" {
		return ""
	}
	out, err := phaseCommand(ctx, runtimeProbeTimeout, docker, "image", "inspect", "--format", "{{index .RepoDigests 0}}", "--", ref)
	if err != nil {
		return ""
	}
	return clampObserved(string(out), observedMaxDigestBytes)
}

// serviceImageRefs maps a compiled job's service declarations to the
// declared-name -> image-reference map observed-runtime capture consumes. An
// anonymous service falls back to its image reference as the name, matching
// the display fallback; duplicate names keep the last declaration, exactly
// like docker's own name collision rules refuse duplicates at admission.
func serviceImageRefs(services []pipeline.Service) map[string]string {
	if len(services) == 0 {
		return nil
	}
	out := make(map[string]string, len(services))
	for _, svc := range services {
		name := strings.TrimSpace(svc.Name)
		if name == "" {
			name = svc.Image
		}
		out[name] = svc.Image
	}
	return out
}

// captureTartObservedRuntime collects the Tart runtime facts: the tart CLI
// version from a bounded `tart --version` and the host OS/arch. Tart has no
// image digest surface, so no digests are recorded.
func captureTartObservedRuntime(ctx context.Context, tart string) *model.ObservedRuntime {
	obs := &model.ObservedRuntime{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		RuntimeName: "tart",
		CapturedAt:  time.Now().UTC(),
	}
	cctx, cancel := context.WithTimeout(ctx, observedCaptureTimeout)
	defer cancel()
	if out, err := phaseCommand(cctx, runtimeProbeTimeout, tart, "--version"); err == nil {
		obs.RuntimeVersion = clampObserved(string(out), observedMaxVersionBytes)
	}
	return obs
}

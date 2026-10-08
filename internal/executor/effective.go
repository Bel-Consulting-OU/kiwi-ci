package executor

import "github.com/Bel-Consulting-OU/kiwi-ci/internal/execution"

// OptionsFromExecution overlays every executor option the materialized
// effective execution determines onto base and returns it. It is the ONE
// mapping shared by the distributed runner and exact replay, so a replayed
// job gets the same untrusted floor, immutable-image requirement and workspace
// bound the recorded distributed run executed under.
//
// Caller-supplied options that are not part of EffectiveExecution (workspace,
// logs, cache, secrets, artifact capture, quota status, lifecycle contexts)
// are preserved untouched. The hard-quota requirement
// (RequireUntrustedDiskQuota) is deliberately NOT derived here: whether an
// OS-level workspace bound can be installed is a property of the runner host
// and its operator escape hatch, not of the persisted job, so the distributed
// runner sets it from its own environment and local replay leaves it off.
func OptionsFromExecution(base Options, e execution.EffectiveExecution) Options {
	base.Untrusted = e.Untrusted
	base.RequireImmutableImages = e.RequireImmutableImages
	base.WorkspaceMaxBytes = e.WorkspaceMaxBytes
	return base
}

package server

import (
	"context"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// retryStagingCleanup runs the shared budget's pending-cleanup retry: every
// spool file whose removal failed after its bytes were no longer needed is
// retried here (Maintain calls this every tick). Until a retry succeeds the
// bytes stay charged and the spool stays registered, so Used() keeps
// reflecting physical occupancy and no new reservation can be admitted
// against unreclaimable bytes. A still-failing removal is logged with the
// pending count, which is the observable degraded/cleanup-required condition.
func (s *Server) retryStagingCleanup(ctx context.Context) {
	b := s.StagingBudget()
	if b == nil || b.PendingCleanup() == 0 {
		return
	}
	removed, err := b.RetryCleanup(ctx)
	if err != nil {
		s.logError("staging: pending spool cleanup retry failed", "removed", removed, "pending", b.PendingCleanup(), "error", err.Error())
		return
	}
	if removed > 0 {
		s.logf("staging: reclaimed %d pending spool file(s)", removed)
	}
}

// StagingBudget returns the shared weighted staging budget every large-upload
// path must charge before spooling bytes: the job cache upload and (through
// the snapshot agent) the workspace snapshot upload. Persistent servers
// always carry one (defaulted under the data dir by the constructors and
// supplied by the configured budget through server.WithStagingBudget at
// construction); it is nil only on a bare in-memory server, where the
// large-upload routes are unreachable (they all require a persistent store or
// CAS). Callers must nil-check and fail closed.
//
// Ownership contract: the budget owns exactly one directory. The persistent
// constructors and the app wiring build it through staging.NewReplicaBudget,
// so the directory is the replica's private <configured-root>/<instance-id>
// (a generated id persisted in the root when none is configured) and not a
// path other replicas also stage into. The constructor took exclusive
// ownership of it (owner lock) and reclaimed every spool file left by a dead
// process, so Used() starts from a truthful zero; the process holds ownership
// until exit. A second live process that resolves to the same directory fails
// startup with staging.ErrStagingDirOwned rather than doubling the bound.
//
// This accessor is the stable consumption point for the snapshot path:
// s.StagingBudget().Acquire(ctx, n) / res.Release(), and
// s.StagingBudget().SpoolFile(body, n) for the staged bytes (the spool is
// registered active with the budget, so a concurrent Prune cannot unlink it).
func (s *Server) StagingBudget() *staging.Budget { return s.Staging }

// installStagingBudget is the construction-time-only staging wiring: it
// records the server's shared budget (and, when a CAS already exists, the
// budget that CAS spools through) and panics if called after construction. It
// is unexported and guarded by stagingSealed, so a live server can never swap
// its staging budget. The previous exported SetStagingBudget allowed a
// post-construction replacement that left in-flight requests charging the old
// budget while new requests charged the new one — a temporary double bound
// over the same disk. WithStagingBudget is the supported construction-time
// entry point; a persistent constructor's data-dir default is installed
// directly before the seal.
func (s *Server) installStagingBudget(b *staging.Budget) {
	if s.stagingSealed {
		panic("server: staging budget is immutable after construction (pass WithStagingBudget to a constructor instead)")
	}
	// stagingSet distinguishes an explicit nil (no staging bound; large
	// uploads fail closed) from "not supplied" (build the data-dir default).
	s.stagingSet = true
	s.Staging = b
	if s.CAS != nil {
		s.CAS.Staging = b
	}
}

// sealStaging marks the end of a server's construction: from here on the
// staging budget is immutable and installStagingBudget panics.
func (s *Server) sealStaging() { s.stagingSealed = true }

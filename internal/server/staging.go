package server

import "github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"

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
// staging.SpoolFile(s.StagingBudget().Dir(), body, n) for the staged bytes.
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

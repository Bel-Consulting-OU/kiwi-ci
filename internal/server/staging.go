package server

import "github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"

// StagingBudget returns the shared weighted staging budget every large-upload
// path must charge before spooling bytes: the job cache upload and (through
// the snapshot agent) the workspace snapshot upload. Persistent servers
// always carry one (defaulted under the data dir by the constructors and
// replaced by the configured budget in the app wiring); it is nil only on a
// bare in-memory server, where the large-upload routes are unreachable
// (they all require a persistent store or CAS). Callers must nil-check and
// fail closed.
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

// SetStagingBudget installs the shared staging budget. The app wiring calls
// it after config.Validate and staging.NewReplicaBudget (or supplies the same
// budget through server.WithStagingBudget at construction), so an unusable
// configured bound — or a directory owned by another live replica — fails
// startup instead of the first multi-GB upload. Replacing a budget does not
// release the previous one's ownership (production replaces only the
// data-dir default, whose directory stays reserved for this process).
//
// The installed budget is also pushed onto the live CAS instance: the legacy
// CAS.Put fallback spools through CAS.Staging, so a budget installed after the
// CAS was built must not leave the fallback failing ErrNoSpool. The
// constructor path installs the budget before newServerCAS, and SetBlobStore
// preserves the current budget, so all three wiring paths agree.
func (s *Server) SetStagingBudget(b *staging.Budget) {
	s.Staging = b
	if s.CAS != nil {
		s.CAS.Staging = b
	}
}

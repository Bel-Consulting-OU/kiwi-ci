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
// This accessor is the stable consumption point for the snapshot path:
// s.StagingBudget().Acquire(ctx, n) / res.Release(), and
// staging.SpoolFile(s.StagingBudget().Dir(), body, n) for the staged bytes.
func (s *Server) StagingBudget() *staging.Budget { return s.Staging }

// SetStagingBudget installs the shared staging budget. The app wiring calls
// it after config.Validate and staging.NewBudget, so an unusable configured
// bound fails startup instead of the first multi-GB upload.
func (s *Server) SetStagingBudget(b *staging.Budget) { s.Staging = b }

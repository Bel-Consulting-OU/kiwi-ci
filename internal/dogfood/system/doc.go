// Package system is the SYSTEM-species dogfood harness: it drives a real
// Kiwi control plane and a real runner through the production HTTP surface,
// never through the in-memory model harness in internal/dogfood.
//
// Species = system. Everything under test here is the product path:
//
//	server.NewPersistent → Server.Handler() → httptest listener
//	POST /api/v1/runs → GET /api/v1/runs/{id}/jobs
//	runner.Runner.Run → register / next / execute / complete
//	outbox → attestExecution → GET /api/v1/jobs/{id}/attestation
//
// The in-memory model Harness (internal/dogfood/harness.go) stays the
// reference/oracle for state-machine races. A green model scenario is never
// proof that the HTTP handler → authorization → store transaction →
// generation predicate → ledger path accepted or rejected a request; this
// package exists to close that gap on the surfaces it can reach without
// Docker/Postgres/XFS.
//
// Mutation rule. The harness never writes to the durable store except through
// the public API being tested. Read-only secondary inspection of
// server.Server state is allowed as an oracle surface only.
//
// Prerequisites. Native-runtime pipelines execute on the host without Docker.
// The untrusted hard-quota gate's fail-closed arm is exercised on any host
// (including darwin, where project quotas do not exist); the positive arm
// (hard quota available → admitted) requires Linux XFS prjquota and is
// documented as unproven here rather than faked.
package system

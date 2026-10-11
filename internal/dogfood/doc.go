// Package dogfood is the INTERNAL 360° dogfood harness for Kiwi: it launches
// the system under test against a named topology, seeds repositories and
// runs, drives scenarios (including hostile and fault-injected ones), and
// proves the evidence contract from the OUTSIDE.
//
// Outer-oracle philosophy. The harness never asserts on Kiwi's internal call
// graphs or private helpers. Every scenario outcome is decided by an outer
// oracle that cross-checks EIGHT independent surfaces of the same run:
//
//  1. client result      — what the public API returned to the caller
//  2. authoritative state — the durable control-plane records
//  3. ledger             — the crash-recovery / event ledger
//  4. runner authority   — which runner held the lease and what it reported
//  5. artifacts          — the collected artifact bytes and identities
//  6. evidence           — the signed attestation envelopes
//  7. external effects   — out-of-band effect sinks (deployments, OIDC)
//  8. recovery           — what a restart/reclaim reconciled
//
// A scenario is green only when every surface present an independent account
// and all eight agree. One surface cannot grade itself.
//
// Read-only state oracle. Beyond the per-scenario eight-oracle check, the
// harness exposes a state oracle that only READS the system under test. The
// dogfood program must never mutate the database (or any durable store)
// except through the public surface being tested; the sole write path in
// this package is the scenario's own seed/setup, and the oracle itself is
// strictly read-only. Evidence verification, quota truthfulness and
// consistency checks are pure functions of what the system already persisted.
package dogfood

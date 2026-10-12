// Package dist is the live multi-process dogfood topology: a real
// PostgreSQL, a real kiwi server process, and two real kiwi runner
// processes, all spawned as separate OS processes via exec.Command.
//
// This package proves DF-DIST-001 (live multi-process topology) and
// DF-DR-001 (backup → destroy → restore) against the production binary
// surface — not the in-process system.System harness. Every component
// (database, control plane, runners) runs in its own operating-system
// process, exactly as a production deployment does.
//
// Real vs in-process:
//
//	PostgreSQL     real (initdb + postgres, or KIWI_TEST_POSTGRES_URL)
//	kiwi server    real OS process (exec.Command the built kiwi binary)
//	kiwi runner    real OS processes (two: runner A and runner B)
//	git checkout   real (local dumb-HTTP git mirror, KIWI_ALLOW_INSECURE_CLONE)
//	API client     in-process HTTP calls from the test (the external client)
//
// Nothing in the topology is faked: the server talks to PostgreSQL over
// TCP, the runners talk to the server over HTTP, and the runners clone
// their workspaces over HTTP. The test process itself only acts as the
// external API client and the process supervisor.
package dist

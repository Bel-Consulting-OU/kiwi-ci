package storage

// Real-PostgreSQL integration tests for the shared cluster-key blob store
// (the HA key-material contract): schema bootstrap, create-if-absent CAS,
// explicit rotation with a version bump, and the cross-replica rotation
// fence. Gated on KIWI_TEST_POSTGRES_URL through the shared pgIT helpers.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPostgresIntegrationClusterKeySchemaAndValidation: the schema bootstrap
// is idempotent, and every method rejects empty identifiers/material and a
// store without an open pool before touching SQL.
func TestPostgresIntegrationClusterKeySchemaAndValidation(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := st.EnsureClusterKeySchema(ctx); err != nil {
			t.Fatalf("EnsureClusterKeySchema (call %d): %v", i+1, err)
		}
	}
	// The table has the pinned shape: kind is the primary key.
	var pk string
	if err := st.pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='cluster_keys'::regclass AND contype='p'`).Scan(&pk); err != nil {
		t.Fatalf("read primary key: %v", err)
	}
	if !strings.Contains(pk, "kind") {
		t.Fatalf("cluster_keys primary key = %q, want kind", pk)
	}

	if _, _, err := st.GetClusterKey(ctx, ""); err == nil {
		t.Fatal("GetClusterKey with an empty kind accepted")
	}
	if _, _, err := st.CreateClusterKey(ctx, "", []byte("d")); err == nil {
		t.Fatal("CreateClusterKey with an empty kind accepted")
	}
	if _, _, err := st.CreateClusterKey(ctx, "lease", nil); err == nil {
		t.Fatal("CreateClusterKey with empty material accepted")
	}
	if err := st.PutClusterKey(ctx, "", []byte("d")); err == nil {
		t.Fatal("PutClusterKey with an empty kind accepted")
	}
	if err := st.PutClusterKey(ctx, "lease", []byte{}); err == nil {
		t.Fatal("PutClusterKey with empty material accepted")
	}
	if _, _, err := st.ClusterKeyVersion(ctx, ""); err == nil {
		t.Fatal("ClusterKeyVersion with an empty kind accepted")
	}
	if err := st.WithClusterKeyRotationFence(ctx, "", func() error { return nil }); err == nil {
		t.Fatal("rotation fence with an empty kind accepted")
	}
	if err := st.WithClusterKeyRotationFence(ctx, "lease", nil); err == nil {
		t.Fatal("rotation fence without a function accepted")
	}

	// A store without an open pool fails closed on every entry point instead
	// of panicking on a nil pool.
	closed := &PostgresStore{}
	if _, _, err := closed.GetClusterKey(ctx, "lease"); err == nil {
		t.Fatal("closed store GetClusterKey succeeded")
	}
	if _, _, err := closed.CreateClusterKey(ctx, "lease", []byte("d")); err == nil {
		t.Fatal("closed store CreateClusterKey succeeded")
	}
	if err := closed.PutClusterKey(ctx, "lease", []byte("d")); err == nil {
		t.Fatal("closed store PutClusterKey succeeded")
	}
	if _, _, err := closed.ClusterKeyVersion(ctx, "lease"); err == nil {
		t.Fatal("closed store ClusterKeyVersion succeeded")
	}
	if err := closed.EnsureClusterKeySchema(ctx); err == nil {
		t.Fatal("closed store EnsureClusterKeySchema succeeded")
	}
	if err := closed.WithClusterKeyRotationFence(ctx, "lease", func() error { return nil }); err == nil {
		t.Fatal("closed store rotation fence succeeded")
	}
}

// TestPostgresIntegrationClusterKeyCreateEveryCallerSeesOneMaterial is the
// CAS proof: the first creator's bytes win for every later creator (returned
// with created=false), absent kinds report not-found, versions advance only
// on Put, and a re-create after a rotation does NOT return the rotated
// material to a caller that thinks it won.
func TestPostgresIntegrationClusterKeyCreateEveryCallerSeesOneMaterial(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	if err := st.EnsureClusterKeySchema(ctx); err != nil {
		t.Fatal(err)
	}
	if b, found, err := st.GetClusterKey(ctx, "oidc"); err != nil || found || b != nil {
		t.Fatalf("absent kind = (%v, %v, %v)", b, found, err)
	}
	if v, found, err := st.ClusterKeyVersion(ctx, "oidc"); err != nil || found || v != 0 {
		t.Fatalf("absent version = (%d, %v, %v)", v, found, err)
	}

	first := []byte("ring-1")
	got, created, err := st.CreateClusterKey(ctx, "oidc", first)
	if err != nil || !created || !bytes.Equal(got, first) {
		t.Fatalf("first create = (%q, %v, %v)", got, created, err)
	}
	// A concurrent (or restarted) creator's material must NEVER be returned.
	second := []byte("ring-2")
	got, created, err = st.CreateClusterKey(ctx, "oidc", second)
	if err != nil || created || !bytes.Equal(got, first) {
		t.Fatalf("second create = (%q, %v, %v), want the winner ring-1", got, created, err)
	}
	if v, found, err := st.ClusterKeyVersion(ctx, "oidc"); err != nil || !found || v != 1 {
		t.Fatalf("version after creates = (%d, %v, %v), want 1", v, found, err)
	}
	// A second "winner" cannot appear at the database level either.
	if _, err := st.pool.Exec(ctx, `INSERT INTO cluster_keys (kind, data) VALUES ('oidc', '{"x":1}')`); err == nil {
		t.Fatal("a duplicate kind insert bypassed the primary key")
	}

	// The explicit rotation write overwrites and bumps the version.
	rotated := []byte("ring-3")
	if err := st.PutClusterKey(ctx, "oidc", rotated); err != nil {
		t.Fatalf("PutClusterKey: %v", err)
	}
	if b, found, err := st.GetClusterKey(ctx, "oidc"); err != nil || !found || !bytes.Equal(b, rotated) {
		t.Fatalf("after rotation = (%q, %v, %v)", b, found, err)
	}
	if v, _, err := st.ClusterKeyVersion(ctx, "oidc"); err != nil || v != 2 {
		t.Fatalf("version after rotation = (%d, %v), want 2", v, err)
	}
	// Put on an absent kind creates it (version 1).
	if err := st.PutClusterKey(ctx, "provenance", []byte("p")); err != nil {
		t.Fatal(err)
	}
	if v, found, err := st.ClusterKeyVersion(ctx, "provenance"); err != nil || !found || v != 1 {
		t.Fatalf("created-by-put version = (%d, %v, %v), want 1", v, found, err)
	}
	// Re-creating after a rotation returns the CURRENT published material to
	// a caller that already handles created=false.
	if got, created, err := st.CreateClusterKey(ctx, "oidc", []byte("ring-4")); err != nil || created || !bytes.Equal(got, rotated) {
		t.Fatalf("create after rotation = (%q, %v, %v), want the published ring-3", got, created, err)
	}
	// Versions are per kind.
	if v, found, err := st.ClusterKeyVersion(ctx, "lease"); err != nil || found || v != 0 {
		t.Fatalf("unrelated kind version = (%d, %v, %v)", v, found, err)
	}
}

// TestPostgresIntegrationClusterKeyRotationFenceSerializes proves the
// rotation fence serializes critical sections across two store instances and
// that a fence body error is propagated (the lock is still released, so the
// next rotation is not wedged).
func TestPostgresIntegrationClusterKeyRotationFenceSerializes(t *testing.T) {
	env := pgITSetup(t)
	stA := env.open(t)
	env.migrate(t, stA)
	pgITArmFence(t, stA)
	ctx := context.Background()
	if err := stA.EnsureClusterKeySchema(ctx); err != nil {
		t.Fatal(err)
	}
	stB := env.open(t)
	pgITArmFence(t, stB)

	var seqMu sync.Mutex
	var seq []string
	var wg sync.WaitGroup
	for name, st := range map[string]*PostgresStore{"a": stA, "b": stB} {
		wg.Add(1)
		go func(name string, st *PostgresStore) {
			defer wg.Done()
			err := st.WithClusterKeyRotationFence(ctx, "oidc", func() error {
				seqMu.Lock()
				seq = append(seq, "enter-"+name)
				seqMu.Unlock()
				// Hold the fence long enough that a missing lock would
				// interleave the two bodies.
				for i := 0; i < 20; i++ {
					_, _, _ = st.ClusterKeyVersion(ctx, "oidc")
				}
				seqMu.Lock()
				seq = append(seq, "exit-"+name)
				seqMu.Unlock()
				return nil
			})
			if err != nil {
				t.Errorf("%s fence: %v", name, err)
			}
		}(name, st)
	}
	wg.Wait()
	if len(seq) != 4 {
		t.Fatalf("fence sequence = %v", seq)
	}
	if !(strings.HasPrefix(seq[0], "enter-") && strings.HasPrefix(seq[1], "exit-") && strings.HasPrefix(seq[2], "enter-") && strings.HasPrefix(seq[3], "exit-")) {
		t.Fatalf("fence critical sections interleaved: %v", seq)
	}
	if seq[0] == seq[2] {
		t.Fatalf("one store ran twice: %v", seq)
	}

	// A fence body error propagates and releases the lock.
	boom := errors.New("rotation body failed")
	if err := stA.WithClusterKeyRotationFence(ctx, "oidc", func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("fence body error = %v, want %v", err, boom)
	}
	done := make(chan struct{})
	go func() {
		_ = stB.WithClusterKeyRotationFence(ctx, "oidc", func() error { return nil })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("fence stayed held after a body error")
	}
}

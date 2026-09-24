package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// TestServerCASMaximumParity pins the R5-A contract: every server CAS
// instance carries the SAME authoritative per-object maximum the cache and
// artifact HTTP endpoints advertise, so the advertised upload interval can
// never drift from what CAS.PutFile accepts.
func TestServerCASMaximumParity(t *testing.T) {
	if cacheUploadMaxBytes != maxBlobBytes {
		t.Fatalf("cache endpoint cap %d drifted from maxBlobBytes %d", cacheUploadMaxBytes, maxBlobBytes)
	}
	// The staging budget is supplied at CONSTRUCTION time: the constructor
	// uses it verbatim and every CAS instance it builds carries it.
	b, err := staging.NewBudget(filepath.Join(t.TempDir(), "staging"), 1<<20)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	dir := t.TempDir()
	s, err := NewPersistent("tok", "tok", dir, WithStagingBudget(b))
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	if s.CAS == nil {
		t.Fatal("persistent constructor built no CAS")
	}
	if s.CAS.MaxBlobBytes != maxBlobBytes {
		t.Fatalf("constructor CAS MaxBlobBytes = %d, want maxBlobBytes %d", s.CAS.MaxBlobBytes, maxBlobBytes)
	}
	if s.CAS.Staging != b || s.Staging != b {
		t.Fatalf("constructor CAS staging = %v, want the supplied budget %v", s.CAS.Staging, b)
	}

	// The cluster-key constructor builds the same authoritative CAS.
	s2, err := NewPersistentWithCluster("tok", "tok", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewPersistentWithCluster: %v", err)
	}
	if s2.CAS == nil || s2.CAS.MaxBlobBytes != maxBlobBytes {
		t.Fatalf("cluster constructor CAS max = %v, want %d", s2.CAS, maxBlobBytes)
	}

	// SetBlobStore must preserve BOTH the object maximum and the staging
	// budget instead of rebuilding a bare cas.New.
	s.SetBlobStore(newMemBlob())
	if s.CAS.MaxBlobBytes != maxBlobBytes {
		t.Fatalf("SetBlobStore dropped the object maximum: %d, want %d", s.CAS.MaxBlobBytes, maxBlobBytes)
	}
	if s.CAS.Staging != b {
		t.Fatalf("SetBlobStore dropped the staging budget: %v, want %v", s.CAS.Staging, b)
	}

	// A bare in-memory server has no CAS until a backend is installed; a
	// construction-time budget is still installed, and there is no
	// post-construction swap.
	mem := New("tok", WithStagingBudget(b))
	if mem.Staging != b || mem.CAS != nil {
		t.Fatalf("in-memory staging wiring = (%v, %v)", mem.Staging, mem.CAS)
	}
	// The explicit-nil option suppresses the constructor default and leaves
	// large uploads failing closed, which is only expressible at construction.
	noBound, err := NewPersistent("tok", "tok", t.TempDir(), WithStagingBudget(nil))
	if err != nil {
		t.Fatalf("NewPersistent with explicit nil staging: %v", err)
	}
	if noBound.Staging != nil || noBound.CAS.Staging != nil {
		t.Fatalf("explicit nil staging = (server %v, cas %v), want nil", noBound.Staging, noBound.CAS.Staging)
	}
}

// TestPersistentConstructorUsesSuppliedStagingBudget pins the R5-C contract:
// a budget supplied through WithStagingBudget is used verbatim, its distinct
// root means the constructor never locks a second data-dir directory, and the
// constructor succeeds where the built-in default would collide on the same
// directory with a different max_bytes.
func TestPersistentConstructorUsesSuppliedStagingBudget(t *testing.T) {
	// Distinct root/max: the constructor must not touch the data-dir default
	// staging directory at all.
	dir := t.TempDir()
	supplied, err := staging.NewReplicaBudget(filepath.Join(t.TempDir(), "configured"), "replica-a", 1<<30)
	if err != nil {
		t.Fatalf("supplied budget: %v", err)
	}
	t.Cleanup(func() { _ = supplied.Close() })
	s, err := NewPersistent("tok", "tok", dir, WithStagingBudget(supplied))
	if err != nil {
		t.Fatalf("NewPersistent with supplied budget: %v", err)
	}
	if s.Staging != supplied {
		t.Fatalf("constructor did not use the supplied budget verbatim: got %v, want %v", s.Staging, supplied)
	}
	if s.CAS.Staging != supplied {
		t.Fatalf("CAS did not receive the supplied budget: %v, want %v", s.CAS.Staging, supplied)
	}
	if _, err := os.Stat(filepath.Join(dir, "kiwi-staging")); !os.IsNotExist(err) {
		t.Fatalf("constructor locked a second data-dir staging directory: stat err = %v", err)
	}

	// Same data-dir default directory but a different max: the built-in
	// default construction would be rejected by the staging registry, so a
	// subsequent optionless construction must fail while the option succeeds.
	collideDir := t.TempDir()
	collide, err := staging.NewReplicaBudget(filepath.Join(collideDir, "kiwi-staging"), "", 1<<30)
	if err != nil {
		t.Fatalf("colliding budget: %v", err)
	}
	t.Cleanup(func() { _ = collide.Close() })
	s3, err := NewPersistent("tok", "tok", collideDir, WithStagingBudget(collide))
	if err != nil {
		t.Fatalf("NewPersistent with an owned non-default budget failed: %v", err)
	}
	if s3.Staging != collide {
		t.Fatalf("constructor staging = %v, want supplied %v", s3.Staging, collide)
	}
	// The prior failure mode is real: without the supplied budget the
	// constructor builds its own default over the same directory with a
	// different max and the registry rejects it.
	if _, err := NewPersistent("tok", "tok", collideDir); err == nil {
		t.Fatal("optionless constructor unexpectedly rebuilt a second budget over an owned directory")
	} else if !strings.Contains(err.Error(), "exactly one ledger") {
		t.Fatalf("collision error = %q, want the one-ledger registry rejection", err)
	}
}

// TestObjectMaximumBoundaryTinyScale is the R5-A parity boundary at a tiny
// scale: with the endpoint cap and the CAS object maximum both set to 8 KiB,
// the whole advertised interval is accepted and one byte past it fails — at
// the endpoint with 413 and at CAS with the documented typed error.
func TestObjectMaximumBoundaryTinyScale(t *testing.T) {
	const limit = 8 << 10
	oldCache := cacheUploadMaxBytes
	cacheUploadMaxBytes = limit
	t.Cleanup(func() { cacheUploadMaxBytes = oldCache })

	s, _, _, hdrs, _ := cacheFixtureWithStaging(t, 1<<20)
	// Endpoint == CAS == 8 KiB: the two bounds a real deployment must keep in
	// lockstep; the default wiring sets both from maxBlobBytes.
	s.CAS.MaxBlobBytes = limit

	exact := bytes.Repeat([]byte("a"), limit)
	over := bytes.Repeat([]byte("b"), limit+1)
	key := strings.Repeat("d", 64)

	// Exact limit is accepted end to end.
	w := doRawBody(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", bytes.NewReader(exact), limit, hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("exact-limit cache upload = %d, want 201: %s", w.Code, w.Body.String())
	}
	// Limit+1 is rejected at the endpoint before staging.
	w = doRawBody(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", bytes.NewReader(over), limit+1, hdrs)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("limit+1 cache upload = %d, want 413: %s", w.Code, w.Body.String())
	}

	// CAS boundary: the same interval is accepted, and limit+1 fails with the
	// documented typed error instead of reaching the backend.
	staged := t.TempDir()
	exactPath := filepath.Join(staged, "exact")
	if err := os.WriteFile(exactPath, exact, 0o600); err != nil {
		t.Fatal(err)
	}
	exactSum := sha256.Sum256(exact)
	if _, err := s.CAS.PutFile(context.Background(), exactPath, hex.EncodeToString(exactSum[:]), limit); err != nil {
		t.Fatalf("CAS PutFile at the limit: %v", err)
	}
	overPath := filepath.Join(staged, "over")
	if err := os.WriteFile(overPath, over, 0o600); err != nil {
		t.Fatal(err)
	}
	overSum := sha256.Sum256(over)
	if _, err := s.CAS.PutFile(context.Background(), overPath, hex.EncodeToString(overSum[:]), limit+1); !errors.Is(err, cas.ErrBlobTooLarge) {
		t.Fatalf("CAS PutFile limit+1 = %v, want cas.ErrBlobTooLarge", err)
	}
}

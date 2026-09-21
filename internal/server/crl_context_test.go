package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// stallCRLStore models a revocation store whose database has stalled: every
// CertRevoked call blocks until its context is done and then reports that
// context error. It records the observed context errors so tests can prove
// WHICH context (and thus which bound) reached the store.
type stallCRLStore struct {
	*dbFakeStore
	entered chan struct{}
	once    sync.Once
	seenErr chan error
}

func newStallCRLStore(f *dbFakeStore) *stallCRLStore {
	return &stallCRLStore{dbFakeStore: f, entered: make(chan struct{}), seenErr: make(chan error, 4)}
}

func (s *stallCRLStore) CertRevoked(ctx context.Context, serial string) (bool, error) {
	s.once.Do(func() { close(s.entered) })
	<-ctx.Done()
	s.seenErr <- ctx.Err()
	return false, ctx.Err()
}

// TestCRLLookupReturnsOnRequestCancellation proves the runner authentication
// path threads the REQUEST context into the durable CRL lookup: a stalled
// revocation store returns as soon as the client's context is canceled
// instead of pinning the request (the pre-fix code used
// context.Background(), so cancellation could not reach it). The failed
// lookup must fail the identity closed.
func TestCRLLookupReturnsOnRequestCancellation(t *testing.T) {
	ca, err := runnerpki.NewCA("crl ctx ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, certA := pkiSignRunner(t, ca, "runner-a")
	stall := newStallCRLStore(newDBFakeStore())
	s := New("runner-tok")
	s.RunnerCA = ca
	if err := s.SwitchToDB(stall); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := crlRequestWithCert(t, certA).WithContext(ctx)

	done := make(chan bool, 1)
	go func() { done <- s.verifyRunnerIdentity(req, "runner-a") }()
	select {
	case <-stall.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("revocation lookup never reached the store")
	}
	start := time.Now()
	cancel()
	select {
	case allowed := <-done:
		if allowed {
			t.Fatal("stalled revocation lookup authorized the certificate (fail open)")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("identity resolution took %v after request cancellation; the lookup is not request-bound", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("identity resolution did not return after the request context was canceled")
	}
	if err := <-stall.seenErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup context error = %v, want context.Canceled (request context not threaded)", err)
	}
}

// TestCRLLookupTimeoutFailsClosed proves the explicit per-lookup bound: a
// stalled store with a live request context is cut off by crlLookupTimeout
// (overridden here to keep the test fast) and the timeout fails the
// certificate closed, returning revoked=true together with the error.
func TestCRLLookupTimeoutFailsClosed(t *testing.T) {
	ca, err := runnerpki.NewCA("crl timeout ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, certA := pkiSignRunner(t, ca, "runner-a")
	serial := certA.SerialNumber.Text(16)
	stall := newStallCRLStore(newDBFakeStore())
	s := New("runner-tok")
	s.RunnerCA = ca
	if err := s.SwitchToDB(stall); err != nil {
		t.Fatal(err)
	}

	old := crlLookupTimeout
	crlLookupTimeout = 50 * time.Millisecond
	defer func() { crlLookupTimeout = old }()

	req := crlRequestWithCert(t, certA)
	start := time.Now()
	_, _, resolveErr := s.resolveRunnerIdentity(req, "runner-a")
	if resolveErr == nil {
		t.Fatal("lookup timeout authorized the certificate (fail open)")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("lookup timeout did not bound the call: took %v", elapsed)
	}
	if err := <-stall.seenErr; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lookup context error = %v, want context.DeadlineExceeded", err)
	}
	// The decision helper itself is fail-closed: revoked=true with the error.
	revoked, err := s.certSerialRevoked(context.Background(), serial)
	if !revoked || err == nil {
		t.Fatalf("fail-closed decision = revoked %v, err %v; want revoked=true with the error", revoked, err)
	}
}

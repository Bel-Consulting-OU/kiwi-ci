package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// storeWithoutFence implements storage.Store by forwarding to an inner store
// while hiding every optional extension interface (the embedded interface
// exposes exactly storage.Store's method set). It models a DB store that
// cannot provide the cross-replica digest fence.
type storeWithoutFence struct{ storage.Store }

// recordingFencer counts the local-fencer calls so a test can prove memory/fs
// mode still routes through the in-process fencer.
type recordingFencer struct {
	mu      sync.Mutex
	with    int
	acquire int
}

func (r *recordingFencer) WithFence(ctx context.Context, digest string, fn func() error) error {
	r.mu.Lock()
	r.with++
	r.mu.Unlock()
	return fn()
}

func (r *recordingFencer) Acquire(ctx context.Context, digest string) (func(), error) {
	r.mu.Lock()
	r.acquire++
	r.mu.Unlock()
	return func() {}, nil
}

func (r *recordingFencer) calls() (with, acquire int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.with, r.acquire
}

// TestDigestFenceDBStoreWithoutCapabilityFailsClosed is the X3-B regression: a
// DB store lacking storage.DigestFenceStore must NOT fall back to the
// process-local MemFencer (which would make publication and GC take unrelated
// locks on different replicas). Both fence entry points refuse with the typed
// error and run nothing.
func TestDigestFenceDBStoreWithoutCapabilityFailsClosed(t *testing.T) {
	f := newDBFakeStore()
	s := New("tok")
	s.DB = storeWithoutFence{Store: f}
	digest := strings.Repeat("a", 64)
	ctx := context.Background()

	if _, err := s.acquireDigestFence(ctx, digest); !errors.Is(err, errDigestFenceUnsupported) {
		t.Fatalf("acquireDigestFence = %v, want errDigestFenceUnsupported", err)
	}
	ran := false
	if err := s.withDigestFence(ctx, digest, func() error { ran = true; return nil }); !errors.Is(err, errDigestFenceUnsupported) {
		t.Fatalf("withDigestFence = %v, want errDigestFenceUnsupported", err)
	}
	if ran {
		t.Fatal("withDigestFence ran the critical section without a distributed fence")
	}
}

// TestDigestFenceStoreCapabilityIsUsed confirms the positive side of the same
// branch: a DB store that provides the capability is used directly.
func TestDigestFenceStoreCapabilityIsUsed(t *testing.T) {
	f := newDBFakeStore()
	s := New("tok")
	s.DB = f
	ran := false
	if err := s.withDigestFence(context.Background(), strings.Repeat("b", 64), func() error { ran = true; return nil }); err != nil {
		t.Fatalf("withDigestFence with capability = %v", err)
	}
	if !ran {
		t.Fatal("withDigestFence did not run the critical section")
	}
	release, err := s.acquireDigestFence(context.Background(), strings.Repeat("c", 64))
	if err != nil {
		t.Fatalf("acquireDigestFence with capability = %v", err)
	}
	release()
}

// TestDigestFenceMemoryModeUsesLocalFencer proves memory/fs mode (DB == nil)
// still serializes through the configured in-process fencer.
func TestDigestFenceMemoryModeUsesLocalFencer(t *testing.T) {
	s := New("tok")
	rec := &recordingFencer{}
	s.digestFence = rec
	ctx := context.Background()
	if err := s.withDigestFence(ctx, strings.Repeat("d", 64), func() error { return nil }); err != nil {
		t.Fatalf("memory-mode withDigestFence = %v", err)
	}
	release, err := s.acquireDigestFence(ctx, strings.Repeat("e", 64))
	if err != nil {
		t.Fatalf("memory-mode acquireDigestFence = %v", err)
	}
	release()
	if with, acquire := rec.calls(); with != 1 || acquire != 1 {
		t.Fatalf("local fencer calls = with:%d acquire:%d, want 1/1", with, acquire)
	}
}

// TestDigestFenceUnsupportedMapsTo503 pins the HTTP mapping: the fail-closed
// fencing error is a server-side capability condition and must answer 503
// wherever a request can proceed (the handler paths route through
// internalError).
func TestDigestFenceUnsupportedMapsTo503(t *testing.T) {
	s := New("tok")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	s.internalError(rec, req, errDigestFenceUnsupported, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("fence error mapping = %d, want 503", rec.Code)
	}
}

// TestCacheUploadDBWithoutDigestFenceReturns503 drives the full request path:
// a DB-mode cache upload whose store lacks the distributed fence is refused
// with 503 BEFORE any manifest/blob is committed, instead of silently taking
// the process-local fence.
func TestCacheUploadDBWithoutDigestFenceReturns503(t *testing.T) {
	s, f, mb, hdrs := cacheFixture(t)
	s.DB = storeWithoutFence{Store: f}
	key := strings.Repeat("f", 64)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cache upload without a distributed fence = %d, want 503: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	manifests := len(f.cacheMans)
	f.mu.Unlock()
	if manifests != 0 {
		t.Fatalf("cache manifests committed without a distributed fence: %d", manifests)
	}
	mb.mu.Lock()
	objects := len(mb.objects)
	mb.mu.Unlock()
	if objects != 0 {
		t.Fatalf("CAS objects published without a distributed fence: %d", objects)
	}
}

package cache

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStoreStallGuardCheckRearmsOnRecordedProgress pins the re-arm edge of the
// watchdog check: progress recorded before the timer fired pushes the deadline
// out for the remainder of the window instead of latching a stall.
func TestStoreStallGuardCheckRearmsOnRecordedProgress(t *testing.T) {
	ctx, guard := newStoreStallGuard(context.Background(), time.Hour)
	defer guard.release()
	guard.progress()
	guard.check()
	if guard.stalled() {
		t.Fatal("progress recorded before the check latched a stall")
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("progress recorded before the check canceled the transfer: %v", err)
	}
}

// TestStallErrorIgnoresMissingError pins the mapping helper's identity edge: a
// nil operation error is nil, never a fabricated stall, with or without a
// guard.
func TestStallErrorIgnoresMissingError(t *testing.T) {
	ctx, guard := newStoreStallGuard(context.Background(), time.Hour)
	defer guard.release()
	if err := stallError(ctx, guard, nil); err != nil {
		t.Fatalf("stallError(nil) = %v, want nil", err)
	}
	if err := stallError(ctx, nil, nil); err != nil {
		t.Fatalf("stallError(nil, nil guard) = %v, want nil", err)
	}
}

// TestDefaultRootsUnderUserCache pins the zero-config store location.
func TestDefaultRootsUnderUserCache(t *testing.T) {
	s := Default()
	want := filepath.Join(".kiwi", "cache")
	if !strings.HasSuffix(filepath.Clean(s.Root), want) {
		t.Fatalf("Default().Root = %q, want a suffix %q", s.Root, want)
	}
}

// TestDefaultContextOwnership pins which layer owns the total transfer policy
// after W5-B: the wrapper NEVER imposes a total wall-clock deadline on either
// path, because a continuously-progressing bulk transfer (up to
// MaxArchiveBytes) must not be cut by a fixed 30-second cap. The former
// no-client deadline is deliberately gone: with a caller-supplied client the
// client owns its bounds, and on the default-client path the transport phase
// bounds (dial/TLS/response headers/idle) plus the sliding storeStallTimeout
// watchdog provide the no-hang guarantee.
func TestDefaultContextOwnership(t *testing.T) {
	for name, s := range map[string]*Store{
		"caller-supplied client": {Client: &http.Client{}},
		"default client":         {},
	} {
		ctx, cancel := s.defaultContext()
		if _, ok := ctx.Deadline(); ok {
			t.Fatalf("%s: the wrapper must not impose a total transfer deadline", name)
		}
		cancel()
	}
}

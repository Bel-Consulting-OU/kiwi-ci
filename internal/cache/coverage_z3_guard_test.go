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

// TestDefaultContextOwnership pins which layer owns the total transfer policy:
// a caller-supplied client removes the wrapper's finite deadline, while the
// default client path carries one.
func TestDefaultContextOwnership(t *testing.T) {
	withClient := &Store{Client: &http.Client{}}
	ctx, cancel := withClient.defaultContext()
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("caller-supplied client still got a wrapper deadline")
	}
	defaulted := &Store{}
	ctx2, cancel2 := defaulted.defaultContext()
	defer cancel2()
	if _, ok := ctx2.Deadline(); !ok {
		t.Fatal("default client path lost its finite wrapper deadline")
	}
}

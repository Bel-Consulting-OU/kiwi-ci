package server

import (
	"fmt"
	"testing"
	"time"
)

// TestCheckRunMirrorPrunesToCap is the G2-G checkruns regression: the fs-mode
// logical-check mirror is bounded and keeps the most recently written
// mappings.
func TestCheckRunMirrorPrunesToCap(t *testing.T) {
	c := &checkRunIDs{m: map[string]string{}}
	total := maxCheckRunIDs + 100
	for i := 0; i < total; i++ {
		c.set(fmt.Sprintf("k%06d", i), "id")
	}
	if len(c.m) > maxCheckRunIDs {
		t.Fatalf("mirror has %d entries, want <= %d", len(c.m), maxCheckRunIDs)
	}
	if _, ok := c.m[fmt.Sprintf("k%06d", total-1)]; !ok {
		t.Fatal("most recently written mapping was pruned")
	}
	if _, ok := c.m["k000000"]; ok {
		t.Fatal("oldest mapping survived the cap")
	}
}

// TestCRLCachePrunesExpiredAndBounds is the G2-G crlCache regression: the
// DB-mode decision cache drops expired entries and evicts oldest under a
// hard cap.
func TestCRLCachePrunesExpiredAndBounds(t *testing.T) {
	s := New("t")
	now := time.Now()
	for i := 0; i < crlCacheMax; i++ {
		s.putCRLCacheLocked(fmt.Sprintf("s%06d", i), crlCacheEntry{revoked: false, at: now})
	}
	s.crlCache["expired"] = crlCacheEntry{revoked: false, at: now.Add(-2 * crlCacheTTL)}
	s.putCRLCacheLocked("trigger", crlCacheEntry{revoked: false, at: now})
	if len(s.crlCache) > crlCacheMax {
		t.Fatalf("crlCache has %d entries, want <= %d", len(s.crlCache), crlCacheMax)
	}
	if _, ok := s.crlCache["expired"]; ok {
		t.Fatal("expired decision survived cap pruning")
	}
	if _, ok := s.crlCache["trigger"]; !ok {
		t.Fatal("newly inserted decision was evicted")
	}
}

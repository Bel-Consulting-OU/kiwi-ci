package storage

// Hermetic tests for the scheduler leadership liveness rules: the
// proof-freshness bound and the bounded context on the reacquire fallback. No
// PostgreSQL server is needed — a listener that accepts TCP and never answers
// stands in for a black-holed database, proving the call cannot wait for
// pgxpool's two-minute default connect timeout.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLeaderProbeIntervalBounded(t *testing.T) {
	cases := []struct {
		ttl  time.Duration
		want time.Duration
	}{
		{time.Hour, time.Second},
		{time.Minute, time.Second},
		{30 * time.Second, time.Second},
		{5 * time.Second, time.Second},
		{2 * time.Second, 400 * time.Millisecond},
		{500 * time.Millisecond, 100 * time.Millisecond},
	}
	for _, tc := range cases {
		if got := leaderProbeInterval(tc.ttl); got != tc.want {
			t.Errorf("leaderProbeInterval(%v) = %v, want %v", tc.ttl, got, tc.want)
		}
	}
	// The freshness window must always stay well under the claim TTL it
	// protects, so a throttled skipped probe can never mask death until TTL.
	for _, ttl := range []time.Duration{50 * time.Millisecond, time.Second, 10 * time.Second, time.Hour} {
		if got := leaderProbeInterval(ttl); got > ttl/2 || got > time.Second {
			t.Errorf("leaderProbeInterval(%v) = %v; want at most min(ttl/2, 1s)", ttl, got)
		}
	}
}

// silentListener accepts TCP connections and never answers, standing in for a
// black-holed database: only a context deadline can end a connect attempt.
type silentListener struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newSilentListener(t *testing.T) *silentListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &silentListener{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, c := range s.conns {
			_ = c.Close()
		}
	})
	return s
}

func (s *silentListener) dsn() string {
	return fmt.Sprintf("postgres://kiwi@%s/kiwi?sslmode=disable", s.ln.Addr().String())
}

// TestLeaderReacquireFallbackBounded pins the reconnect fallback bound: a
// black-holed database must not hold a leadership caller for pgxpool's
// two-minute default connect timeout. The caller's deadline bounds the call
// when it is shorter than leaderAcquireTimeout; leaderAcquireTimeout bounds it
// otherwise.
func TestLeaderReacquireFallbackBounded(t *testing.T) {
	blackhole := newSilentListener(t)
	cfg, err := pgxpool.ParseConfig(blackhole.dsn())
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	st := NewPostgresFromPool(pool)

	t.Run("caller-deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		got, err := st.TryAcquireLeadership(ctx, "kiwi-leader-bounded", time.Minute)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("black-holed acquire = %v, nil; want a context error", got)
		}
		if got {
			t.Fatal("black-holed acquire reported leadership")
		}
		if elapsed > time.Second {
			t.Fatalf("black-holed acquire took %v; the caller deadline must bound it", elapsed)
		}
	})

	t.Run("store-timeout", func(t *testing.T) {
		old := leaderAcquireTimeout
		leaderAcquireTimeout = 250 * time.Millisecond
		defer func() { leaderAcquireTimeout = old }()
		start := time.Now()
		got, err := st.TryAcquireLeadership(context.Background(), "kiwi-leader-bounded", time.Minute)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("black-holed acquire = %v, nil; want a timeout error", got)
		}
		if got {
			t.Fatal("black-holed acquire reported leadership")
		}
		if elapsed > time.Second {
			t.Fatalf("black-holed acquire without a caller deadline took %v; leaderAcquireTimeout must bound it", elapsed)
		}
	})
}

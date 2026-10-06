package server

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// dbPoolStatsFake implements the optional server-side dbPoolStatsStore
// contract. The embedded storage.Store satisfies the s.DB field type; only
// the pool accessors are ever called.
type dbPoolStatsFake struct {
	storage.Store
	op, adv storage.PoolStatView
	held    bool
}

func (f dbPoolStatsFake) PoolStats() (storage.PoolStatView, storage.PoolStatView) {
	return f.op, f.adv
}

func (f dbPoolStatsFake) LeaderSessionHeld() bool { return f.held }

// TestRefreshDBPoolMetrics pins the finding-11 gauge wiring: operational and
// advisory pool series are exported from the store's optional accessor, the
// leadership session is a 0/1 gauge, absent pools produce no series, and a
// store without the optional contract (or no DB at all) is a silent no-op.
func TestRefreshDBPoolMetrics(t *testing.T) {
	gauge := func(s *Server, labels string) (float64, bool) {
		s.Metrics.mu.Lock()
		defer s.Metrics.mu.Unlock()
		v, ok := s.Metrics.gauges["kiwi_db_pool"][labels]
		return v, ok
	}

	s := New("token")
	s.Metrics.Reset()
	s.DB = dbPoolStatsFake{
		op:   storage.PoolStatView{Present: true, InUse: 1, Idle: 2, Total: 3, Max: 5},
		adv:  storage.PoolStatView{Present: true, InUse: 4, Idle: 0, Total: 4, Max: 4},
		held: true,
	}
	s.refreshDBPoolMetrics()
	for labels, want := range map[string]float64{
		`pool="operational",stat="in_use"`:  1,
		`pool="operational",stat="idle"`:    2,
		`pool="operational",stat="total"`:   3,
		`pool="operational",stat="max"`:     5,
		`pool="advisory",stat="in_use"`:     4,
		`pool="advisory",stat="max"`:        4,
		`pool="leader",stat="session_held"`: 1,
	} {
		if got, ok := gauge(s, labels); !ok || got != want {
			t.Errorf("kiwi_db_pool{%s} = %v (present=%v), want %v", labels, got, ok, want)
		}
	}

	// An absent pool renders no series for that pool; a released leadership
	// session is explicitly zero rather than stale. A fresh registry proves
	// the absence (a scrape-time gauge keeps its last value otherwise, which
	// is normal Prometheus staleness).
	s2 := New("token")
	s2.Metrics.Reset()
	s2.DB = dbPoolStatsFake{
		op:   storage.PoolStatView{Present: true, InUse: 0, Idle: 1, Total: 1, Max: 1},
		adv:  storage.PoolStatView{},
		held: false,
	}
	s2.refreshDBPoolMetrics()
	if _, ok := gauge(s2, `pool="advisory",stat="max"`); ok {
		t.Error("absent advisory pool exported a series")
	}
	if got, ok := gauge(s2, `pool="leader",stat="session_held"`); !ok || got != 0 {
		t.Errorf("leader session_held = %v (present=%v), want 0", got, ok)
	}

	// Stores without the optional contract and a nil DB are no-ops.
	s.DB = newDBFakeStore()
	s.refreshDBPoolMetrics()
	s.DB = nil
	s.refreshDBPoolMetrics()
	bare := &Server{}
	bare.refreshDBPoolMetrics()
}

package runner

import (
	"net/http"
	"time"
)

// maintenanceSchedule models the periodic runner maintenance passes. The
// runner reaps stale runtime resources (executor.GC) every GCInterval and
// refreshes digest-pinned prewarmed images every PrewarmInterval.
type maintenanceSchedule struct {
	GCInterval      time.Duration
	PrewarmInterval time.Duration
}

// due reports which passes are due at now given their last run times. A
// zero last run time means "never ran" and is always due.
func (m maintenanceSchedule) due(now time.Time, lastGC, lastPrewarm time.Time) (gc, prewarm bool) {
	if m.GCInterval > 0 && (lastGC.IsZero() || now.Sub(lastGC) >= m.GCInterval) {
		gc = true
	}
	if m.PrewarmInterval > 0 && (lastPrewarm.IsZero() || now.Sub(lastPrewarm) >= m.PrewarmInterval) {
		prewarm = true
	}
	return gc, prewarm
}

// newMetricsServer builds the stdlib HTTP server exposing the runner's
// Prometheus text metrics on the configured listen address.
func newMetricsServer(addr string, m *Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m)
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

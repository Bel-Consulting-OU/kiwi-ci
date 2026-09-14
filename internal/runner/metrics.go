package runner

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Metrics is the runner's minimal Prometheus text-format metric registry.
// It deliberately sticks to stdlib counters (cumulative values) so the
// runner never needs a metrics dependency: duration metrics are exported as
// cumulative seconds under their exact counter names.
type Metrics struct {
	mu       sync.Mutex
	counters map[string]float64
}

// NewMetrics returns an empty metric registry.
func NewMetrics() *Metrics {
	return &Metrics{counters: map[string]float64{}}
}

// Counter adds delta to the named counter.
func (m *Metrics) Counter(name string, delta float64) {
	m.mu.Lock()
	m.counters[name] += delta
	m.mu.Unlock()
}

// Observe accumulates a duration sample (seconds) into the named counter.
func (m *Metrics) Observe(name string, seconds float64) {
	m.Counter(name, seconds)
}

// Expose renders the registry in Prometheus text exposition format with
// deterministic (sorted) name order.
func (m *Metrics) Expose(w io.Writer) error {
	m.mu.Lock()
	names := make([]string, 0, len(m.counters))
	for name := range m.counters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := fmt.Fprintf(w, "# TYPE %s counter\n%s %v\n", name, name, m.counters[name]); err != nil {
			m.mu.Unlock()
			return err
		}
	}
	m.mu.Unlock()
	return nil
}

// ServeHTTP exposes the registry on the runner's metrics listener.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := m.Expose(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// stepTimer derives per-step wall-clock durations from the executor's log
// sink. Every executed step emits a "running on <backend> (attempt …)" line
// before running, so the first line seen for a (job, step) key marks the
// step start; the duration is finalised when the next step starts and by
// flush() after the job finishes. Skipped steps never emit lines and are
// never counted.
type stepTimer struct {
	m       *Metrics
	mu      sync.Mutex
	started map[string]time.Time
	active  string
}

func (st *stepTimer) WriteLine(job, step, line string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.started == nil {
		st.started = map[string]time.Time{}
	}
	key := job + "\x00" + step
	if st.active != "" && st.active != key {
		if t0, ok := st.started[st.active]; ok {
			st.m.Observe("kiwi_runner_step_duration_seconds", time.Since(t0).Seconds())
		}
	}
	if _, ok := st.started[key]; !ok {
		st.started[key] = time.Now()
	}
	st.active = key
}

func (st *stepTimer) flush() {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.active != "" {
		if t0, ok := st.started[st.active]; ok {
			st.m.Observe("kiwi_runner_step_duration_seconds", time.Since(t0).Seconds())
		}
		st.active = ""
	}
}

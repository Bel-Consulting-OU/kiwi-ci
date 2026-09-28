package runner

import (
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

// Metrics is the runner's minimal Prometheus text-format metric registry.
// It deliberately sticks to stdlib counters and callback gauges (cumulative
// values and sampled values) so the runner never needs a metrics dependency:
// duration metrics are exported as cumulative seconds under their exact
// counter names, while gauges such as the staging ledger are evaluated at
// scrape time through their callback so the exposed value is never staler
// than the request.
type Metrics struct {
	mu       sync.Mutex
	counters map[string]float64
	gauges   map[string]func() float64
}

// NewMetrics returns an empty metric registry.
func NewMetrics() *Metrics {
	return &Metrics{counters: map[string]float64{}, gauges: map[string]func() float64{}}
}

// Counter adds delta to the named counter.
func (m *Metrics) Counter(name string, delta float64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.counters[name] += delta
	m.mu.Unlock()
}

// Observe accumulates a duration sample (seconds) into the named counter.
func (m *Metrics) Observe(name string, seconds float64) {
	m.Counter(name, seconds)
}

// GaugeFunc registers fn as the scrape-time value of the named gauge. The
// callback is evaluated outside the registry lock on every scrape (and must
// be concurrency-safe); a later registration replaces an earlier one, so a
// restarted in-process Run can re-point a gauge at its new ledger. A gauge
// name shadows a same-named counter.
func (m *Metrics) GaugeFunc(name string, fn func() float64) {
	if m == nil || name == "" || fn == nil {
		return
	}
	m.mu.Lock()
	m.gauges[name] = fn
	m.mu.Unlock()
}

// Expose renders the registry in Prometheus text exposition format with
// deterministic (sorted) name order. Counter values are snapshotted under
// the lock; gauge callbacks run after it is released.
func (m *Metrics) Expose(w io.Writer) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	names := make([]string, 0, len(m.counters)+len(m.gauges))
	counters := make(map[string]float64, len(m.counters))
	for name, v := range m.counters {
		counters[name] = v
		names = append(names, name)
	}
	gauges := make(map[string]func() float64, len(m.gauges))
	for name, fn := range m.gauges {
		gauges[name] = fn
		if _, shadowed := counters[name]; !shadowed {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	m.mu.Unlock()
	for _, name := range names {
		if fn, ok := gauges[name]; ok {
			if _, err := fmt.Fprintf(w, "# TYPE %s gauge\n%s %v\n", name, name, fn()); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "# TYPE %s counter\n%s %v\n", name, name, counters[name]); err != nil {
			return err
		}
	}
	return nil
}

// ServeHTTP exposes the registry on the runner's metrics listener.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := m.Expose(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// applyStepReporter wires the executor's StepReporter hook into the
// kiwi_runner_step_duration_seconds counter. The hook has the signature
// func(jobID, stepID string, d time.Duration) and carries the REAL
// executor-measured per-step wall-clock duration (the sink-derived
// approximation was removed). The wiring is reflection-based so this
// package builds against executor versions with and without the field;
// when the field is absent it returns false and step durations are then
// simply not collected.
func applyStepReporter(opts *executor.Options, m *Metrics) bool {
	v := reflect.ValueOf(opts).Elem()
	f := v.FieldByName("StepReporter")
	if !f.IsValid() || f.Kind() != reflect.Func || !f.CanSet() {
		return false
	}
	t := f.Type()
	if t.NumIn() != 3 || t.NumOut() != 0 {
		return false
	}
	f.Set(reflect.MakeFunc(t, func(args []reflect.Value) []reflect.Value {
		if len(args) == 3 {
			if d, ok := args[2].Interface().(time.Duration); ok {
				m.Observe("kiwi_runner_step_duration_seconds", d.Seconds())
			}
		}
		return nil
	}))
	return true
}

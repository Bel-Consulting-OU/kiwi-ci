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

// stepReporterFunc is the expected executor.Options.StepReporter signature:
// it receives a completed step's wall-clock duration as measured by the
// executor, which is the real measurement (the sink-derived approximation
// was removed).
type stepReporterFunc func(jobID, step string, d time.Duration)

// applyStepReporter wires the executor's StepReporter hook into the
// kiwi_runner_step_duration_seconds counter. The hook is added by the
// executor workstream; until it lands, the field is absent and the function
// returns false (step durations are then simply not collected). The wiring
// is reflection-based so this package builds against executor versions with
// and without the field.
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

package runner

import (
	"bufio"
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

func TestMetricsExpositionParses(t *testing.T) {
	m := NewMetrics()
	m.Counter("kiwi_runner_cache_hits", 3)
	m.Counter("kiwi_runner_cache_misses", 1)
	m.Observe("kiwi_runner_checkout_duration_seconds", 1.5)
	m.Counter("kiwi_runner_artifact_bytes", 4096)
	m.Observe("kiwi_runner_step_duration_seconds", 2.25)
	m.Observe("kiwi_runner_snapshot_duration_seconds", 0.5)

	var buf bytes.Buffer
	if err := m.Expose(&buf); err != nil {
		t.Fatal(err)
	}
	content := buf.String()
	if !strings.Contains(content, "# TYPE kiwi_runner_cache_hits counter") {
		t.Fatal("exposition lacks TYPE comment")
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	values := map[string]float64{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("unexpected exposition line %q", line)
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			t.Fatalf("metric %s: %v", fields[0], err)
		}
		values[fields[0]] = v
	}
	want := map[string]float64{
		"kiwi_runner_cache_hits":                3,
		"kiwi_runner_cache_misses":              1,
		"kiwi_runner_checkout_duration_seconds": 1.5,
		"kiwi_runner_artifact_bytes":            4096,
		"kiwi_runner_step_duration_seconds":     2.25,
		"kiwi_runner_snapshot_duration_seconds": 0.5,
	}
	for name, wantV := range want {
		got, ok := values[name]
		if !ok {
			t.Fatalf("metric %s missing from exposition", name)
		}
		if got != wantV {
			t.Fatalf("metric %s = %v, want %v", name, got, wantV)
		}
	}
}

// TestStepReporterWiring verifies that when the executor build carries the
// StepReporter hook, the runner wires it to kiwi_runner_step_duration_seconds
// with the REAL executor-measured wall-clock duration (the sink-derived
// approximation was removed). When the field is absent (executor predates
// the hook) the wiring reports false and no observation is possible.
func TestStepReporterWiring(t *testing.T) {
	m := NewMetrics()
	var opts executor.Options
	if !applyStepReporter(&opts, m) {
		t.Fatal("applyStepReporter found no usable StepReporter field: the executor/runner wiring must be present in every build")
	}
	f := reflect.ValueOf(&opts).Elem().FieldByName("StepReporter")
	if !f.IsValid() || f.Kind() != reflect.Func || f.IsNil() {
		t.Fatal("applyStepReporter reported success but did not install the StepReporter hook")
	}
	f.Call([]reflect.Value{
		reflect.ValueOf("job-1"),
		reflect.ValueOf("build"),
		reflect.ValueOf(3 * time.Second),
	})
	m.mu.Lock()
	got := m.counters["kiwi_runner_step_duration_seconds"]
	m.mu.Unlock()
	if got != 3 {
		t.Fatalf("kiwi_runner_step_duration_seconds = %v, want 3", got)
	}
}

// TestApplyStepReporterRejectsWrongShape was removed: executor.Options.StepReporter
// is a compile-time-fixed field of exactly the accepted signature
// (func(jobID, stepID string, d time.Duration)), so no test input can present
// the wrong shape to applyStepReporter without editing production types. The
// reachable contract (the hook is installed and observes real durations) is
// covered mutation-proof by TestStepReporterWiring above.

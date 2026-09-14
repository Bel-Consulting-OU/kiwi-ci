package runner

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
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

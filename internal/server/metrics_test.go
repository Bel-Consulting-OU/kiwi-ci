package server

import (
	"strings"
	"testing"
)

func TestMetricsExposition(t *testing.T) {
	m := NewMetrics()
	m.Add("kiwi_lease_expirations_total", 2, nil)
	m.Add("kiwi_cache_hits_total", 3, nil)
	m.Add("kiwi_http_requests_total", 1, map[string]string{"code": "200", "method": "GET", "path_class": "runs"})
	m.Add("kiwi_http_requests_total", 1, map[string]string{"code": "429", "method": "GET", "path_class": "runs"})
	m.Observe("kiwi_queue_latency_seconds", 0.5, nil)
	m.Observe("kiwi_queue_latency_seconds", 2.5, nil)
	m.SetGauge("kiwi_runner_saturation", 0.75, nil)
	m.SetGauge("kiwi_db_pool", 5, map[string]string{"stat": "acquired"})

	var b strings.Builder
	m.WritePrometheus(&b)
	out := b.String()

	for _, want := range []string{
		"# HELP kiwi_lease_expirations_total",
		"# TYPE kiwi_lease_expirations_total counter",
		"kiwi_lease_expirations_total 2",
		"kiwi_cache_hits_total 3",
		`kiwi_http_requests_total{code="200",method="GET",path_class="runs"} 1`,
		`kiwi_http_requests_total{code="429",method="GET",path_class="runs"} 1`,
		"# TYPE kiwi_queue_latency_seconds histogram",
		`kiwi_queue_latency_seconds_bucket{le="0.5"} 1`,
		`kiwi_queue_latency_seconds_bucket{le="2.5"} 2`,
		`kiwi_queue_latency_seconds_bucket{le="+Inf"} 2`,
		"kiwi_queue_latency_seconds_sum 3",
		"kiwi_queue_latency_seconds_count 2",
		"kiwi_runner_saturation 0.75",
		`kiwi_db_pool{stat="acquired"} 5`,
		"# TYPE kiwi_db_pool gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q\n%s", want, out)
		}
	}
	// Pre-declared but unobserved counters render as zero.
	if !strings.Contains(out, "kiwi_webhook_failures_total 0") {
		t.Errorf("unobserved counter missing zero sample:\n%s", out)
	}
}

func TestMetricsUnknownNamePanics(t *testing.T) {
	m := NewMetrics()
	defer func() {
		if recover() == nil {
			t.Fatal("Add with unknown name did not panic")
		}
	}()
	m.Add("kiwi_nope_total", 1, nil)
}

func TestMetricsHistogramBucketBounds(t *testing.T) {
	m := NewMetrics()
	m.Observe("kiwi_job_duration_seconds", 0.001, nil) // below first bucket
	m.Observe("kiwi_job_duration_seconds", 400, nil)   // above last bucket, in +Inf
	var b strings.Builder
	m.WritePrometheus(&b)
	out := b.String()
	if !strings.Contains(out, `kiwi_job_duration_seconds_bucket{le="0.005"} 1`) {
		t.Error("first bucket count wrong")
	}
	if !strings.Contains(out, `kiwi_job_duration_seconds_bucket{le="+Inf"} 2`) {
		t.Error("+Inf bucket count wrong")
	}
}

func TestMetricsCardinalityCap(t *testing.T) {
	m := NewMetrics()
	for i := 0; i < maxLabelSets+50; i++ {
		m.Add("kiwi_http_requests_total", 1, map[string]string{
			"code": "200", "method": "GET", "path_class": "runs", "extra": string(rune('a'+i%26)) + strings.Repeat("x", i/26),
		})
	}
	m.mu.Lock()
	n := len(m.counters["kiwi_http_requests_total"])
	m.mu.Unlock()
	if n != maxLabelSets {
		t.Errorf("label set count = %d, want capped at %d", n, maxLabelSets)
	}
}

func TestMetricsLabelEscaping(t *testing.T) {
	m := NewMetrics()
	m.SetGauge("kiwi_db_pool", 1, map[string]string{"stat": `a"b\c` + "\nd"})
	var b strings.Builder
	m.WritePrometheus(&b)
	if !strings.Contains(b.String(), `stat="a\"b\\c\nd"`) {
		t.Errorf("label value not escaped:\n%s", b.String())
	}
}

func TestMetricsPathClass(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/readiness", "health"},
		{"/liveness", "health"},
		{"/metrics", "health"},
		{"/hooks/github", "hooks"},
		{"/api/v1/oidc/jwks", "oidc"},
		{"/api/v1/jobs/j1/oidc", "oidc"},
		{"/api/v1/jobs/j1/secrets", "secrets"},
		{"/api/v1/runs/r1/logs", "logs"},
		{"/api/v1/jobs/j1/log", "logs"},
		{"/api/v1/runs/r1/artifacts", "artifacts"},
		{"/api/v1/cache/key", "cache"},
		{"/api/v1/runners", "runners"},
		{"/api/v1/runners/r1/next", "runners"},
		{"/api/v1/runs", "runs"},
		{"/api/v1/runs/r1/jobs", "runs"},
		{"/api/v1/test-intelligence", "other"},
		{"/", "other"},
	}
	for _, c := range cases {
		if got := metricsPathClass(c.path); got != c.want {
			t.Errorf("metricsPathClass(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestNormMethod(t *testing.T) {
	if normMethod("GET") != "GET" || normMethod("CONNECT") != "other" {
		t.Errorf("normMethod wrong: %q %q", normMethod("GET"), normMethod("CONNECT"))
	}
}

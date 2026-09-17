package server

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metrics is a dependency-free Prometheus-style registry: cumulative
// counters, fixed-bucket histograms and gauges, exported in the
// Prometheus text format 0.0.4. Label cardinality is bounded: vector
// metrics admit at most maxLabelSets distinct label sets, and callers must
// only use the fixed label vocabularies declared below (never raw repo
// names, run IDs or other unbounded values).
type Metrics struct {
	mu         sync.Mutex
	meta       map[string]metricMeta
	counters   map[string]map[string]float64
	gauges     map[string]map[string]float64
	histograms map[string]map[string]*histogram
}

type metricMeta struct {
	help   string
	typ    string // "counter", "histogram", "gauge"
	bounds []float64
}

type histogram struct {
	bounds []float64
	counts []uint64 // cumulative: observations <= bounds[i]
	sum    float64
	count  uint64
}

func (h *histogram) observe(v float64) {
	h.sum += v
	h.count++
	for i, b := range h.bounds {
		if v <= b {
			h.counts[i]++
		}
	}
}

// maxLabelSets bounds vector cardinality per metric name. Beyond it, new
// label sets are dropped rather than unboundedly accumulated.
const maxLabelSets = 1000

// defaultHistogramBounds are the seconds buckets shared by every
// duration histogram (5ms to 5min).
var defaultHistogramBounds = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}

// NewMetrics returns a registry with every kiwi_* metric pre-declared so
// scrapes always see the full HELP/TYPE surface even before the first
// observation.
func NewMetrics() *Metrics {
	m := &Metrics{
		meta:       map[string]metricMeta{},
		counters:   map[string]map[string]float64{},
		gauges:     map[string]map[string]float64{},
		histograms: map[string]map[string]*histogram{},
	}
	m.declare("kiwi_lease_expirations_total", "Job leases expired and recovered", "counter", nil)
	m.declare("kiwi_lost_runners_total", "Jobs failed after exhausting infra retries on lost runners", "counter", nil)
	m.declare("kiwi_queue_timeouts_total", "Queued jobs cancelled after their queue deadline", "counter", nil)
	m.declare("kiwi_runner_killswitch_jobs_total", "Active job leases invalidated by the runner disable kill switch", "counter", nil)
	m.declare("kiwi_cache_hits_total", "Cache download hits", "counter", nil)
	m.declare("kiwi_cache_misses_total", "Cache download misses", "counter", nil)
	m.declare("kiwi_cache_bytes_total", "Bytes served from the cache", "counter", nil)
	m.declare("kiwi_artifact_bytes_total", "Bytes uploaded as artifacts", "counter", nil)
	m.declare("kiwi_webhook_failures_total", "Webhook deliveries rejected or failed", "counter", nil)
	m.declare("kiwi_oidc_issues_total", "OIDC tokens issued to jobs", "counter", nil)
	m.declare("kiwi_secret_deliveries_total", "Secrets delivered to leased jobs", "counter", nil)
	m.declare("kiwi_http_requests_total", "HTTP requests by status code, method and path class", "counter", nil)
	m.declare("kiwi_queue_latency_seconds", "Time a job waited from enqueue to lease", "histogram", defaultHistogramBounds)
	m.declare("kiwi_job_duration_seconds", "Job wall-clock duration", "histogram", defaultHistogramBounds)
	m.declare("kiwi_step_duration_seconds", "Pipeline step duration", "histogram", defaultHistogramBounds)
	m.declare("kiwi_checkout_duration_seconds", "Workspace checkout duration", "histogram", defaultHistogramBounds)
	m.declare("kiwi_environment_wait_seconds", "Time jobs waited for an environment lock", "histogram", defaultHistogramBounds)
	m.declare("kiwi_approval_wait_seconds", "Time jobs waited for approval", "histogram", defaultHistogramBounds)
	m.declare("kiwi_test_duration_seconds", "Test report test duration", "histogram", defaultHistogramBounds)
	m.declare("kiwi_http_duration_seconds", "HTTP request handling latency", "histogram", defaultHistogramBounds)
	m.declare("kiwi_cas_latency_seconds", "Content-addressed storage latency", "histogram", defaultHistogramBounds)
	m.declare("kiwi_cas_gc_deleted_objects_total", "Unreferenced CAS objects removed by the garbage collector", "counter", nil)
	m.declare("kiwi_cas_gc_deleted_bytes_total", "Unreferenced CAS bytes removed by the garbage collector", "counter", nil)
	m.declare("kiwi_scheduler_loop_duration_seconds", "Scheduler housekeeping loop duration", "histogram", defaultHistogramBounds)
	m.declare("kiwi_runner_saturation", "Fraction of runner capacity in use (busy slots / total slots)", "gauge", nil)
	m.declare("kiwi_db_pool", "Database pool statistics by stat name", "gauge", nil)
	m.declare("kiwi_usage_cost_total", "Aggregated job cost recorded at completion", "counter", nil)
	m.declare("kiwi_usage_energy_total", "Aggregated job energy (Wh) recorded at completion", "counter", nil)
	m.declare("kiwi_dynamic_jobs_generated_total", "Dynamically generated child jobs admitted", "counter", nil)
	m.declare("kiwi_dynamic_jobs_rejected_total", "Dynamically generated child jobs rejected", "counter", nil)
	m.declare("kiwi_downstream_launches_total", "Cross-repo downstream runs launched", "counter", nil)
	m.declare("kiwi_downstream_skips_total", "Cross-repo downstream dispatches skipped (already launched)", "counter", nil)
	return m
}

func (m *Metrics) declare(name, help, typ string, bounds []float64) {
	m.meta[name] = metricMeta{help: help, typ: typ, bounds: bounds}
	switch typ {
	case "counter":
		m.counters[name] = map[string]float64{"": 0}
	case "gauge":
		m.gauges[name] = map[string]float64{}
	case "histogram":
		m.histograms[name] = map[string]*histogram{"": &histogram{bounds: bounds, counts: make([]uint64, len(bounds))}}
	}
}

// Add increments a counter by delta. Unknown names are programming errors
// and panic (registry names are compile-time constants).
func (m *Metrics) Add(name string, delta float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	vec, ok := m.counters[name]
	if !ok {
		panic("metrics: unknown counter " + name)
	}
	k := labelKey(labels)
	if _, exists := vec[k]; !exists && len(vec) >= maxLabelSets {
		return
	}
	vec[k] += delta
}

// Observe records one observation in a histogram.
func (m *Metrics) Observe(name string, v float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	vec, ok := m.histograms[name]
	if !ok {
		panic("metrics: unknown histogram " + name)
	}
	k := labelKey(labels)
	h := vec[k]
	if h == nil {
		if len(vec) >= maxLabelSets {
			return
		}
		h = &histogram{bounds: m.meta[name].bounds, counts: make([]uint64, len(m.meta[name].bounds))}
		vec[k] = h
	}
	h.observe(v)
}

// SetGauge sets a gauge to v.
func (m *Metrics) SetGauge(name string, v float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	vec, ok := m.gauges[name]
	if !ok {
		panic("metrics: unknown gauge " + name)
	}
	k := labelKey(labels)
	if _, exists := vec[k]; !exists && len(vec) >= maxLabelSets {
		return
	}
	vec[k] = v
}

// Reset zeroes every counter, gauge vector and histogram while keeping the
// pre-declared HELP/TYPE surface. Tests use it to assert call-site
// behavior without cross-test pollution.
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name := range m.counters {
		m.counters[name] = map[string]float64{"": 0}
	}
	for name := range m.gauges {
		m.gauges[name] = map[string]float64{}
	}
	for name, meta := range m.meta {
		if meta.typ == "histogram" {
			m.histograms[name] = map[string]*histogram{"": {bounds: meta.bounds, counts: make([]uint64, len(meta.bounds))}}
		}
	}
}

// WritePrometheus renders the registry in Prometheus text format 0.0.4.
// Output is deterministic: metric names, label sets and buckets are
// sorted.
func (m *Metrics) WritePrometheus(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.meta))
	for name := range m.meta {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		meta := m.meta[name]
		fmt.Fprintf(w, "# HELP %s %s\n", name, meta.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", name, meta.typ)
		switch meta.typ {
		case "counter":
			m.writeVec(w, name, m.counters[name])
		case "gauge":
			m.writeVec(w, name, m.gauges[name])
		case "histogram":
			m.writeHistogram(w, name, meta.bounds, m.histograms[name])
		}
	}
}

func (m *Metrics) writeVec(w io.Writer, name string, vec map[string]float64) {
	for _, k := range sortedKeys(vec) {
		if k == "" {
			fmt.Fprintf(w, "%s %s\n", name, formatFloat(vec[k]))
		} else {
			fmt.Fprintf(w, "%s{%s} %s\n", name, k, formatFloat(vec[k]))
		}
	}
}

func (m *Metrics) writeHistogram(w io.Writer, name string, bounds []float64, vec map[string]*histogram) {
	for _, k := range sortedKeys(vec) {
		h := vec[k]
		for i, b := range bounds {
			fmt.Fprintf(w, "%s_bucket{le=%q%s} %d\n", name, formatFloat(b), suffix(k), h.counts[i])
		}
		fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"%s} %d\n", name, suffix(k), h.count)
		fmt.Fprintf(w, "%s_sum%s %s\n", name, brace(k), formatFloat(h.sum))
		fmt.Fprintf(w, "%s_count%s %d\n", name, brace(k), h.count)
	}
}

// suffix renders k as ",k=v,..." for bucket lines; brace renders k as
// "{k=v,...}" for sum/count lines.
func suffix(k string) string {
	if k == "" {
		return ""
	}
	return "," + k
}

func brace(k string) string {
	if k == "" {
		return ""
	}
	return "{" + k + "}"
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// labelKey renders a label set into the canonical, escaped
// "k=\"v\",k2=\"v2\"" form used as the internal identity.
func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(labels[k]))
		b.WriteByte('"')
	}
	return b.String()
}

// escapeLabel escapes backslash, quote and newline per the Prometheus
// text format.
func escapeLabel(v string) string {
	if !strings.ContainsAny(v, `\"`+"\n") {
		return v
	}
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// metricsPathClass maps a request path to one of the fixed, bounded path
// classes for kiwi_http_requests_total. Raw IDs never leak into labels.
func metricsPathClass(p string) string {
	switch {
	case p == "/readiness" || p == "/liveness" || p == "/metrics":
		return "health"
	case strings.HasPrefix(p, "/hooks/"):
		return "hooks"
	case strings.HasPrefix(p, "/api/v1/oidc") || strings.HasSuffix(p, "/oidc"):
		return "oidc"
	case strings.HasSuffix(p, "/secrets"):
		return "secrets"
	case strings.HasSuffix(p, "/logs") || strings.HasSuffix(p, "/log"):
		return "logs"
	case strings.Contains(p, "/artifacts"):
		return "artifacts"
	case strings.Contains(p, "/cache"):
		return "cache"
	case strings.Contains(p, "/runners"):
		return "runners"
	case strings.Contains(p, "/runs"):
		return "runs"
	case strings.Contains(p, "/jobs"):
		return "jobs"
	}
	return "other"
}

// normMethod maps HTTP methods onto a bounded label vocabulary.
func normMethod(m string) string {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS":
		return m
	}
	return "other"
}

// metricAdd/metricObserve/metricSet are nil-safe Server instrumentation
// helpers: servers constructed without a registry (bare &Server{} in
// tests) skip recording.
func (s *Server) metricAdd(name string, v float64, labels map[string]string) {
	if s.Metrics != nil {
		s.Metrics.Add(name, v, labels)
	}
}

func (s *Server) metricObserve(name string, v float64, labels map[string]string) {
	if s.Metrics != nil {
		s.Metrics.Observe(name, v, labels)
	}
}

func (s *Server) metricSet(name string, v float64, labels map[string]string) {
	if s.Metrics != nil {
		s.Metrics.SetGauge(name, v, labels)
	}
}

// observeHTTP records kiwi_http_requests_total and the request latency
// histogram for every request that passes through, including 401/429
// responses produced by the middleware chain inside it.
func (s *Server) observeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		code := rec.status
		if code == 0 {
			code = http.StatusOK
		}
		s.metricAdd("kiwi_http_requests_total", 1, map[string]string{
			"code":       strconv.Itoa(code),
			"method":     normMethod(r.Method),
			"path_class": metricsPathClass(r.URL.Path),
		})
		s.metricObserve("kiwi_http_duration_seconds", time.Since(start).Seconds(), map[string]string{
			"method":     normMethod(r.Method),
			"path_class": metricsPathClass(r.URL.Path),
		})
	})
}

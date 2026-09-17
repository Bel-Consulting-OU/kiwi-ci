package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// otelCollector is a minimal OTLP/HTTP collector that records export bodies.
type otelCollector struct {
	mu     sync.Mutex
	reqs   int
	bodies [][]byte
}

func (c *otelCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reqs
}

func (c *otelCollector) exported() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.bodies, nil)
}

func newOTelCollector(t *testing.T) (*otelCollector, *httptest.Server) {
	t.Helper()
	c := &otelCollector{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs++
		c.bodies = append(c.bodies, body)
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

// configureCollectorTracing installs a real OTLP exporter pointed at a test
// collector and restores the previous global provider when the test ends.
func configureCollectorTracing(t *testing.T, s *Server) *otelCollector {
	t.Helper()
	col, srv := newOTelCollector(t)
	prev := otel.GetTracerProvider()
	t.Cleanup(func() {
		s.ShutdownTracing(context.Background())
		otel.SetTracerProvider(prev)
	})
	if err := s.ConfigureTracing(context.Background(), srv.URL+"/v1/traces"); err != nil {
		t.Fatalf("ConfigureTracing = %v", err)
	}
	if !s.otelEnabled || s.otelShutdown == nil {
		t.Fatal("ConfigureTracing did not install a provider")
	}
	return col
}

// TestIDCovConfigureTracingDisabled pins the disabled contract: an empty or
// whitespace endpoint is a no-op that never installs a provider.
func TestIDCovConfigureTracingDisabled(t *testing.T) {
	prev := otel.GetTracerProvider()
	defer otel.SetTracerProvider(prev)
	for _, ep := range []string{"", "   ", "\t\n"} {
		s := New("t")
		if err := s.ConfigureTracing(context.Background(), ep); err != nil {
			t.Fatalf("ConfigureTracing(%q) = %v, want nil", ep, err)
		}
		if s.otelEnabled || s.otelShutdown != nil || s.OTelEndpoint != "" {
			t.Fatalf("ConfigureTracing(%q) enabled tracing", ep)
		}
	}
	if otel.GetTracerProvider() != prev {
		t.Fatal("empty endpoint replaced the global tracer provider")
	}
}

// TestIDCovConfigureTracingExportsSpans proves the previously broken path:
// a well-formed OTLP/HTTP endpoint installs an exporter whose spans reach the
// collector, the service name survives the resource build, and shutdown
// flushes the batch.
func TestIDCovConfigureTracingExportsSpans(t *testing.T) {
	s := New("t")
	col := configureCollectorTracing(t, s)
	if s.OTelEndpoint == "" {
		t.Fatal("configured endpoint not recorded")
	}
	_, span := s.startSpan(context.Background(), "kiwi.test.export",
		attribute.String("k", "v"))
	span.End()
	s.ShutdownTracing(context.Background())
	if s.otelEnabled || s.otelShutdown != nil {
		t.Fatal("ShutdownTracing left tracing enabled")
	}
	if col.count() == 0 {
		t.Fatal("collector received no export requests")
	}
	if !bytes.Contains(col.exported(), []byte(otelServiceName)) {
		t.Fatalf("exported spans lack the %q service name", otelServiceName)
	}
}

// TestIDCovShutdownTracingUsableProvider proves shutdown never poisons the
// global provider: otel.Tracer keeps working after ShutdownTracing and a
// second shutdown is a no-op.
func TestIDCovShutdownTracingUsableProvider(t *testing.T) {
	s := New("t")
	_ = configureCollectorTracing(t, s)
	ctx := context.Background()
	s.ShutdownTracing(ctx)
	_, span := otel.Tracer("post-shutdown").Start(ctx, "usable")
	span.End()
	s.ShutdownTracing(ctx)
	if s.otelEnabled || s.otelShutdown != nil {
		t.Fatal("repeated shutdown changed state")
	}
	_, span = otel.Tracer("post-shutdown-2").Start(ctx, "usable")
	span.End()
}

// TestIDCovConfigureTracingIdempotentReplacesProvider covers the idempotency
// entry path: a second ConfigureTracing call shuts the previous provider down
// and installs a fresh one.
func TestIDCovConfigureTracingIdempotentReplacesProvider(t *testing.T) {
	col, srv := newOTelCollector(t)
	prev := otel.GetTracerProvider()
	defer otel.SetTracerProvider(prev)
	s := New("t")
	ctx := context.Background()
	if err := s.ConfigureTracing(ctx, srv.URL+"/v1/traces"); err != nil {
		t.Fatal(err)
	}
	_, span := s.startSpan(ctx, "first")
	span.End()
	if err := s.ConfigureTracing(ctx, srv.URL+"/v1/traces"); err != nil {
		t.Fatal(err)
	}
	s.ShutdownTracing(ctx)
	if col.count() == 0 {
		t.Fatal("first provider's spans were not flushed by the reconfigure")
	}
}

// TestIDCovInitTracingFromEnv covers the env wiring: unset is a no-op and a
// set endpoint enables tracing through ConfigureTracing.
func TestIDCovInitTracingFromEnv(t *testing.T) {
	prev := otel.GetTracerProvider()
	defer otel.SetTracerProvider(prev)
	s := New("t")
	s.initTracingFromEnv()
	if s.otelEnabled {
		t.Fatal("tracing enabled without KIWI_OTEL_ENDPOINT")
	}
	col, srv := newOTelCollector(t)
	t.Setenv("KIWI_OTEL_ENDPOINT", "  "+srv.URL+"/v1/traces  ")
	s2 := New("t")
	s2.initTracingFromEnv()
	if !s2.otelEnabled {
		t.Fatal("tracing not enabled from KIWI_OTEL_ENDPOINT")
	}
	_, span := s2.startSpan(context.Background(), "env")
	span.End()
	s2.ShutdownTracing(context.Background())
	if col.count() == 0 {
		t.Fatal("env-configured exporter exported nothing")
	}
}

// TestIDCovStartSpan covers both startSpan branches: disabled returns the
// context unchanged, enabled attaches the service attribute plus the request
// ID when the context carries one.
func TestIDCovStartSpan(t *testing.T) {
	s := New("t")
	ctx := context.Background()
	out, span := s.startSpan(ctx, "disabled")
	if out != ctx || span == nil {
		t.Fatal("disabled startSpan did not return the original context/span")
	}
	if s.tracer() == nil {
		t.Fatal("tracer() returned nil")
	}
	if got := requestIDFromCtx(ctx); got != "" {
		t.Fatalf("requestIDFromCtx(empty) = %q", got)
	}

	_ = configureCollectorTracing(t, s)
	idCtx := context.WithValue(ctx, requestIDContextKey{}, "req-abc")
	withID, span := s.startSpan(idCtx, "enabled", spanInt("n", 7), attribute.String("k", "v"))
	if withID == nil || span == nil {
		t.Fatal("enabled startSpan returned nil")
	}
	span.End()
	// A context value of the wrong type must not panic and must report "".
	if got := requestIDFromCtx(context.WithValue(ctx, requestIDContextKey{}, 42)); got != "" {
		t.Fatalf("requestIDFromCtx(non-string) = %q", got)
	}
	if got := requestIDFromCtx(idCtx); got != "req-abc" {
		t.Fatalf("requestIDFromCtx = %q", got)
	}
}

// TestIDCovTracingMiddlewareDisabled passes requests straight through when
// tracing is off.
func TestIDCovTracingMiddlewareDisabled(t *testing.T) {
	s := New("t")
	called := false
	h := s.tracingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if !called || w.Code != http.StatusTeapot {
		t.Fatalf("disabled middleware called=%v code=%d", called, w.Code)
	}
}

// TestIDCovTracingMiddlewareEnabled walks the enabled middleware status
// classes: 2xx, 4xx (rejected) and 5xx (server error + recorded error).
func TestIDCovTracingMiddlewareEnabled(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   bool
	}{
		{"ok", http.StatusOK, false},
		{"write-implies-200", 0, true},
		{"rejected", http.StatusForbidden, false},
		{"server-error", http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New("t")
			_ = configureCollectorTracing(t, s)
			h := s.tracingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.body {
					_, _ = w.Write([]byte("body"))
					return
				}
				w.WriteHeader(tc.status)
			}))
			r := httptest.NewRequest(http.MethodGet, "/api/v1/runs/abc", nil)
			r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, "rid-"+tc.name))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := tc.status
			if tc.body {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("status = %d, want %d", w.Code, want)
			}
		})
	}
}

// TestIDCovTracingMiddlewareThroughHandler proves the middleware is wired in
// the real Handler() chain and that the request ID reaches the span context.
func TestIDCovTracingMiddlewareThroughHandler(t *testing.T) {
	s := New("admin-token")
	_ = configureCollectorTracing(t, s)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/liveness", nil)
	r.Header.Set("X-Kiwi-Request-ID", "client-id-1")
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("liveness = %d", w.Code)
	}
	if got := w.Header().Get("X-Kiwi-Request-ID"); got != "client-id-1" {
		t.Fatalf("request id echo = %q", got)
	}
}

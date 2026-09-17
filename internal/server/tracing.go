package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const otelServiceName = "kiwi-server"

// ConfigureTracing installs an OTLP/HTTP trace exporter and sets the global
// tracer provider. It is idempotent for the same endpoint; an empty
// endpoint disables tracing. The returned shutdown flushes pending spans.
func (s *Server) ConfigureTracing(ctx context.Context, endpoint string) error {
	s.shutdownTracing(ctx)
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(strings.TrimSpace(endpoint)))
	if err != nil {
		return fmt.Errorf("otel: create exporter: %w", err)
	}
	attrs := append(resource.Default().Attributes(), semconv.ServiceName(otelServiceName))
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewSchemaless(attrs...)),
	)
	otel.SetTracerProvider(provider)
	s.otelShutdown = provider.Shutdown
	s.otelEnabled = true
	s.OTelEndpoint = endpoint
	s.logInfo("otel tracing enabled", "endpoint", endpoint)
	return nil
}

// initTracingFromEnv wires tracing from KIWI_OTEL_ENDPOINT when set, so a
// deployment can enable spans without a code change. Explicit
// ConfigureTracing calls remain available for the app wiring.
func (s *Server) initTracingFromEnv() {
	if ep := strings.TrimSpace(os.Getenv("KIWI_OTEL_ENDPOINT")); ep != "" {
		if err := s.ConfigureTracing(context.Background(), ep); err != nil {
			s.logError("otel: setup failed, tracing disabled", "error", err.Error())
		}
	}
}

func (s *Server) shutdownTracing(ctx context.Context) {
	if s.otelShutdown != nil {
		_ = s.otelShutdown(ctx)
		s.otelShutdown = nil
		s.otelEnabled = false
		otel.SetTracerProvider(noop.NewTracerProvider())
	}
}

// ShutdownTracing flushes and disables tracing; callers that configured a
// provider should invoke it at process exit.
func (s *Server) ShutdownTracing(ctx context.Context) { s.shutdownTracing(ctx) }

// tracer returns the package tracer, or a no-op when tracing is disabled.
func (s *Server) tracer() trace.Tracer {
	return otel.Tracer("github.com/Bel-Consulting-OU/kiwi-ci/internal/server")
}

// startSpan begins a named span on the request context when tracing is
// enabled; otherwise it returns the context unchanged. The request ID is
// attached as an attribute when present.
func (s *Server) startSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if !s.otelEnabled {
		return ctx, trace.SpanFromContext(ctx)
	}
	all := []attribute.KeyValue{attribute.String("service", otelServiceName)}
	if id := requestIDFromCtx(ctx); id != "" {
		all = append(all, attribute.String("kiwi.request_id", id))
	}
	all = append(all, attrs...)
	spanCtx, span := s.tracer().Start(ctx, name, trace.WithAttributes(all...))
	return spanCtx, span
}

func requestIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		return id
	}
	return ""
}

// tracingMiddleware creates one span per request named after the method and
// path class, tagging it with the request ID, the observed status code and
// any error.
func (s *Server) tracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.otelEnabled {
			next.ServeHTTP(w, r)
			return
		}
		ctx, span := s.startSpan(r.Context(), "http "+r.Method+" "+metricsPathClass(r.URL.Path),
			attribute.String("http.method", r.Method),
			attribute.String("http.route", r.URL.Path),
		)
		defer span.End()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r.WithContext(ctx))
		span.SetAttributes(attribute.Int("http.status_code", rec.status))
		if rec.status >= 500 {
			span.SetStatus(codes.Error, "server error")
			span.RecordError(fmt.Errorf("http status %d", rec.status))
		} else if rec.status >= 400 {
			span.SetStatus(codes.Error, "request rejected")
		}
	})
}

// spanInt is a tiny helper for numeric span attributes.
func spanInt(k string, v int64) attribute.KeyValue { return attribute.Int64(k, v) }

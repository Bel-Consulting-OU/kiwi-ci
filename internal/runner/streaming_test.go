package runner

// Streaming/deadline regression tests for the S1 client policy:
//
//   - ordinary control-plane calls keep a bounded TOTAL timeout
//     (controlClientTimeout),
//   - bulk artifact/cache/snapshot/dependency transfers run on a separate
//     client with Timeout 0 (transport phase bounds only) and a sliding
//     inactivity guard (streamIdleTimeout),
//   - a stalled peer is still torn down on the streaming path.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// slowStreamServer serves a fixed number of one-byte chunks with a gap
// between them, so the total exchange outlives a shrunken control timeout
// while every individual gap is far below the idle bound.
func slowStreamServer(t *testing.T, chunks int, gap time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("stream test writer is not flushable")
			return
		}
		for i := 0; i < chunks; i++ {
			if _, err := io.WriteString(w, "x"); err != nil {
				return
			}
			fl.Flush()
			time.Sleep(gap)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestStreamingClientPolicyOutlivesControlTimeout proves the split policy on
// plain HTTP: a response streamed over a duration far beyond the (shrunken)
// control timeout completes through the streaming client and is cut through
// the control client. This is exactly the 8 GiB-object class the global 65s
// timeout used to kill.
func TestStreamingClientPolicyOutlivesControlTimeout(t *testing.T) {
	prevControl := controlClientTimeout
	controlClientTimeout = 250 * time.Millisecond
	t.Cleanup(func() { controlClientTimeout = prevControl })

	const chunks = 8
	srv := slowStreamServer(t, chunks, 100*time.Millisecond) // ~800ms total

	// One shared transport, mirroring applyClientPolicy/prepareClient: only
	// the per-client total timeout differs.
	transport := newStreamingTransport(nil)
	control := &http.Client{Timeout: controlClientTimeout, Transport: transport}
	stream := &http.Client{Transport: transport}

	// Failing before headers is also a valid bounded outcome; succeeding
	// requires a fully read body.
	controlStart := time.Now()
	if respCtl, ctlErr := control.Get(srv.URL); ctlErr == nil {
		_, rerr := io.ReadAll(respCtl.Body)
		respCtl.Body.Close()
		if rerr == nil {
			t.Fatal("stream longer than the control timeout completed through the control client")
		}
	}
	if elapsed := time.Since(controlStart); elapsed > 2*time.Second {
		t.Fatalf("control client failure took %v, want the bounded total timeout", elapsed)
	}

	resp, err := stream.Get(srv.URL)
	if err != nil {
		t.Fatalf("streaming client cut a healthy slow stream: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("streaming client read: %v", err)
	}
	if len(got) != chunks {
		t.Fatalf("streamed %d chunks, want %d", len(got), chunks)
	}
}

// TestMTLSStreamingClientPolicyOutlivesControlTimeout proves the same split
// for the mTLS-prepared client: prepareClient must install both clients (the
// streaming one reusing the certificate transport) and the slow stream must
// survive the control timeout over TLS.
func TestMTLSStreamingClientPolicyOutlivesControlTimeout(t *testing.T) {
	prevControl := controlClientTimeout
	controlClientTimeout = 250 * time.Millisecond
	t.Cleanup(func() { controlClientTimeout = prevControl })

	serverCertPEM, serverKeyPEM := selfSignedServerCert(t)
	const chunks = 8
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			if _, err := io.WriteString(w, "x"); err != nil {
				return
			}
			fl.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	tlsConf, err := runnerpki.TLSServerConfig(serverCertPEM, serverKeyPEM, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = tlsConf
	srv.StartTLS()
	t.Cleanup(srv.Close)

	r := &Runner{Cfg: Config{Server: srv.URL, CACert: string(serverCertPEM)}, ID: "runner-1"}
	if err := r.prepareClient(context.Background()); err != nil {
		t.Fatalf("prepareClient: %v", err)
	}
	if r.Client == nil || r.StreamClient == nil {
		t.Fatalf("mTLS preparation must install both clients: control=%v stream=%v", r.Client, r.StreamClient)
	}
	if r.Client.Timeout != controlClientTimeout {
		t.Fatalf("control client Timeout = %v, want %v", r.Client.Timeout, controlClientTimeout)
	}
	if r.StreamClient.Timeout != 0 {
		t.Fatalf("streaming client Timeout = %v, want 0 (no total bound)", r.StreamClient.Timeout)
	}
	tr, ok := r.StreamClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("streaming transport = %T, want *http.Transport", r.StreamClient.Transport)
	}
	if tr.TLSHandshakeTimeout != 30*time.Second || tr.ResponseHeaderTimeout != 60*time.Second || tr.IdleConnTimeout != 90*time.Second {
		t.Fatalf("streaming transport phase bounds = handshake %v header %v idle %v, want 30s/60s/90s", tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, tr.IdleConnTimeout)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("streaming transport lost the mTLS configuration")
	}

	if resp, err := r.Client.Get(srv.URL); err == nil {
		_, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr == nil {
			t.Fatal("slow stream completed through the mTLS control client")
		}
	}
	resp, err := r.StreamClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS streaming client cut a healthy slow stream: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("mTLS streaming read: %v", err)
	}
}

// TestArtifactUploadUsesStreamingClient asserts the client selection directly
// and observably: putArtifact must run on StreamClient (Timeout 0) and never
// on the bounded control client, and a healthy upload whose exchange outlives
// the control timeout must succeed.
func TestArtifactUploadUsesStreamingClient(t *testing.T) {
	prevControl := controlClientTimeout
	controlClientTimeout = 250 * time.Millisecond
	t.Cleanup(func() { controlClientTimeout = prevControl })

	var controlHits, streamHits atomic.Int64
	recording := func(hits *atomic.Int64) http.RoundTripper {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hits.Add(1)
			_, _ = io.Copy(io.Discard, req.Body)
			return &http.Response{
				StatusCode: http.StatusCreated,
				Status:     "201 Created",
				Header:     http.Header{},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		})
	}
	// The streaming transport takes longer than the control timeout before
	// answering, exactly like a real large upload: only a client without a
	// total timeout can carry it.
	slowRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		streamHits.Add(1)
		_, _ = io.Copy(io.Discard, req.Body)
		time.Sleep(400 * time.Millisecond)
		return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Header: http.Header{}, Body: http.NoBody, Request: req}, nil
	})

	r := &Runner{
		ID:           "runner-1",
		Cfg:          Config{Server: "http://kiwi.invalid"},
		Client:       &http.Client{Timeout: controlClientTimeout, Transport: recording(&controlHits)},
		StreamClient: &http.Client{Transport: slowRT},
		Metrics:      NewMetrics(),
	}
	path := filepath.Join(t.TempDir(), "artifact.tar.gz")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.putArtifact(context.Background(), basicTask(payloadPipeline), "bin", path); err != nil {
		t.Fatalf("putArtifact through the streaming client: %v", err)
	}
	if got := streamHits.Load(); got != 1 {
		t.Fatalf("streaming client served %d uploads, want 1", got)
	}
	if got := controlHits.Load(); got != 0 {
		t.Fatalf("bounded control client served %d uploads, want 0", got)
	}
}

// TestControlClientTimesOutOnStalledResponse is the counterpart guarantee:
// the bounded control client (register/next/heartbeat/log-batch/completion
// JSON) must still cut a peer that never answers.
func TestControlClientTimesOutOnStalledResponse(t *testing.T) {
	prevControl := controlClientTimeout
	controlClientTimeout = 200 * time.Millisecond
	t.Cleanup(func() { controlClientTimeout = prevControl })

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	r := &Runner{ID: "runner-1", Cfg: Config{Server: srv.URL}, Client: &http.Client{Timeout: controlClientTimeout}, Metrics: NewMetrics()}
	start := time.Now()
	err := r.post(context.Background(), "/api/v1/runners/register", map[string]string{"name": "r"}, nil)
	if err == nil {
		t.Fatal("stalled control call succeeded, want the total timeout to fire")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled control call returned after %v, want the bounded total timeout", elapsed)
	}
}

// TestStreamingIdleGuardCancelsStalledDownload proves the runner-side sliding
// guard: a dependency download that sends some bytes and then stops is
// cancelled after the idle bound instead of hanging forever.
func TestStreamingIdleGuardCancelsStalledDownload(t *testing.T) {
	prevIdle := streamIdleTimeout
	streamIdleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { streamIdleTimeout = prevIdle })

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	r := &Runner{
		ID:           "runner-1",
		Cfg:          Config{Server: srv.URL, CacheRoot: t.TempDir()},
		Client:       &http.Client{Timeout: 30 * time.Second},
		StreamClient: &http.Client{Transport: newStreamingTransport(nil)},
		Metrics:      NewMetrics(),
	}
	start := time.Now()
	err := r.restoreDownloads(context.Background(), basicTask(payloadPipeline),
		[]pipeline.ArtifactInput{{From: "build", Name: "bin", Path: "deps"}}, t.TempDir())
	if err == nil {
		t.Fatal("stalled download succeeded, want the idle guard to cancel it")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled download returned after %v; the idle guard did not fire", elapsed)
	}
}

// TestStreamingIdleGuardKeepsSlowButContinuousRead confirms the guard is
// sliding, not absolute: a download whose every gap is below the idle bound
// completes even though its total duration is many idle windows.
func TestStreamingIdleGuardKeepsSlowButContinuousRead(t *testing.T) {
	prevIdle := streamIdleTimeout
	streamIdleTimeout = 400 * time.Millisecond
	t.Cleanup(func() { streamIdleTimeout = prevIdle })

	body := tarGzWithFile(t, "app.txt", "slow-but-alive")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("stream test writer is not flushable")
			return
		}
		// One small chunk every 100ms: each gap is a quarter of the idle
		// bound, so only an ABSOLUTE timeout could cut this transfer.
		for off := 0; off < len(body); off += 8 {
			end := off + 8
			if end > len(body) {
				end = len(body)
			}
			if _, err := w.Write(body[off:end]); err != nil {
				return
			}
			fl.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)

	r := &Runner{
		ID:           "runner-1",
		Cfg:          Config{Server: srv.URL, CacheRoot: t.TempDir()},
		Client:       &http.Client{Timeout: 30 * time.Second},
		StreamClient: &http.Client{Transport: newStreamingTransport(nil)},
		Metrics:      NewMetrics(),
	}
	workspace := t.TempDir()
	start := time.Now()
	err := r.restoreDownloads(context.Background(), downloadTask(),
		[]pipeline.ArtifactInput{{From: "build", Name: "bin", Path: "deps"}}, workspace)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("continuous slow download failed: %v", err)
	}
	if elapsed < 400*time.Millisecond {
		t.Fatalf("download finished in %v; it never streamed slowly", elapsed)
	}
	got, err := os.ReadFile(filepath.Join(workspace, "deps", "app.txt"))
	if err != nil || string(got) != "slow-but-alive" {
		t.Fatalf("extracted content = %q, %v", got, err)
	}
}

// TestApplyClientPolicyPlainInstallsUnboundedStreamClient covers the plain
// (non-mTLS) Run path: the control client stays bounded-total, the streaming
// client gets Timeout 0, and both share one connection pool. A caller-
// provided client is preserved and only gains a streaming sibling.
func TestApplyClientPolicyPlainInstallsUnboundedStreamClient(t *testing.T) {
	r := &Runner{ID: "runner-1", Cfg: Config{Server: "http://127.0.0.1:1"}, Metrics: NewMetrics()}
	r.applyClientPolicy()
	if r.Client == nil || r.Client.Timeout != controlClientTimeout {
		t.Fatalf("control client Timeout = %v, want %v", r.Client.Timeout, controlClientTimeout)
	}
	if r.StreamClient == nil || r.StreamClient.Timeout != 0 {
		t.Fatalf("streaming client = %+v, want Timeout 0", r.StreamClient)
	}
	if r.StreamClient.Transport != r.Client.Transport {
		t.Fatal("control and streaming clients do not share one connection pool")
	}
	tr, ok := r.StreamClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("plain streaming transport = %T, want *http.Transport", r.StreamClient.Transport)
	}
	if tr.DialContext == nil || tr.TLSHandshakeTimeout != 30*time.Second || tr.ResponseHeaderTimeout != 60*time.Second || tr.IdleConnTimeout != 90*time.Second {
		t.Fatalf("streaming transport phase bounds not installed: %+v", tr)
	}

	provided := &http.Client{Timeout: 7 * time.Second}
	r2 := &Runner{ID: "runner-2", Cfg: Config{Server: "http://127.0.0.1:1"}, Client: provided, Metrics: NewMetrics()}
	r2.applyClientPolicy()
	if r2.Client != provided {
		t.Fatal("caller-provided control client was replaced")
	}
	if r2.StreamClient == nil || r2.StreamClient.Timeout != 0 {
		t.Fatal("caller-provided control client did not gain an unbounded streaming sibling")
	}
}

// TestJobCacheUsesStreamingClientPolicy asserts the cache store and its inner
// digest-verifying client are both wired with the streaming transport and no
// total timeout, so cache traffic cannot be cut by the control bound.
func TestJobCacheUsesStreamingClientPolicy(t *testing.T) {
	transport := &http.Transport{}
	r := &Runner{
		ID:           "runner-1",
		Cfg:          Config{Server: "http://127.0.0.1:1"},
		Client:       &http.Client{Timeout: controlClientTimeout},
		StreamClient: &http.Client{Transport: transport},
		Metrics:      NewMetrics(),
	}
	store := r.newJobCache(basicTask(payloadPipeline), r.Metrics)
	if store.Client == nil {
		t.Fatal("cache store has no client")
	}
	if store.Client.Timeout != 0 {
		t.Fatalf("cache store client Timeout = %v, want 0 (streaming policy)", store.Client.Timeout)
	}
	tr, ok := store.Client.Transport.(*cacheTransport)
	if !ok {
		t.Fatalf("cache store transport = %T, want *cacheTransport", store.Client.Transport)
	}
	if tr.client == nil || tr.client.HTTP == nil {
		t.Fatal("inner cache client not wired")
	}
	if tr.client.HTTP.Timeout != 0 {
		t.Fatalf("inner cache client Timeout = %v, want 0", tr.client.HTTP.Timeout)
	}
	if tr.client.HTTP.Transport != http.RoundTripper(transport) {
		t.Fatalf("inner cache client transport = %T, want the streaming transport", tr.client.HTTP.Transport)
	}
}

package blob

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const streamTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestS3BodyGuardSlidingWindowAccounting pins the watchdog's sliding window
// with fake time accounting instead of long sleeps: progress that arrives
// inside the window always re-arms it (so a transfer can outlive any number
// of windows), and only a full window without progress aborts.
func TestS3BodyGuardSlidingWindowAccounting(t *testing.T) {
	fired := make(chan struct{})
	guard := newS3BodyGuard(func() { close(fired) }, time.Hour)
	defer guard.stop()

	// Simulated progress for many windows in a row: the callback dispatched
	// after each progress instant must re-check the instant and re-arm rather
	// than abort an active transfer.
	for i := 0; i < 5000; i++ {
		guard.progress()
		guard.onIdle()
		if guard.stalled() {
			t.Fatalf("guard fired although progress continued on iteration %d", i)
		}
	}

	// Simulated silence of two full windows: the callback aborts.
	guard.mu.Lock()
	guard.last = time.Now().Add(-2 * guard.idle)
	guard.mu.Unlock()
	guard.onIdle()
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("guard did not fire after a full silent window")
	}
	if !guard.stalled() {
		t.Fatal("fired guard must report stalled")
	}

	// A stopped guard never fires again.
	guard.stop()
}

// dripReadCloser yields one byte per Read with a fixed gap between reads,
// letting a test simulate a slow but continuously progressing transfer.
type dripReadCloser struct {
	gap    time.Duration
	chunks int
	read   int
	mu     sync.Mutex
}

func (d *dripReadCloser) Read(p []byte) (int, error) {
	d.mu.Lock()
	if d.read >= d.chunks {
		d.mu.Unlock()
		return 0, io.EOF
	}
	n := d.read
	d.read++
	d.mu.Unlock()
	if n > 0 {
		time.Sleep(d.gap)
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = byte('a' + n%26)
	return 1, nil
}

func (d *dripReadCloser) Close() error { return nil }

// TestS3OpenProgressingBodyOutlivesInactivityWindow proves the new contract:
// a body that drips bytes for many times the inactivity window over a total
// wall-clock span that exceeds several windows still succeeds, and the
// request context carries no total deadline at all.
func TestS3OpenProgressingBodyOutlivesInactivityWindow(t *testing.T) {
	const (
		window = 200 * time.Millisecond
		gap    = 25 * time.Millisecond
		chunks = 40
	)
	rt := &recordingTripper{resp: &http.Response{
		StatusCode:    http.StatusOK,
		Body:          &dripReadCloser{gap: gap, chunks: chunks},
		ContentLength: chunks,
	}}
	s := s3WithTripper(rt)
	s.BodyInactivityTimeout = window

	start := time.Now()
	rc, _, err := s.Open(context.Background(), streamTestKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := rt.requestContext(t).Deadline(); ok {
		t.Fatal("Open must not impose a total request deadline")
	}
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("progressing body must not be aborted: %v", err)
	}
	if len(body) != chunks {
		t.Fatalf("body length = %d, want %d", len(body), chunks)
	}
	if elapsed := time.Since(start); elapsed <= 3*window {
		t.Fatalf("transfer completed in %v; expected it to outlive several inactivity windows", elapsed)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestS3OpenStalledBodyAbortsWithInactivityError proves a body that stops
// sending is aborted within about one inactivity window and surfaces a
// timeout-class error (ErrBodyStalled wrapping context.DeadlineExceeded).
func TestS3OpenStalledBodyAbortsWithInactivityError(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("test server does not support flushing")
			return
		}
		_, _ = w.Write([]byte("x"))
		fl.Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	s := s3WithTripper(http.DefaultTransport)
	s.Endpoint = srv.URL

	window := 60 * time.Millisecond
	s.BodyInactivityTimeout = window

	rc, _, err := s.Open(context.Background(), streamTestKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
	buf := make([]byte, 8)
	n, err := rc.Read(buf)
	if n != 1 || err != nil {
		t.Fatalf("first read = (%d, %v), want (1, nil)", n, err)
	}
	start := time.Now()
	n, err = rc.Read(buf)
	elapsed := time.Since(start)
	if n != 0 || err == nil {
		t.Fatalf("stalled read = (%d, %v), want an error", n, err)
	}
	if !errors.Is(err, ErrBodyStalled) {
		t.Fatalf("stalled body error = %v, want ErrBodyStalled", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled body error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("stall aborted after %v, want about one %v window", elapsed, window)
	}
}

// TestS3OpenCallerCancellationAbortsPromptly proves a caller's own
// cancellation aborts the body promptly and is reported unchanged, not
// misattributed to the inactivity watchdog.
func TestS3OpenCallerCancellationAbortsPromptly(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("x"))
		fl.Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	s := s3WithTripper(http.DefaultTransport)
	s.Endpoint = srv.URL
	s.BodyInactivityTimeout = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	rc, _, err := s.Open(ctx, streamTestKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
	buf := make([]byte, 8)
	if n, err := rc.Read(buf); n != 1 || err != nil {
		t.Fatalf("first read = (%d, %v), want (1, nil)", n, err)
	}
	cancel()
	start := time.Now()
	_, err = rc.Read(buf)
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrBodyStalled) {
		t.Fatalf("caller cancellation misattributed to the watchdog: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v to abort the body", elapsed)
	}
}

// TestS3OpenResponseHeaderTimeoutBounded proves a peer that never sends
// response headers is bounded by the transport's ResponseHeaderTimeout, not
// by any body watchdog.
func TestS3OpenResponseHeaderTimeoutBounded(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	s := s3WithTripper(&http.Transport{ResponseHeaderTimeout: 80 * time.Millisecond})
	s.Endpoint = srv.URL

	start := time.Now()
	_, _, err := s.Open(context.Background(), streamTestKey)
	if err == nil {
		t.Fatal("Open against a silent endpoint succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("response-header bound took %v", elapsed)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error %v (%T) is not a timeout-class error", err, err)
	}
}

// TestS3OpenTLSHandshakeTimeoutBounded proves a peer that accepts TCP but
// never completes the TLS handshake is bounded by the transport's
// TLSHandshakeTimeout.
func TestS3OpenTLSHandshakeTimeoutBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})

	s := &S3{
		Endpoint:        "https://" + ln.Addr().String(),
		Region:          "us-east-1",
		Bucket:          "bucket",
		AccessKeyID:     "key",
		SecretAccessKey: "secret",
		PathStyle:       true,
		Client:          &http.Client{Transport: &http.Transport{TLSHandshakeTimeout: 80 * time.Millisecond}},
	}
	start := time.Now()
	_, _, err = s.Open(context.Background(), streamTestKey)
	if err == nil {
		t.Fatal("Open against a silent TLS peer succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("TLS handshake bound took %v", elapsed)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tls") && !strings.Contains(strings.ToLower(err.Error()), "timeout") {
		t.Fatalf("TLS handshake error is not clear: %v", err)
	}
}

package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// s3TestServer returns an httptest server that records PUT bodies against a
// fixed bucket, plus an S3 store pointing at it with path-style addressing.
func s3TestServer(t *testing.T) (*S3, *httptest.Server, map[string][]byte) {
	t.Helper()
	bodies := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			b, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			bodies[r.URL.Path] = b
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			b, ok := bodies[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		case http.MethodDelete:
			delete(bodies, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	s := &S3{
		Endpoint:        srv.URL,
		Region:          "us-east-1",
		Bucket:          "bucket",
		AccessKeyID:     "key",
		SecretAccessKey: "secret",
		PathStyle:       true,
	}
	t.Cleanup(srv.Close)
	return s, srv, bodies
}

func TestS3PutRejectsSizeMismatch(t *testing.T) {
	s, _, bodies := s3TestServer(t)
	key := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	data := []byte("exact payload")

	// Declared size matches: accepted and stored.
	obj, err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if obj.Size != int64(len(data)) {
		t.Fatalf("size = %d", obj.Size)
	}
	if got := bodies["/bucket/"+key]; !bytes.Equal(got, data) {
		t.Fatalf("stored body = %q", got)
	}

	// Short read: the stream ends before the declared size.
	if _, err := s.Put(context.Background(), key, bytes.NewReader(data[:4]), int64(len(data))); err == nil {
		t.Fatal("short put must be rejected")
	}

	// Long stream: more bytes than the declared size.
	long := bytes.Repeat([]byte("x"), 128)
	if _, err := s.Put(context.Background(), key, bytes.NewReader(long), int64(len(long)-1)); err == nil {
		t.Fatal("oversized put must be rejected")
	}

	// Exact size but the server never saw the extra byte: the stored body
	// must be exactly the declared size even when the reader had more.
	if _, err := s.Put(context.Background(), key, bytes.NewReader(long), int64(len(long))); err != nil {
		t.Fatalf("exact put: %v", err)
	}
	if got := bodies["/bucket/"+key]; len(got) != len(long) {
		t.Fatalf("stored body length = %d, want %d", len(got), len(long))
	}
}

func TestS3PutOpenRoundTrip(t *testing.T) {
	s, _, _ := s3TestServer(t)
	key := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	data := []byte("round trip payload")
	if _, err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	rc, obj, err := s.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	if !bytes.Equal(b, data) {
		t.Fatalf("open content = %q", b)
	}
	if obj.Size != int64(len(data)) {
		t.Fatalf("open size = %d", obj.Size)
	}
}

// recordingTripper captures the request it was asked to perform so tests can
// observe the request context, and returns a canned response or error.
type recordingTripper struct {
	mu   sync.Mutex
	req  *http.Request
	resp *http.Response
	err  error
}

func (rt *recordingTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.req = req
	rt.mu.Unlock()
	if rt.err != nil {
		return nil, rt.err
	}
	return rt.resp, nil
}

func (rt *recordingTripper) requestContext(t *testing.T) context.Context {
	t.Helper()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.req == nil {
		t.Fatal("no request reached the transport")
	}
	return rt.req.Context()
}

// s3WithTripper returns a path-style test store whose HTTP client uses rt.
func s3WithTripper(rt http.RoundTripper) *S3 {
	return &S3{
		Endpoint:        "http://s3.test",
		Region:          "us-east-1",
		Bucket:          "bucket",
		AccessKeyID:     "key",
		SecretAccessKey: "secret",
		PathStyle:       true,
		Client:          &http.Client{Transport: rt},
	}
}

// TestS3OpenStreamsBodyAfterReturn pins the stream lifetime contract: Open
// returns as soon as the response headers are available and the body keeps
// streaming afterwards. A server that flushes the first chunk and only then
// produces the rest must not block Open.
func TestS3OpenStreamsBodyAfterReturn(t *testing.T) {
	chunks := []string{"first-chunk|", "second-chunk|", "third-chunk"}
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("test server does not support flushing")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, chunks[0])
		fl.Flush()
		// Fail-safe: a broken Open that waits for the full body must not
		// hang the suite; it must fail on the assertion below instead.
		time.AfterFunc(2*time.Second, unblock)
		<-release
		_, _ = io.WriteString(w, chunks[1])
		fl.Flush()
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(w, chunks[2])
		fl.Flush()
	}))
	t.Cleanup(srv.Close)

	key := strings.Repeat("c", 64)
	s := s3WithTripper(http.DefaultTransport)
	s.Endpoint = srv.URL
	rc, _, err := s.Open(context.Background(), key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	select {
	case <-done:
		t.Fatal("Open returned only after the server had written the whole body")
	default:
	}
	unblock()
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read after Open returned: %v", err)
	}
	if got, want := string(body), strings.Join(chunks, ""); got != want {
		t.Fatalf("streamed body = %q, want %q", got, want)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestS3OpenCloseCancelsRequestContext verifies the request context outlives
// Open while the caller streams, is cancelled by Close, and that Close is
// idempotent.
func TestS3OpenCloseCancelsRequestContext(t *testing.T) {
	payload := []byte("streamed payload")
	rt := &recordingTripper{resp: &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}}
	s := s3WithTripper(rt)

	key := strings.Repeat("d", 64)
	rc, obj, err := s.Open(context.Background(), key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := rt.requestContext(t)
	if ctx.Err() != nil {
		t.Fatalf("request context cancelled while the caller is still streaming: %v", ctx.Err())
	}
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body = %q, want %q", body, payload)
	}
	if obj.Size != int64(len(payload)) {
		t.Fatalf("size = %d, want %d", obj.Size, len(payload))
	}
	if ctx.Err() != nil {
		t.Fatalf("EOF alone must not cancel the request context: %v", ctx.Err())
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("Close must cancel the request context, got %v", ctx.Err())
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestS3OpenFailureCancelsRequestContext verifies every failure path releases
// the bounded request context instead of leaking it until its timeout.
func TestS3OpenFailureCancelsRequestContext(t *testing.T) {
	key := strings.Repeat("e", 64)
	cases := map[string]*recordingTripper{
		"status": {resp: &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("boom")),
		}},
		"not-found": {resp: &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("missing")),
		}},
		"transport": {err: errors.New("connection refused")},
	}
	for name, rt := range cases {
		t.Run(name, func(t *testing.T) {
			s := s3WithTripper(rt)
			if _, _, err := s.Open(context.Background(), key); err == nil {
				t.Fatal("Open must fail")
			}
			ctx := rt.requestContext(t)
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("failed Open leaked its request context: %v", ctx.Err())
			}
		})
	}
}

func TestS3DefaultTransportSettings(t *testing.T) {
	s := &S3{Endpoint: "https://example.com", Bucket: "b"}
	c := s.client()
	if c.CheckRedirect == nil {
		t.Fatal("S3 client must disable redirects")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default client transport = %T, want *http.Transport", c.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("default transport has no dialer")
	}
	if s3Dialer.Timeout != 10*time.Second {
		t.Fatalf("dial timeout = %v, want 10s", s3Dialer.Timeout)
	}
	if s3Dialer.KeepAlive != 30*time.Second {
		t.Fatalf("dial keep-alive = %v, want 30s", s3Dialer.KeepAlive)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Fatalf("idle conn timeout = %v, want 90s", tr.IdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("TLS handshake timeout = %v, want 10s", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("response header timeout = %v, want 30s", tr.ResponseHeaderTimeout)
	}
	if tr.MaxIdleConns != 100 || tr.MaxIdleConnsPerHost != 20 {
		t.Fatalf("idle conn limits = %d/%d, want 100/20", tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}

	// A custom client is respected (copied, with the redirect policy
	// overlaid).
	custom := &http.Client{Timeout: 7 * time.Second}
	s.Client = custom
	c2 := s.client()
	if c2 == custom {
		t.Fatal("custom client must be copied, not mutated in place")
	}
	if c2.Timeout != 7*time.Second {
		t.Fatalf("custom client timeout = %v, want 7s", c2.Timeout)
	}
	if c2.CheckRedirect == nil {
		t.Fatal("custom client must still disable redirects")
	}
	if custom.CheckRedirect != nil {
		t.Fatal("caller's client must not be mutated")
	}
}

func TestS3RequestContextDeadlines(t *testing.T) {
	// A context that already has a deadline passes through unchanged.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, cancelOut := withDeadline(ctx, time.Hour)
	defer cancelOut()
	if out != ctx {
		t.Fatal("context with a deadline must pass through unchanged")
	}
	d, ok := out.Deadline()
	if !ok || time.Until(d) > time.Minute {
		t.Fatalf("deadline altered: ok=%v in=%v", ok, time.Until(d))
	}

	// A deadline-less context receives the requested bound.
	ctx2 := context.Background()
	out2, cancel2 := withDeadline(ctx2, 5*time.Second)
	defer cancel2()
	d2, ok := out2.Deadline()
	if !ok {
		t.Fatal("withDeadline added no deadline")
	}
	remaining := time.Until(d2)
	if remaining <= 0 || remaining > 5*time.Second {
		t.Fatalf("deadline in %v, want (0, 5s]", remaining)
	}
}

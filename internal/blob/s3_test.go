package blob

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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

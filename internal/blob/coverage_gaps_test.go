package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const covKey = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// TestS3MultipartTransportErrorUnwrap pins the typed transport wrapper's
// message and unwrap chain.
func TestS3MultipartTransportErrorUnwrap(t *testing.T) {
	te := &s3MultipartTransportError{err: io.ErrUnexpectedEOF}
	if got := te.Error(); got != io.ErrUnexpectedEOF.Error() {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(te, io.ErrUnexpectedEOF) {
		t.Fatal("Unwrap did not expose the transport cause")
	}
}

// TestS3BodyGuardStoppedBranches proves a stopped guard neither cancels when
// its timer callback runs late nor accepts later progress.
func TestS3BodyGuardStoppedBranches(t *testing.T) {
	var cancelled atomic.Bool
	g := newS3BodyGuard(func() { cancelled.Store(true) }, time.Hour)
	g.stop()
	g.onIdle()
	g.progress()
	if cancelled.Load() {
		t.Fatal("stopped guard cancelled the transfer")
	}
}

// TestS3PureHelpers covers the small derivations directly: part counting for
// zero/negative sizes, the retryable status table, and the multipart part-size
// buffer clamp.
func TestS3PureHelpers(t *testing.T) {
	if got := s3MultipartPartCount(0, 10); got != 0 {
		t.Fatalf("part count for zero size = %d, want 0", got)
	}
	if got := s3MultipartPartCount(-7, 10); got != 0 {
		t.Fatalf("part count for negative size = %d, want 0", got)
	}
	if got := s3MultipartPartCount(10, 10); got != 1 {
		t.Fatalf("part count 10/10 = %d, want 1", got)
	}
	if got := s3MultipartPartCount(11, 10); got != 2 {
		t.Fatalf("part count 11/10 = %d, want 2", got)
	}

	for _, tc := range []struct {
		code int
		want bool
	}{
		{http.StatusRequestTimeout, true},
		{http.StatusTooManyRequests, true},
		{500, true},
		{599, true},
		{http.StatusBadRequest, false},
		{http.StatusNotFound, false},
		{200, false},
	} {
		if got := s3RetryableStatus(tc.code); got != tc.want {
			t.Errorf("s3RetryableStatus(%d) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

// TestS3DirectGuardErrors covers the validation doors reachable without a
// network round trip: invalid keys on every keyed operation, negative sizes on
// putSingle, and objectURL resolution failures on the mutating and listing
// paths.
func TestS3DirectGuardErrors(t *testing.T) {
	ctx := context.Background()
	s, _, _ := s3TestServer(t)
	if _, err := s.Stat(ctx, "not-a-digest"); err == nil {
		t.Fatal("Stat accepted an invalid key")
	}
	if _, err := s.putSingle(ctx, "not-a-digest", bytes.NewReader(nil), 0); err == nil {
		t.Fatal("putSingle accepted an invalid key")
	}
	if _, err := s.putSingle(ctx, covKey, bytes.NewReader(nil), -1); err == nil {
		t.Fatal("putSingle accepted a negative size")
	}

	bad := &S3{Endpoint: "http://%zz", Bucket: "bucket", PathStyle: true, MultipartThreshold: 1, MultipartPartSize: 4, multipartTestParts: true}
	if _, err := bad.listURL(""); err == nil {
		t.Fatal("listURL accepted an unresolvable endpoint")
	}
	if _, err := bad.listPage(ctx, ""); err == nil {
		t.Fatal("listPage accepted an unresolvable endpoint")
	}
	if _, err := bad.putMultipart(ctx, covKey, strings.NewReader("0123456789"), 10); err == nil {
		t.Fatal("putMultipart accepted an unresolvable endpoint")
	}
}

// TestS3MultipartCreateFailureModes drives every create-response arm through
// the scriptable fake: transport drop, non-200 status, undecodable body, and
// a 200 response without an upload id.
func TestS3MultipartCreateFailureModes(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		reply *fakeS3Reply
		want  string
	}{
		{"transport", &fakeS3Reply{dropConn: true}, "multipart create"},
		{"status", &fakeS3Reply{status: http.StatusInternalServerError, body: "boom"}, "multipart create 500"},
		{"decode", &fakeS3Reply{status: http.StatusOK, body: "<not-xml"}, "multipart create decode"},
		{"no-upload-id", &fakeS3Reply{status: http.StatusOK, body: "<InitiateMultipartUploadResult/>"}, "no upload id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, f := multipartTestS3(t, 1, 4)
			f.failCreate = tc.reply
			_, err := s.Put(ctx, covKey, strings.NewReader("0123456789"), 10)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Put = %v, want %q", err, tc.want)
			}
			if n := countCalls(f.recordedCalls(), isCompleteCall); n != 0 {
				t.Fatalf("a failed create still completed the upload (%d calls)", n)
			}
		})
	}
}

// TestS3MultipartSmallerThanPartSize covers the buffer clamp (a single part
// smaller than the configured part size) and verifies the stored object.
func TestS3MultipartSmallerThanPartSize(t *testing.T) {
	s, f := multipartTestS3(t, 1, 100)
	data := []byte("small-multipart-body")
	if _, err := s.Put(context.Background(), covKey, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	stored, ok := f.storedObject(covKey)
	if !ok || !bytes.Equal(stored, data) {
		t.Fatalf("stored object = %q/%v", stored, ok)
	}
}

// TestS3PartUploadFailureArms covers the non-retryable part status (single
// attempt, no retry loop) and a source read error surfaced as a part-read
// failure.
func TestS3PartUploadFailureArms(t *testing.T) {
	ctx := context.Background()

	s, f := multipartTestS3(t, 1, 4)
	f.failPart = func(part, attempt int) *fakeS3Reply {
		return &fakeS3Reply{status: http.StatusBadRequest, body: "nope"}
	}
	_, err := s.Put(ctx, covKey, strings.NewReader("0123456789"), 10)
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("Put = %v, want the part status error", err)
	}
	if got := f.attempts[1]; got != 1 {
		t.Fatalf("non-retryable part attempted %d times, want 1", got)
	}
	if n := countCalls(f.recordedCalls(), isAbortCall); n != 1 {
		t.Fatalf("abort calls = %d, want 1 after a part failure", n)
	}

	s, f = multipartTestS3(t, 1, 4)
	_, err = s.Put(ctx, covKey, failingReader{err: errors.New("source exploded")}, 10)
	if err == nil || !strings.Contains(err.Error(), "read part 1") {
		t.Fatalf("Put = %v, want the part-read error", err)
	}
	if n := countCalls(f.recordedCalls(), isAbortCall); n != 1 {
		t.Fatalf("abort calls = %d, want 1 after a read failure", n)
	}
}

// TestS3AbortTransportError proves an abort that fails at the transport level
// is joined into the reported error without masking the primary failure.
func TestS3AbortTransportError(t *testing.T) {
	s, f := multipartTestS3(t, 1, 4)
	f.failPart = func(part, attempt int) *fakeS3Reply {
		return &fakeS3Reply{status: http.StatusBadRequest, body: "nope"}
	}
	f.failAbort = &fakeS3Reply{dropConn: true}
	_, err := s.Put(context.Background(), covKey, strings.NewReader("0123456789"), 10)
	if err == nil || !strings.Contains(err.Error(), "status 400") || !strings.Contains(err.Error(), "abort") {
		t.Fatalf("Put = %v, want the part failure joined with the abort failure", err)
	}
}

// TestS3PutSingleTransportAfterFullBody covers the transport-error arm where
// the source was already fully consumed: the put reports the transport cause
// without inventing a size mismatch.
func TestS3PutSingleTransportAfterFullBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		killFakeConnection(w)
	}))
	t.Cleanup(srv.Close)
	s := &S3{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true}
	data := []byte("full body delivered")
	_, err := s.Put(context.Background(), covKey, bytes.NewReader(data), int64(len(data)))
	if err == nil || strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("Put = %v, want the bare transport error", err)
	}
}

// TestS3CompleteResponseReadError covers a Complete whose 200 headers arrive
// but whose body dies mid-read: the failure is a transport-class error and no
// object is acknowledged unless a HEAD proves it exists.
func TestS3CompleteResponseReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.Method == http.MethodPost && q.Has("uploads"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && q.Get("uploadId") != "":
			w.Header().Set("ETag", `"etag-1"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && q.Get("uploadId") != "":
			w.Header().Set("Content-Length", "64")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "<CompleteMultipartUploadResult>")
			killFakeConnection(w)
		case r.Method == http.MethodDelete && q.Get("uploadId") != "":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	s := &S3{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true,
		MultipartThreshold: 1, MultipartPartSize: 4, multipartTestParts: true}
	_, err := s.Put(context.Background(), covKey, strings.NewReader("0123456789"), 10)
	if err == nil || !strings.Contains(err.Error(), "multipart complete") {
		t.Fatalf("Put = %v, want the complete transport error", err)
	}
}

// TestS3PartResponseArms covers a part PUT that fails at the transport level
// (retryable) and a 200 part response that carries no ETag.
func TestS3PartResponseArms(t *testing.T) {
	ctx := context.Background()

	s, f := multipartTestS3(t, 1, 4)
	f.failPart = func(part, attempt int) *fakeS3Reply {
		return &fakeS3Reply{dropConn: true}
	}
	_, err := s.Put(ctx, covKey, strings.NewReader("0123456789"), 10)
	if err == nil || !strings.Contains(err.Error(), "part 1") {
		t.Fatalf("Put = %v, want the dropped part transport error", err)
	}
	if got := f.attempts[1]; got != 2 {
		t.Fatalf("transport-failed part attempted %d times, want the one retry", got)
	}

	s, f = multipartTestS3(t, 1, 4)
	f.failPart = func(part, attempt int) *fakeS3Reply {
		return &fakeS3Reply{status: http.StatusOK}
	}
	_, err = s.Put(ctx, covKey, strings.NewReader("0123456789"), 10)
	if err == nil || !strings.Contains(err.Error(), "no ETag") {
		t.Fatalf("Put = %v, want the missing-ETag error", err)
	}
}

// TestS3PutSingleShortReadWithOKResponse covers the post-200 size check: a
// server that answers OK without consuming the declared body must never be
// acknowledged as a complete object.
func TestS3PutSingleShortReadWithOKResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s := &S3{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true}
	data := bytes.Repeat([]byte("x"), 1<<20)
	_, err := s.Put(context.Background(), covKey, bytes.NewReader(data), int64(len(data)))
	if err == nil {
		t.Fatal("a short-read OK response was acknowledged as a complete put")
	}
	if !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("Put = %v, want the size-mismatch error", err)
	}
}

// TestS3ListCoverageArms drives the list failure arms: response read error,
// over-limit key count, repeated continuation token, and the page cap.
func TestS3ListCoverageArms(t *testing.T) {
	ctx := context.Background()

	t.Run("page read error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "64")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "<ListBucketResult>")
			killFakeConnection(w)
		}))
		t.Cleanup(srv.Close)
		s := &S3{Endpoint: srv.URL, Bucket: "bucket", PathStyle: true}
		if err := s.List(ctx, func(Object) error { return nil }); err == nil {
			t.Fatal("List acknowledged a page whose body died mid-read")
		}
	})

	t.Run("too many keys", func(t *testing.T) {
		var body strings.Builder
		body.WriteString("<ListBucketResult>")
		for i := 0; i <= maxS3ListKeys; i++ {
			body.WriteString("<Contents></Contents>")
		}
		body.WriteString("</ListBucketResult>")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, body.String())
		}))
		t.Cleanup(srv.Close)
		s := &S3{Endpoint: srv.URL, Bucket: "bucket", PathStyle: true}
		err := s.List(ctx, func(Object) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "declares") {
			t.Fatalf("List = %v, want the over-limit key count error", err)
		}
	})

	t.Run("repeated token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>dup</NextContinuationToken></ListBucketResult>")
		}))
		t.Cleanup(srv.Close)
		s := &S3{Endpoint: srv.URL, Bucket: "bucket", PathStyle: true}
		err := s.List(ctx, func(Object) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "repeated a continuation token") {
			t.Fatalf("List = %v, want the repeated-token error", err)
		}
	})

	t.Run("page cap", func(t *testing.T) {
		var n atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t%d</NextContinuationToken></ListBucketResult>", n.Add(1))
		}))
		t.Cleanup(srv.Close)
		s := &S3{Endpoint: srv.URL, Bucket: "bucket", PathStyle: true}
		err := s.List(ctx, func(Object) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "exceeded") {
			t.Fatalf("List = %v, want the page-cap error", err)
		}
	})
}

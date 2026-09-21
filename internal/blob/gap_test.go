package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireNonRootBlob(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not apply to root")
	}
}

const gapKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

type fakeFileInfo struct{ size int64 }

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return 0o600 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// TestFSPutInputErrors proves invalid keys and negative sizes are rejected.
func TestFSPutInputErrors(t *testing.T) {
	s := NewFS(t.TempDir())
	if _, err := s.Put(context.Background(), "short", bytes.NewReader(nil), 0); err == nil {
		t.Fatal("invalid key must fail")
	}
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader(nil), -1); err == nil {
		t.Fatal("negative size must fail")
	}
}

// TestFSPutMkdirError proves a store root that cannot host the shard
// directory fails.
func TestFSPutMkdirError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFS(blocker)
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("store root under a file must fail")
	}
}

// TestFSPutExistingObjectStatErrors proves the existing-object fast path
// surfaces a metadata failure and reports the stored size otherwise.
func TestFSPutExistingObjectStatErrors(t *testing.T) {
	origStat, origRename := fsStat, fsRename
	defer func() { fsStat, fsRename = origStat, origRename }()

	// First stat succeeds, second stat (re-check) fails.
	calls := 0
	fsStat = func(string) (os.FileInfo, error) {
		calls++
		if calls == 1 {
			return fakeFileInfo{size: 7}, nil
		}
		return nil, errors.New("stat refused")
	}
	s := NewFS(t.TempDir())
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); err == nil || !strings.Contains(err.Error(), "stat refused") {
		t.Fatalf("second stat failure = %v, want stat error", err)
	}

	// Consistent stats report the stored object.
	calls = 0
	fsStat = func(string) (os.FileInfo, error) { return fakeFileInfo{size: 7}, nil }
	obj, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("ignored")), 1)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 7 || obj.Key != gapKey {
		t.Fatalf("existing object = %+v", obj)
	}
}

// TestFSPutRenameRaceBranches proves the rename-failure paths: a concurrent
// winner's object is accepted, and a genuine rename failure is reported.
func TestFSPutRenameRaceBranches(t *testing.T) {
	origStat, origRename := fsStat, fsRename
	defer func() { fsStat, fsRename = origStat, origRename }()

	// The key must match the content digest for Put to reach the rename.
	content := []byte("payload")
	sum := sha256.Sum256(content)
	key := hex.EncodeToString(sum[:])

	// Rename fails but the destination exists: the concurrent writer won.
	// The first stat probes the destination (absent), the second is the
	// rename-conflict check (present).
	calls := 0
	fsStat = func(name string) (os.FileInfo, error) {
		calls++
		if calls == 1 {
			return nil, os.ErrNotExist
		}
		return fakeFileInfo{size: int64(len(content))}, nil
	}
	fsRename = func(string, string) error { return errors.New("rename lost") }
	s := NewFS(t.TempDir())
	obj, err := s.Put(context.Background(), key, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("rename race with existing object: %v", err)
	}
	if obj.Size != int64(len(content)) {
		t.Fatalf("race object size = %d, want %d", obj.Size, len(content))
	}

	// Rename fails and the destination does not exist: report the error and
	// leave no temp file behind.
	fsStat = func(name string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	fsRename = func(string, string) error { return errors.New("rename refused") }
	s2 := NewFS(t.TempDir())
	if _, err := s2.Put(context.Background(), key, bytes.NewReader(content), int64(len(content))); err == nil || !strings.Contains(err.Error(), "rename refused") {
		t.Fatalf("rename failure = %v, want rename error", err)
	}
	entries, err := os.ReadDir(filepath.Join(s2.Root, "sha256", key[:2]))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("failed put left %q behind", e.Name())
	}
}

// TestFSPutCreateTempError proves an unwritable shard directory fails.
func TestFSPutCreateTempError(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootBlob(t)
	root := t.TempDir()
	shard := filepath.Join(root, "sha256", gapKey[:2])
	if err := os.MkdirAll(shard, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shard, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shard, 0o755) })
	if _, err := NewFS(root).Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("unwritable shard directory must fail")
	}
}

// TestFSPutCopyAndSizeErrors proves stream failures and declared-size
// mismatches are surfaced and leave no object behind.
func TestFSPutCopyAndSizeErrors(t *testing.T) {
	s := NewFS(t.TempDir())
	boom := errors.New("stream broke")
	if _, err := s.Put(context.Background(), gapKey, failingReader{err: boom}, 1); !errors.Is(err, boom) {
		t.Fatalf("copy failure = %v, want %v", err, boom)
	}
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("abc")), 4); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("size mismatch = %v, want size error", err)
	}
	// No object or temp file may remain after a failed put.
	dir := filepath.Join(s.Root, "sha256", gapKey[:2])
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("failed put left %q behind", e.Name())
	}
}

// TestFSFirstErr proves the error selector returns the first non-nil error.
func TestFSFirstErr(t *testing.T) {
	if err := firstErr(nil, nil, nil); err != nil {
		t.Fatalf("all nil = %v, want nil", err)
	}
	e1 := errors.New("first")
	e2 := errors.New("second")
	if err := firstErr(nil, e1, e2); err != e1 {
		t.Fatalf("firstErr = %v, want %v", err, e1)
	}
	if err := firstErr(e2, e1); err != e2 {
		t.Fatalf("firstErr = %v, want %v", err, e2)
	}
}

// TestFSOpenStatAndOpenErrors proves non-notfound stat errors and open
// errors are surfaced.
func TestFSOpenStatAndOpenErrors(t *testing.T) {
	testutil.UnixChmod(t)
	requireNonRootBlob(t)
	root := t.TempDir()
	// Unreadable shard directory: Stat fails with EACCES.
	shard := filepath.Join(root, "sha256", gapKey[:2])
	if err := os.MkdirAll(shard, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shard, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewFS(root).Open(context.Background(), gapKey); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("unreadable shard = %v, want permission error", err)
	}
	if err := os.Chmod(shard, 0o755); err != nil {
		t.Fatal(err)
	}

	// Unreadable object: Stat succeeds, Open fails.
	path := filepath.Join(shard, gapKey)
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, _, err := NewFS(root).Open(context.Background(), gapKey); err == nil {
		t.Fatal("unreadable object must fail Open")
	}
}

// TestFSDeleteErrorBranches proves invalid keys and failed removals surface.
func TestFSDeleteErrorBranches(t *testing.T) {
	s := NewFS(t.TempDir())
	if err := s.Delete(context.Background(), "short"); err == nil {
		t.Fatal("invalid key must fail")
	}
	// A non-empty directory at the object path makes Remove fail with a
	// non-not-exist error.
	dir := filepath.Join(s.Root, "sha256", gapKey[:2], gapKey)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background(), gapKey); err == nil {
		t.Fatal("non-empty directory removal must fail")
	}
}

// TestS3ClientRedirectPolicy proves the S3 client refuses redirects.
func TestS3ClientRedirectPolicy(t *testing.T) {
	s := &S3{Endpoint: "https://s3.example", Bucket: "b"}
	c := s.client()
	req, err := http.NewRequest(http.MethodGet, "https://s3.example/b/k", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}

// TestS3ObjectURLStyles proves both addressing styles build the expected URL:
// ports are preserved in both styles, a path-style endpoint keeps its gateway
// path prefix, trailing endpoint slashes never leak a double slash into the
// path, and a scheme-less endpoint is rejected (it is not an absolute URL).
func TestS3ObjectURLStyles(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:9000/", "http://localhost:9000//"} {
		path := &S3{Endpoint: endpoint, Bucket: "bucket", PathStyle: true}
		got, err := path.objectURL("/key")
		if err != nil {
			t.Fatalf("path-style URL for %q: %v", endpoint, err)
		}
		if got != "http://localhost:9000/bucket/key" {
			t.Fatalf("path-style URL for %q = %q", endpoint, got)
		}
	}
	// Ports and a gateway path prefix survive path-style addressing.
	prefix := &S3{Endpoint: "https://gw.example:9443/s3/", Bucket: "bucket", PathStyle: true}
	if got, err := prefix.objectURL("key"); err != nil || got != "https://gw.example:9443/s3/bucket/key" {
		t.Fatalf("path-style prefixed URL = %q, err=%v", got, err)
	}
	// Virtual-hosted style puts the bucket before the endpoint host, keeps
	// the port, and ignores trailing slashes.
	for _, tc := range []struct{ endpoint, want string }{
		{"https://s3.example.com/", "https://bucket.s3.example.com/key"},
		{"https://s3.example.com//", "https://bucket.s3.example.com/key"},
		{"https://s3.example.com:8443", "https://bucket.s3.example.com:8443/key"},
	} {
		virtual := &S3{Endpoint: tc.endpoint, Bucket: "bucket"}
		got, err := virtual.objectURL("key")
		if err != nil {
			t.Fatalf("virtual-hosted URL for %q: %v", tc.endpoint, err)
		}
		if got != tc.want {
			t.Fatalf("virtual-hosted URL for %q = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
	bare := &S3{Endpoint: "s3.example.com", Bucket: "bucket"}
	if _, err := bare.objectURL("key"); err == nil {
		t.Fatal("scheme-less endpoint accepted")
	}
}

// TestS3ValidateS3Config pins the endpoint/bucket coherence rules shared by
// config validation (blob.ValidateS3Config) and the transport: invalid
// endpoints, unusable bucket names, IP endpoints in virtual-hosted style and
// path prefixes in virtual-hosted style are refused (pointing the operator at
// s3_path_style), while the path-style variants are accepted.
func TestS3ValidateS3Config(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		bucket   string
		path     bool
		wantErr  bool
		wantHint bool
	}{
		{"https dns virtual", "https://s3.example.com", "bucket", false, false, false},
		{"http dns path", "http://localhost:9000", "bucket", true, false, false},
		{"ip path-style", "http://127.0.0.1:9000", "bucket", true, false, false},
		{"ip virtual rejected", "http://127.0.0.1:9000", "bucket", false, true, true},
		{"ipv6 path-style", "http://[::1]:9000", "bucket", true, false, false},
		{"ipv6 virtual rejected", "http://[::1]:9000", "bucket", false, true, true},
		{"path prefix path-style", "https://gw.example/s3", "bucket", true, false, false},
		{"path prefix virtual rejected", "https://gw.example/s3", "bucket", false, true, true},
		{"dotted bucket virtual", "https://s3.example.com", "my.bucket", false, false, false},
		{"dotted bucket path-style", "https://s3.example.com", "my.bucket", true, false, false},
		{"double-dot virtual rejected", "https://s3.example.com", "my..bucket", false, true, false},
		{"double-dot path rejected", "https://s3.example.com", "my..bucket", true, true, false},
		{"empty bucket rejected", "https://s3.example.com", "", false, true, false},
		{"slash bucket rejected", "https://s3.example.com", "a/b", true, true, false},
		{"space bucket rejected", "https://s3.example.com", "a b", true, true, false},
		{"leading-dash label virtual rejected", "https://s3.example.com", "b-.x", false, true, true},
		{"empty label virtual rejected", "https://s3.example.com", "b..x", false, true, false},
		{"missing scheme", "s3.example.com", "bucket", true, true, false},
		{"empty endpoint", "", "bucket", true, true, false},
		{"non-http scheme", "ftp://s3.example.com", "bucket", true, true, false},
		{"https without host", "https://", "bucket", true, true, false},
		{"userinfo", "https://u:p@s3.example.com", "bucket", true, true, false},
		{"query", "https://s3.example.com?x=1", "bucket", true, true, false},
		{"fragment", "https://s3.example.com#f", "bucket", true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateS3Config(tc.endpoint, tc.bucket, tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateS3Config(%q, %q, path=%v) = %v, wantErr=%v", tc.endpoint, tc.bucket, tc.path, err, tc.wantErr)
			}
			if err != nil && tc.wantHint && !strings.Contains(err.Error(), "s3_path_style") {
				t.Fatalf("error %q does not point at s3_path_style", err)
			}
		})
	}
}

// TestS3ValidateAndParseOnce proves the store's own Validate reports the same
// coherence error objectURL reports and that the endpoint is resolved exactly
// once per store instance: a later Endpoint mutation cannot silently redirect
// an already-validated store.
func TestS3ValidateAndParseOnce(t *testing.T) {
	bad := &S3{Endpoint: "http://127.0.0.1:9000", Bucket: "bucket"}
	err := bad.Validate()
	if err == nil || !strings.Contains(err.Error(), "s3_path_style") {
		t.Fatalf("virtual-hosted IP endpoint Validate = %v", err)
	}
	if _, uerr := bad.objectURL("key"); uerr == nil {
		t.Fatal("objectURL accepted the same unusable combination")
	}

	s := &S3{Endpoint: "https://s3.example.com", Bucket: "bucket"}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Endpoint = "http://[::1"
	if got, err := s.objectURL("key"); err != nil || got != "https://bucket.s3.example.com/key" {
		t.Fatalf("cached endpoint URL = %q, err=%v", got, err)
	}
}

// TestS3SignWithTokenAndDefaults proves the session token header and the
// default region are applied.
func TestS3SignWithTokenAndDefaults(t *testing.T) {
	s := &S3{Bucket: "bucket", AccessKeyID: "ak", SecretAccessKey: "sk", Token: "session"}
	req, err := http.NewRequest(http.MethodGet, "https://bucket.s3.example/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.sign(req, emptyPayloadHash, time.Unix(0, 0).UTC())
	if req.Header.Get("x-amz-security-token") != "session" {
		t.Fatal("session token header missing")
	}
	if req.Header.Get("x-amz-date") != "19700101T000000Z" {
		t.Fatalf("x-amz-date = %q", req.Header.Get("x-amz-date"))
	}
	if !strings.Contains(req.Header.Get("Authorization"), "/us-east-1/s3/aws4_request") {
		t.Fatalf("default region missing from scope: %q", req.Header.Get("Authorization"))
	}
}

// TestS3CanonicalRequestQueryAndEmptyPath proves canonicalization handles a
// query string and an empty path.
func TestS3CanonicalRequestQueryAndEmptyPath(t *testing.T) {
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "s3.example", RawQuery: "b=2&a=1"},
		Header: http.Header{},
	}
	canonical, signed := canonicalRequest(req, emptyPayloadHash)
	if !strings.Contains(canonical, "a=1&b=2") {
		t.Fatalf("canonical query not sorted: %q", canonical)
	}
	if !strings.HasPrefix(canonical, "GET\n/\n") {
		t.Fatalf("empty path must canonicalize to /: %q", canonical)
	}
	if signed != "host" {
		t.Fatalf("signed headers = %q", signed)
	}
}

// TestS3PutInputErrors proves negative sizes and unparsable endpoints are
// rejected before any network use.
func TestS3PutInputErrors(t *testing.T) {
	s := s3WithTripper(nil)
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader(nil), -1); err == nil {
		t.Fatal("negative size must fail")
	}
	bad := s3WithTripper(nil)
	bad.Endpoint = "http://[::1"
	bad.PathStyle = true
	if _, err := bad.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("invalid endpoint must fail request construction")
	}
}

// TestS3PutTempDirFailure proves temp-file creation failures surface.
func TestS3PutTempDirFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missing)
	s := s3WithTripper(nil)
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("unusable TMPDIR must fail")
	}
}

// TestS3PutReaderAndSeekErrors proves reader, seek, and re-read failures are
// surfaced.
func TestS3PutReaderAndSeekErrors(t *testing.T) {
	s := s3WithTripper(nil)
	boom := errors.New("reader broke")
	if _, err := s.Put(context.Background(), gapKey, failingReader{err: boom}, 1); !errors.Is(err, boom) {
		t.Fatalf("reader failure = %v, want %v", err, boom)
	}

	origSeek := seekTemp
	seekTemp = func(*os.File, int64, int) (int64, error) { return 0, errors.New("seek refused") }
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("seek failure must surface")
	}
	seekTemp = origSeek

	origOpen := openTempForRead
	openTempForRead = func(string) (io.ReadCloser, error) { return nil, errors.New("reopen refused") }
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("reopen failure must surface")
	}
	openTempForRead = func(string) (io.ReadCloser, error) {
		return io.NopCloser(failingReader{err: errors.New("reread refused")}), nil
	}
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("re-read failure must surface")
	}
	openTempForRead = origOpen
}

// TestS3PutTransportAndStatusErrors proves transport failures and non-2xx
// responses are surfaced with the server body.
func TestS3PutTransportAndStatusErrors(t *testing.T) {
	boom := errors.New("connection refused")
	s := s3WithTripper(&recordingTripper{err: boom})
	if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v, want %v", err, boom)
	}

	for _, status := range []int{http.StatusInternalServerError, http.StatusForbidden} {
		s := s3WithTripper(&recordingTripper{resp: &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader("server says no")),
		}})
		_, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("x")), 1)
		if err == nil || !strings.Contains(err.Error(), "server says no") {
			t.Fatalf("status %d error = %v, want body", status, err)
		}
	}
}

// TestS3OpenRequestError proves an unparsable endpoint fails Open before any
// network use.
func TestS3OpenRequestError(t *testing.T) {
	s := &S3{Endpoint: "http://[::1", Bucket: "b", PathStyle: true}
	if _, _, err := s.Open(context.Background(), gapKey); err == nil {
		t.Fatal("invalid endpoint must fail")
	}
}

// TestS3DeleteMatrix proves Delete accepts 200/204/404 and surfaces
// construction, transport, and status failures.
func TestS3DeleteMatrix(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusOK, http.StatusNotFound} {
		s := s3WithTripper(&recordingTripper{resp: &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader("")),
		}})
		if err := s.Delete(context.Background(), gapKey); err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
	}

	s := s3WithTripper(&recordingTripper{resp: &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(strings.NewReader("delete refused")),
	}})
	if err := s.Delete(context.Background(), gapKey); err == nil || !strings.Contains(err.Error(), "delete refused") {
		t.Fatalf("status error = %v, want body", err)
	}

	boom := errors.New("connection refused")
	s = s3WithTripper(&recordingTripper{err: boom})
	if err := s.Delete(context.Background(), gapKey); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v, want %v", err, boom)
	}

	bad := &S3{Endpoint: "http://[::1", Bucket: "b", PathStyle: true}
	if err := bad.Delete(context.Background(), gapKey); err == nil {
		t.Fatal("invalid endpoint must fail")
	}
}

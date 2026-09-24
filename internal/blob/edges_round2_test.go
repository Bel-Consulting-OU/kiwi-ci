package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// TestFSStatBranches covers the stat-only read path: invalid key, missing
// object, a shard path component that is not a directory, and the success
// arm.
func TestFSStatBranches(t *testing.T) {
	s := NewFS(t.TempDir())
	ctx := context.Background()
	if _, err := s.Stat(ctx, "short"); err == nil {
		t.Fatal("invalid key accepted")
	}
	if _, err := s.Stat(ctx, gapKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object = %v, want ErrNotFound", err)
	}
	payload := []byte("payload")
	sum := sha256.Sum256(payload)
	liveKey := hex.EncodeToString(sum[:])
	if _, err := s.Put(ctx, liveKey, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	obj, err := s.Stat(ctx, liveKey)
	if err != nil || obj.Size != int64(len(payload)) || obj.Key != liveKey {
		t.Fatalf("stat = %+v, %v", obj, err)
	}

	// A shard entry that is a FILE makes Stat fail with a non-ENOENT error.
	blocked := NewFS(t.TempDir())
	shard := filepath.Join(blocked.Root, "sha256", gapKey[:2])
	if err := os.MkdirAll(filepath.Dir(shard), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shard, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.Stat(ctx, gapKey); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("shard-is-file stat = %v, want a non-NotFound error", err)
	}
}

// TestFSListBranches covers the walk's skip and error arms: a non-directory
// at the sha256 level, a non-directory shard entry, an unreadable shard and a
// nested directory inside a shard.
func TestFSListBranches(t *testing.T) {
	ctx := context.Background()

	// sha256 is a file: List surfaces the read error.
	fileRoot := NewFS(t.TempDir())
	if err := os.MkdirAll(filepath.Join(fileRoot.Root, "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(fileRoot.Root, "sha256")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileRoot.Root, "sha256"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fileRoot.List(ctx, func(Object) error { return nil }); err == nil {
		t.Fatal("List over a file sha256 level succeeded")
	}

	// A non-directory shard entry and a nested directory are skipped.
	mixed := NewFS(t.TempDir())
	sha := filepath.Join(mixed.Root, "sha256")
	if err := os.MkdirAll(sha, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sha, "strayfile"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	shardDir := filepath.Join(sha, gapKey[:2])
	if err := os.MkdirAll(filepath.Join(shardDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := mixed.List(ctx, func(Object) error { seen++; return nil }); err != nil {
		t.Fatalf("mixed List: %v", err)
	}
	if seen != 0 {
		t.Fatalf("mixed List reported %d objects, want 0", seen)
	}

	// An unreadable shard surfaces the read error.
	unreadable := NewFS(t.TempDir())
	shard := filepath.Join(unreadable.Root, "sha256", gapKey[:2])
	if err := os.MkdirAll(shard, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shard, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shard, 0o700) })
	if err := unreadable.List(ctx, func(Object) error { return nil }); err == nil {
		t.Fatal("List over an unreadable shard succeeded")
	}
}

// TestFSPutShardSyncFailures covers the shard-parent and shard directory fsync
// failures: neither may acknowledge the put.
func TestFSPutShardSyncFailures(t *testing.T) {
	for _, failSuffix := range []string{"/sha256", "/sha256/" + gapKey[:2]} {
		t.Run(failSuffix, func(t *testing.T) {
			s := NewFS(t.TempDir())
			restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(dir string) error {
				if strings.HasSuffix(dir, failSuffix) {
					return errors.New("injected shard fsync failure")
				}
				return fsutil.RealSyncDir(dir)
			}})
			defer restore()
			if _, err := s.Put(context.Background(), gapKey, bytes.NewReader([]byte("payload")), 7); err == nil {
				t.Fatalf("put with a failing %s fsync was acknowledged", failSuffix)
			}
		})
	}
}

// s3HeadServer returns a store pointing at a server whose HEAD behavior is
// scripted, plus the server.
func s3HeadServer(t *testing.T, head func(http.ResponseWriter, *http.Request)) (*S3, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && head != nil {
			head(w, r)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	t.Cleanup(srv.Close)
	return &S3{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true}, srv
}

// TestS3StatMatrix covers HeadObject: not-found, error status, and the
// Last-Modified/size success arm.
func TestS3StatMatrix(t *testing.T) {
	ctx := context.Background()
	key := strings.Repeat("a", 64)

	notFound, _ := s3HeadServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if _, err := notFound.Stat(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 stat = %v, want ErrNotFound", err)
	}

	serverErr, _ := s3HeadServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})
	if _, err := serverErr.Stat(ctx, key); err == nil {
		t.Fatal("500 stat succeeded")
	}

	ok, _ := s3HeadServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "42")
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	})
	obj, err := ok.Stat(ctx, key)
	if err != nil || obj.Size != 42 || obj.ModTime.IsZero() {
		t.Fatalf("stat = %+v, %v; want size 42 with a Last-Modified", obj, err)
	}

	// A malformed endpoint fails before any request.
	bad := &S3{Endpoint: "http://", Bucket: "bucket", PathStyle: true}
	if _, err := bad.Stat(ctx, key); err == nil {
		t.Fatal("stat through a malformed endpoint succeeded")
	}

	// A closed server fails the request.
	closed, srv := s3HeadServer(t, nil)
	srv.Close()
	if _, err := closed.Stat(ctx, key); err == nil {
		t.Fatal("stat against a closed server succeeded")
	}
}

// TestS3PutStatusAndOverlong covers the non-2xx put status arm and the
// declared-size violation when the source is longer than size.
func TestS3PutStatusAndOverlong(t *testing.T) {
	ctx := context.Background()
	key := strings.Repeat("b", 64)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	s := &S3{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true}
	if _, err := s.Put(ctx, key, bytes.NewReader([]byte("abcd")), 4); err == nil {
		t.Fatal("put with a 500 status succeeded")
	}

	over, _, _ := s3TestServer(t)
	if _, err := over.Put(ctx, key, bytes.NewReader([]byte("abcde")), 4); err == nil {
		t.Fatal("put of an over-long source succeeded")
	}
}

// TestS3DeleteErrorArms covers the invalid-key and error-status arms.
func TestS3DeleteErrorArms(t *testing.T) {
	ctx := context.Background()
	s := &S3{Endpoint: "http://127.0.0.1:1", Bucket: "bucket", PathStyle: true}
	if err := s.Delete(ctx, "not-a-digest"); err == nil {
		t.Fatal("delete with an invalid key succeeded")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	bad := &S3{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true}
	if err := bad.Delete(ctx, strings.Repeat("c", 64)); err == nil {
		t.Fatal("delete with a 500 status succeeded")
	}
}

// TestValidateS3BucketDNSLabels covers the virtual-hosted label rule.
func TestValidateS3BucketDNSLabels(t *testing.T) {
	if err := validateS3Bucket("foo_bar", false); err == nil {
		t.Fatal("underscore label accepted for virtual-hosted addressing")
	}
	if err := validateS3Bucket("foo_bar", true); err != nil {
		t.Fatalf("path-style underscore bucket rejected: %v", err)
	}
	if err := validateS3Bucket("bad..bucket", true); err == nil {
		t.Fatal("double-dot bucket accepted")
	}
	if err := validateS3Bucket("", true); err == nil {
		t.Fatal("empty bucket accepted")
	}
}

// TestS3ListErrorArms covers the list status, decode and non-digest skip arms.
func TestS3ListErrorArms(t *testing.T) {
	ctx := context.Background()
	sink := func(Object) error { return nil }

	status, _, _ := s3TestServer(t)
	statusErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer statusErr.Close()
	status.Endpoint = statusErr.URL
	if err := status.List(ctx, sink); err == nil {
		t.Fatal("list with a 500 status succeeded")
	}

	decode, _, _ := s3TestServer(t)
	decodeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<not-valid-xml"))
	}))
	defer decodeSrv.Close()
	decode.Endpoint = decodeSrv.URL
	if err := decode.List(ctx, sink); err == nil {
		t.Fatal("list with undecodable XML succeeded")
	}

	filter, _, _ := s3TestServer(t)
	body := `<?xml version="1.0"?><ListBucketResult><IsTruncated>false</IsTruncated>` +
		`<Contents><Key>not-a-digest</Key><Size>1</Size></Contents>` +
		`<Contents><Key>` + strings.Repeat("d", 64) + `</Key><Size>3</Size></Contents></ListBucketResult>`
	filterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer filterSrv.Close()
	filter.Endpoint = filterSrv.URL
	count := 0
	if err := filter.List(ctx, func(Object) error { count++; return nil }); err != nil {
		t.Fatalf("filter list: %v", err)
	}
	if count != 1 {
		t.Fatalf("filter list reported %d objects, want only the digest key", count)
	}

	closed, _, _ := s3TestServer(t)
	closedSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed.Endpoint = closedSrv.URL
	closedSrv.Close()
	if err := closed.List(ctx, sink); err == nil {
		t.Fatal("list against a closed server succeeded")
	}
}

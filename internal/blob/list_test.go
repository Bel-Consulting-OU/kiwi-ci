package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func digestOf(b byte) string {
	return strings.Repeat(fmt.Sprintf("%02x", b), 32)
}

// putBlob stores payload and returns its real content digest.
func putBlob(t *testing.T, s *FS, payload string) Object {
	t.Helper()
	sum := sha256.Sum256([]byte(payload))
	obj, err := s.Put(context.Background(), hex.EncodeToString(sum[:]), strings.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

// TestFSListReportsObjectsSkipsStaging covers the FS enumeration contract:
// every committed digest is reported with size and mtime, staging files and
// non-digest names are never surfaced, and the sink's error aborts the walk.
func TestFSListReportsObjectsSkipsStaging(t *testing.T) {
	root := t.TempDir()
	s := NewFS(root)
	want := map[string]int64{}
	var first Object
	for _, payload := range []string{"alpha", "beta", "gamma"} {
		obj := putBlob(t, s, payload)
		want[obj.Key] = obj.Size
		if first.Key == "" {
			first = obj
		}
	}
	// Staging scratch files and non-digest names must be invisible: the GC
	// may never mistake them for payloads.
	staging := filepath.Join(root, "sha256", first.Key[:2])
	if err := os.WriteFile(filepath.Join(staging, ".01.tmp-deadbeef"), []byte("scratch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "not-a-digest"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := map[string]Object{}
	err := s.List(context.Background(), func(o Object) error {
		got[o.Key] = o
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("listed %d objects, want %d: %+v", len(got), len(want), got)
	}
	for key, size := range want {
		o, ok := got[key]
		if !ok {
			t.Fatalf("object %s missing from listing", key)
		}
		if o.SHA256 != key || o.Size != size {
			t.Fatalf("object %s = %+v, want size %d", key, o, size)
		}
		if o.ModTime.IsZero() {
			t.Fatalf("object %s has zero mtime", key)
		}
	}

	// A sink error stops the walk and is returned unchanged.
	sentinel := errors.New("stop")
	calls := 0
	if err := s.List(context.Background(), func(Object) error {
		calls++
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("sink error = %v, want sentinel", err)
	}
	if calls != 1 {
		t.Fatalf("sink called %d times after error, want 1", calls)
	}

	// A cancelled context stops before reporting anything.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.List(ctx, func(Object) error {
		t.Fatal("sink called for a cancelled context")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled List = %v, want context.Canceled", err)
	}
}

// TestFSListMissingRootIsEmpty keeps first-run GC passes quiet: a store that
// never wrote an object must enumerate to nothing instead of failing.
func TestFSListMissingRootIsEmpty(t *testing.T) {
	s := NewFS(filepath.Join(t.TempDir(), "does-not-exist"))
	if err := s.List(context.Background(), func(Object) error {
		t.Fatal("sink called for an empty store")
		return nil
	}); err != nil {
		t.Fatalf("List on missing root = %v", err)
	}
}

// TestFSRePutRefreshesModTime pins the dedupe age-refresh contract: a
// re-put of an existing digest moves the object's mtime forward so a GC
// age floor sees the most recent reference event.
func TestFSRePutRefreshesModTime(t *testing.T) {
	root := t.TempDir()
	s := NewFS(root)
	obj := putBlob(t, s, "payload")
	key := obj.Key
	old := time.Now().Add(-48 * time.Hour)
	path := filepath.Join(root, "sha256", key[:2], key)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(context.Background(), key, strings.NewReader("payload"), int64(len("payload"))); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("dedupe re-put left mtime at %v", fi.ModTime())
	}
}

// s3PaginatedServer serves a two-page ListObjectsV2 listing: page one is
// truncated with a continuation token, page two is complete. It records the
// max-keys and continuation-token values it was asked for.
func s3PaginatedServer(t *testing.T, firstPage, secondPage []string) (*S3, *httptest.Server, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("list-type") != "2" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		calls = append(calls, q.Get("continuation-token"))
		w.Header().Set("Content-Type", "application/xml")
		if q.Get("continuation-token") == "" {
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>page-2</NextContinuationToken>%s</ListBucketResult>`, xmlContents(firstPage))
			return
		}
		if q.Get("continuation-token") != "page-2" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated>%s</ListBucketResult>`, xmlContents(secondPage))
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
	return s, srv, &calls
}

func xmlContents(keys []string) string {
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, `<Contents><Key>%s</Key><Size>%d</Size><LastModified>2024-01-02T03:04:05.000Z</LastModified></Contents>`, k, len(k))
	}
	return b.String()
}

// TestS3ListPaginatesAndFilters covers the S3 enumeration contract: both
// ListObjectsV2 pages are followed, the bounded page size is requested,
// digest keys are reported with size+mtime, and bookkeeping keys are
// filtered out.
func TestS3ListPaginatesAndFilters(t *testing.T) {
	first := digestOf(0x11)
	second := digestOf(0x22)
	third := digestOf(0x33)
	s, _, calls := s3PaginatedServer(t,
		[]string{first, "some/other/object", "sha256/" + second[:2] + "/" + second},
		[]string{third, "sha256/not-a-bucket-object"})

	var got []Object
	if err := s.List(context.Background(), func(o Object) error {
		got = append(got, o)
		return nil
	}); err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })
	want := map[string]int64{first: 64, second: 74, third: 64}
	if len(got) != len(want) {
		t.Fatalf("listed %d objects, want %d: %+v", len(got), len(want), got)
	}
	for _, o := range got {
		size, ok := want[o.Key]
		if !ok || o.SHA256 != o.Key {
			t.Fatalf("unexpected object %+v", o)
		}
		if o.Size != size {
			t.Fatalf("object %s size = %d, want %d", o.Key, o.Size, size)
		}
		if o.ModTime.IsZero() {
			t.Fatalf("object %s has zero mtime", o.Key)
		}
	}
	if len(*calls) != 2 || (*calls)[0] != "" || (*calls)[1] != "page-2" {
		t.Fatalf("continuation calls = %v", *calls)
	}
}

// TestS3ListMaxKeysAndSinkError pins the bounded page size and the callback
// error contract.
func TestS3ListMaxKeysAndSinkError(t *testing.T) {
	key := digestOf(0x44)
	var sawMaxKeys string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMaxKeys = r.URL.Query().Get("max-keys")
		fmt.Fprintf(w, `<?xml version="1.0"?><ListBucketResult><IsTruncated>false</IsTruncated>%s</ListBucketResult>`, xmlContents([]string{key}))
	}))
	t.Cleanup(srv.Close)
	s := &S3{Endpoint: srv.URL, Region: "us-east-1", Bucket: "b", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true}
	sentinel := errors.New("stop")
	if err := s.List(context.Background(), func(Object) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("sink error = %v", err)
	}
	if sawMaxKeys != "1000" {
		t.Fatalf("max-keys = %q, want 1000", sawMaxKeys)
	}
}

// TestS3ListTruncatedWithoutTokenFails closes the silent-truncation hole: an
// endpoint that reports truncation without a token can never make the GC
// treat an incomplete listing as complete.
func TestS3ListTruncatedWithoutTokenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>`)
	}))
	t.Cleanup(srv.Close)
	s := &S3{Endpoint: srv.URL, Region: "us-east-1", Bucket: "b", AccessKeyID: "k", SecretAccessKey: "s", PathStyle: true}
	if err := s.List(context.Background(), func(Object) error {
		t.Fatal("no objects expected")
		return nil
	}); err == nil || !strings.Contains(err.Error(), "continuation token") {
		t.Fatalf("truncated-without-token error = %v", err)
	}
}

// TestSigV4CanonicalQueryEncoding pins the AWS URI encoding used for signed
// query strings: spaces are %20 (never "+") and reserved characters are
// percent-encoded.
func TestSigV4CanonicalQueryEncoding(t *testing.T) {
	if got := awsURIEncode("a b/c=d&e", true); got != "a%20b%2Fc%3Dd%26e" {
		t.Fatalf("awsURIEncode = %q", got)
	}
	if got := awsURIEncode("a b/c", false); got != "a%20b/c" {
		t.Fatalf("awsURIEncode(no slash) = %q", got)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/b?continuation-token=a+b%2Fc&list-type=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := canonicalRequest(req, emptyPayloadHash)
	if !strings.Contains(canonical, "continuation-token=a%20b%2Fc&list-type=2") {
		t.Fatalf("canonical query encoding wrong:\n%s", canonical)
	}
}

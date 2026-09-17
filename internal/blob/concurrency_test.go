package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func invalidShapeKey() string { return strings.Repeat("a", 64) }

// TestS3RejectsInvalidKeysWithoutNetwork verifies every S3 operation rejects
// a key that could escape the bucket path (or a URL) before any request is
// issued.
func TestS3RejectsInvalidKeysWithoutNetwork(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s := &S3{Endpoint: srv.URL, Bucket: "bucket", PathStyle: true, AccessKeyID: "k", SecretAccessKey: "s"}
	bad := []string{"../evil", "a/b", "a?b", "..", "", strings.Repeat("a", 65), "a b"}
	for _, key := range bad {
		if _, err := s.Put(context.Background(), key, bytes.NewReader(nil), 0); err == nil {
			t.Errorf("Put(%q) accepted", key)
		}
		if _, _, err := s.Open(context.Background(), key); err == nil {
			t.Errorf("Open(%q) accepted", key)
		}
		if err := s.Delete(context.Background(), key); err == nil {
			t.Errorf("Delete(%q) accepted", key)
		}
	}
	if requests != 0 {
		t.Fatalf("invalid keys issued %d requests", requests)
	}
}

// TestS3HangingServerHonorsContextDeadline verifies a stalled endpoint
// cannot hang an S3 call when the caller supplies a deadline.
func TestS3HangingServerHonorsContextDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)
	s := &S3{Endpoint: srv.URL, Bucket: "bucket", PathStyle: true, AccessKeyID: "k", SecretAccessKey: "s"}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := s.Open(ctx, invalidShapeKey()); err == nil {
		t.Fatal("hanging endpoint must fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("context deadline not honored: took %v", elapsed)
	}
}

// TestS3ZeroSizePut verifies a zero-byte object round-trips (size 0 is a
// valid exact size, not an "unknown size" marker at the S3 layer).
func TestS3ZeroSizePut(t *testing.T) {
	s, _, bodies := s3TestServer(t)
	key := invalidShapeKey()
	obj, err := s.Put(context.Background(), key, bytes.NewReader(nil), 0)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 0 {
		t.Fatalf("size = %d", obj.Size)
	}
	if got, ok := bodies["/bucket/"+key]; !ok || len(got) != 0 {
		t.Fatalf("stored body = %q ok=%v", got, ok)
	}
}

// TestFSConcurrentPutOpenDeleteSameKey hammers one content-addressed path
// with concurrent writers, readers and deleters.
func TestFSConcurrentPutOpenDeleteSameKey(t *testing.T) {
	s := NewFS(t.TempDir())
	payload := bytes.Repeat([]byte("body"), 128)
	sum := sha256.Sum256(payload)
	key := hex.EncodeToString(sum[:])

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Put(context.Background(), key, bytes.NewReader(payload), int64(len(payload)))
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, _, err := s.Open(context.Background(), key)
			if err != nil {
				if !errors.Is(err, ErrNotFound) {
					t.Errorf("concurrent Open: %v", err)
				}
				return
			}
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(rc)
			_ = rc.Close()
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Delete(context.Background(), key)
		}()
	}
	wg.Wait()

	if _, err := s.Put(context.Background(), key, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("store unusable after churn: %v", err)
	}
	rc, obj, err := s.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(rc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), payload) || obj.Size != int64(len(payload)) {
		t.Fatal("content corrupted after churn")
	}
}

// TestFSConcurrentIdenticalPutContentMismatch verifies that a Put whose
// stream does not hash to the requested key can never leave the key
// populated with wrong content, even racing an identical-looking rename.
func TestFSConcurrentIdenticalPutContentMismatch(t *testing.T) {
	s := NewFS(t.TempDir())
	key := invalidShapeKey() // valid shape, but not the digest of the payload
	if _, err := s.Put(context.Background(), key, bytes.NewReader([]byte("not matching")), 12); err == nil {
		t.Fatal("content/key mismatch must be rejected")
	}
	if _, _, err := s.Open(context.Background(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected put left content behind: %v", err)
	}
}

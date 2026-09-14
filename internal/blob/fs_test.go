package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func testKey(t *testing.T, data []byte) string {
	t.Helper()
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestFSRoundTrip(t *testing.T) {
	s := NewFS(t.TempDir())
	data := []byte("kiwi artifact payload")
	key := testKey(t, data)
	obj, err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if obj.SHA256 != key || obj.Size != int64(len(data)) {
		t.Fatalf("unexpected object %+v", obj)
	}
	rc, got, err := s.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, data) {
		t.Fatal("content mismatch")
	}
	if got.Size != int64(len(data)) {
		t.Fatal("size mismatch")
	}
	// Close the reader before Delete: Windows cannot remove an open file,
	// and the blob.FS contract does not promise delete-while-open.
	if err := s.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(context.Background(), key); err != ErrNotFound {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestFSPutDigestMismatch(t *testing.T) {
	s := NewFS(t.TempDir())
	data := []byte("payload")
	other := testKey(t, []byte("different"))
	if _, err := s.Put(context.Background(), other, bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("expected digest mismatch rejection")
	}
}

func TestFSConcurrentIdenticalPuts(t *testing.T) {
	s := NewFS(t.TempDir())
	data := []byte("same content")
	key := testKey(t, data)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)))
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rc, obj, err := s.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if obj.Size != int64(len(data)) {
		t.Fatal("size mismatch")
	}
}

func TestFSRejectsInvalidKey(t *testing.T) {
	s := NewFS(t.TempDir())
	if _, err := s.Put(context.Background(), "../../etc", bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected invalid key rejection")
	}
	if _, _, err := s.Open(context.Background(), "abc"); err == nil {
		t.Fatal("expected invalid key rejection")
	}
}

// TestSigV4AWSExampleVector checks canonicalization and signing against the
// published AWS S3 documentation example:
// GET /test.txt?X-Amz-Algorithm... simplified to the documented header-signed
// vector with fixed credentials and timestamp.
func TestSigV4AWSExampleVector(t *testing.T) {
	req, err := httpNewGet("https://examplebucket.s3.amazonaws.com/test.txt")
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-9")
	req.Header.Set("x-amz-date", "20130524T000000Z")
	req.Header.Set("x-amz-content-sha256", emptyPayloadHash)

	canonical, signedHeaders := canonicalRequest(req, emptyPayloadHash)
	wantCanonical := "GET\n/test.txt\n\n" +
		"host:examplebucket.s3.amazonaws.com\n" +
		"range:bytes=0-9\n" +
		"x-amz-content-sha256:" + emptyPayloadHash + "\n" +
		"x-amz-date:20130524T000000Z\n\n" +
		"host;range;x-amz-content-sha256;x-amz-date\n" + emptyPayloadHash
	if canonical != wantCanonical {
		t.Fatalf("canonical request mismatch:\n got: %q\nwant: %q", canonical, wantCanonical)
	}
	if signedHeaders != "host;range;x-amz-content-sha256;x-amz-date" {
		t.Fatalf("signed headers mismatch: %q", signedHeaders)
	}

	sts := stringToSign(timeMust(t, "2013-05-24T00:00:00Z"), "20130524/us-east-1/s3/aws4_request", canonical)
	wantSTS := "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
	if sts != wantSTS {
		t.Fatalf("string to sign mismatch:\n got: %s\nwant: %s", sts, wantSTS)
	}

	sig := signature("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3", sts)
	wantSig := "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if sig != wantSig {
		t.Fatalf("signature mismatch:\n got: %s\nwant: %s", sig, wantSig)
	}
}

func httpNewGet(u string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, u, nil)
}

func timeMust(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSigV4DifferentDataDifferentSignature(t *testing.T) {
	req, _ := httpNewGet("https://examplebucket.s3.amazonaws.com/a")
	req.Header.Set("x-amz-date", "20130524T000000Z")
	req.Header.Set("x-amz-content-sha256", emptyPayloadHash)
	c1, _ := canonicalRequest(req, emptyPayloadHash)
	req2, _ := httpNewGet("https://examplebucket.s3.amazonaws.com/b")
	req2.Header.Set("x-amz-date", "20130524T000000Z")
	req2.Header.Set("x-amz-content-sha256", emptyPayloadHash)
	c2, _ := canonicalRequest(req2, emptyPayloadHash)
	if c1 == c2 {
		t.Fatal("different URIs must produce different canonical requests")
	}
}

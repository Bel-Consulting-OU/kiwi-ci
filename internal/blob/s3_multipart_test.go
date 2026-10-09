package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const multipartTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeS3Call records one request the multipart fake served.
type fakeS3Call struct {
	Method     string
	Key        string
	UploadID   string
	PartNumber int
	Body       []byte
	Query      url.Values
}

func (c fakeS3Call) String() string {
	return fmt.Sprintf("%s %s part=%d upload=%s", c.Method, c.Key, c.PartNumber, c.UploadID)
}

// fakeS3Reply scripts one failure response: an HTTP status/body, or a dropped
// connection when dropConn is set.
type fakeS3Reply struct {
	status   int
	body     string
	dropConn bool
}

// fakeS3Multipart is a scriptable S3-compatible endpoint implementing the
// multipart surface Put exercises (Create, UploadPart, Complete, Abort) plus
// single PUT and HEAD. Every request is recorded, and hooks script failures.
type fakeS3Multipart struct {
	mu       sync.Mutex
	objects  map[string][]byte
	uploads  map[string]*fakeS3Upload
	calls    []fakeS3Call
	attempts map[int]int
	nextID   int

	// Scripting hooks, set before the Put under test.
	failCreate            *fakeS3Reply
	failPart              func(part, attempt int) *fakeS3Reply
	failComplete          *fakeS3Reply
	failAbort             *fakeS3Reply
	completeDrop          bool
	completeStore         bool
	completeEmbeddedError string
}

type fakeS3Upload struct {
	key   string
	parts map[int]fakeS3Part
}

type fakeS3Part struct {
	etag string
	body []byte
}

// newFakeS3Multipart returns a path-style S3 store pointed at the fake plus
// the fake itself.
func newFakeS3Multipart(t *testing.T) (*S3, *fakeS3Multipart) {
	t.Helper()
	f := &fakeS3Multipart{
		objects:  map[string][]byte{},
		uploads:  map[string]*fakeS3Upload{},
		attempts: map[int]int{},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &S3{
		Endpoint:        srv.URL,
		Region:          "us-east-1",
		Bucket:          "bucket",
		AccessKeyID:     "key",
		SecretAccessKey: "secret",
		PathStyle:       true,
	}, f
}

// multipartTestS3 returns a store whose multipart switchover and part size
// are small enough for cheap in-memory tests. The explicit test seam also
// bypasses the production S3 part-size range validation, which those small
// sizes would otherwise fail.
func multipartTestS3(t *testing.T, threshold, partSize int64) (*S3, *fakeS3Multipart) {
	t.Helper()
	s, f := newFakeS3Multipart(t)
	s.MultipartThreshold = threshold
	s.MultipartPartSize = partSize
	s.multipartTestParts = true
	return s, f
}

func (f *fakeS3Multipart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodPost && q.Has("uploads"):
		f.handleCreate(w, r)
	case r.Method == http.MethodPut && q.Get("uploadId") != "":
		f.handleUploadPart(w, r)
	case r.Method == http.MethodPost && q.Get("uploadId") != "":
		f.handleComplete(w, r)
	case r.Method == http.MethodDelete && q.Get("uploadId") != "":
		f.handleAbort(w, r)
	case r.Method == http.MethodHead:
		f.handleHead(w, r)
	case r.Method == http.MethodPut:
		f.handleSinglePut(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3Multipart) handleCreate(w http.ResponseWriter, r *http.Request) {
	key := fakeS3Key(r)
	f.mu.Lock()
	reply := f.failCreate
	id := ""
	if reply == nil {
		f.nextID++
		id = fmt.Sprintf("upload-%d", f.nextID)
		f.uploads[id] = &fakeS3Upload{key: key, parts: map[int]fakeS3Part{}}
	}
	f.calls = append(f.calls, fakeS3Call{Method: r.Method, Key: key, UploadID: id, Query: r.URL.Query()})
	f.mu.Unlock()
	if reply != nil {
		writeFakeReply(w, reply)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>`, key, id)
}

func (f *fakeS3Multipart) handleUploadPart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uploadID := q.Get("uploadId")
	part, _ := strconv.Atoi(q.Get("partNumber"))
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.calls = append(f.calls, fakeS3Call{Method: r.Method, Key: fakeS3Key(r), UploadID: uploadID, PartNumber: part, Body: body, Query: q})
	f.attempts[part]++
	attempt := f.attempts[part]
	hook := f.failPart
	f.mu.Unlock()
	if hook != nil {
		if reply := hook(part, attempt); reply != nil {
			writeFakeReply(w, reply)
			return
		}
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	f.mu.Lock()
	up := f.uploads[uploadID]
	if up != nil {
		up.parts[part] = fakeS3Part{etag: etag, body: body}
	}
	f.mu.Unlock()
	if up == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3Multipart) handleComplete(w http.ResponseWriter, r *http.Request) {
	uploadID := r.URL.Query().Get("uploadId")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.calls = append(f.calls, fakeS3Call{Method: r.Method, Key: fakeS3Key(r), UploadID: uploadID, Body: body, Query: r.URL.Query()})
	up := f.uploads[uploadID]
	reply := f.failComplete
	drop, storeOnDrop := f.completeDrop, f.completeStore
	embedded := f.completeEmbeddedError
	f.mu.Unlock()
	if up == nil {
		writeFakeStatus(w, http.StatusNotFound, "NoSuchUpload")
		return
	}
	var req s3CompleteMultipartUpload
	if err := xml.Unmarshal(body, &req); err != nil {
		writeFakeStatus(w, http.StatusBadRequest, "bad complete xml: "+err.Error())
		return
	}
	assembled, verr := f.assemble(up, req.Parts)
	if verr != nil {
		writeFakeStatus(w, http.StatusBadRequest, verr.Error())
		return
	}
	if reply != nil {
		writeFakeReply(w, reply)
		return
	}
	if embedded != "" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<CompleteMultipartUploadResult><Error><Code>InternalError</Code><Message>%s</Message></Error></CompleteMultipartUploadResult>`, embedded)
		return
	}
	if drop {
		if storeOnDrop {
			f.storeObject(up.key, assembled)
		}
		killFakeConnection(w)
		return
	}
	f.storeObject(up.key, assembled)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><Bucket>bucket</Bucket><ETag>"composite"</ETag></CompleteMultipartUploadResult>`)
}

// assemble validates that Complete lists exactly the uploaded parts in
// order, with the ETags originally issued, and returns the concatenation.
func (f *fakeS3Multipart) assemble(up *fakeS3Upload, parts []s3CompletePart) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(parts) != len(up.parts) {
		return nil, fmt.Errorf("complete lists %d parts, %d were uploaded", len(parts), len(up.parts))
	}
	var buf bytes.Buffer
	for i, p := range parts {
		want := i + 1
		if p.PartNumber != want {
			return nil, fmt.Errorf("complete part %d carries number %d", want, p.PartNumber)
		}
		stored, ok := up.parts[want]
		if !ok {
			return nil, fmt.Errorf("complete references part %d that was never uploaded", want)
		}
		if p.ETag != stored.etag {
			return nil, fmt.Errorf("complete part %d etag %q, uploaded etag %q", want, p.ETag, stored.etag)
		}
		buf.Write(stored.body)
	}
	return buf.Bytes(), nil
}

func (f *fakeS3Multipart) handleAbort(w http.ResponseWriter, r *http.Request) {
	uploadID := r.URL.Query().Get("uploadId")
	f.mu.Lock()
	f.calls = append(f.calls, fakeS3Call{Method: r.Method, Key: fakeS3Key(r), UploadID: uploadID, Query: r.URL.Query()})
	reply := f.failAbort
	delete(f.uploads, uploadID)
	f.mu.Unlock()
	if reply != nil {
		writeFakeReply(w, reply)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeS3Multipart) handleHead(w http.ResponseWriter, r *http.Request) {
	key := fakeS3Key(r)
	f.mu.Lock()
	f.calls = append(f.calls, fakeS3Call{Method: r.Method, Key: key, Query: r.URL.Query()})
	body, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3Multipart) handleSinglePut(w http.ResponseWriter, r *http.Request) {
	key := fakeS3Key(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.calls = append(f.calls, fakeS3Call{Method: r.Method, Key: key, Body: body, Query: r.URL.Query()})
	f.objects[key] = body
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3Multipart) storeObject(key string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = append([]byte(nil), body...)
}

func (f *fakeS3Multipart) recordedCalls() []fakeS3Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeS3Call, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeS3Multipart) storedObject(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, ok := f.objects[key]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, true
}

func fakeS3Key(r *http.Request) string {
	return strings.TrimPrefix(r.URL.Path, "/bucket/")
}

func writeFakeReply(w http.ResponseWriter, reply *fakeS3Reply) {
	if reply.dropConn {
		killFakeConnection(w)
		return
	}
	status := reply.status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	writeFakeStatus(w, status, reply.body)
}

func writeFakeStatus(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg)
}

// killFakeConnection closes the connection without answering, so the client
// observes a transport-level failure after the handler processed the request.
func killFakeConnection(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func isCreateCall(c fakeS3Call) bool {
	return c.Method == http.MethodPost && c.Query.Has("uploads")
}

func isCompleteCall(c fakeS3Call) bool {
	return c.Method == http.MethodPost && c.Query.Get("uploadId") != ""
}

func isAbortCall(c fakeS3Call) bool {
	return c.Method == http.MethodDelete && c.Query.Get("uploadId") != ""
}

func isPartCall(c fakeS3Call) bool {
	return c.Method == http.MethodPut && c.PartNumber > 0
}

func isHeadCall(c fakeS3Call) bool {
	return c.Method == http.MethodHead
}

func countCalls(calls []fakeS3Call, match func(fakeS3Call) bool) int {
	n := 0
	for _, c := range calls {
		if match(c) {
			n++
		}
	}
	return n
}

func firstCall(calls []fakeS3Call, match func(fakeS3Call) bool) (fakeS3Call, bool) {
	for _, c := range calls {
		if match(c) {
			return c, true
		}
	}
	return fakeS3Call{}, false
}

func summarizeCalls(calls []fakeS3Call) string {
	var b strings.Builder
	for i, c := range calls {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.String())
	}
	return b.String()
}

func payloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// TestS3PutThresholdSelectsSinglePutOrMultipart pins the switchover: an
// object at the threshold uses exactly one plain PUT and no multipart call,
// while an object above it uses the multipart protocol and reports the same
// streamed digest.
func TestS3PutThresholdSelectsSinglePutOrMultipart(t *testing.T) {
	ctx := context.Background()
	payload := []byte("0123456789abcdef0123456789abcdef")

	s, f := multipartTestS3(t, int64(len(payload)), 8)
	obj, err := s.Put(ctx, multipartTestKey, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put at the threshold: %v", err)
	}
	if obj.SHA256 != payloadDigest(payload) || obj.Size != int64(len(payload)) {
		t.Fatalf("object = %+v", obj)
	}
	calls := f.recordedCalls()
	if len(calls) != 1 || calls[0].Method != http.MethodPut || isCreateCall(calls[0]) || isPartCall(calls[0]) {
		t.Fatalf("object at the threshold must use one plain PUT, got: %s", summarizeCalls(calls))
	}

	s2, f2 := multipartTestS3(t, int64(len(payload))-1, 8)
	obj2, err := s2.Put(ctx, multipartTestKey, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put above the threshold: %v", err)
	}
	if obj2 != obj {
		t.Fatalf("multipart object = %+v, want %+v", obj2, obj)
	}
	calls2 := f2.recordedCalls()
	if countCalls(calls2, isCreateCall) != 1 {
		t.Fatalf("object above the threshold must use multipart, got: %s", summarizeCalls(calls2))
	}
}

// TestS3MultipartUploadSequence pins the whole protocol: Create, then UploadPart
// with contiguous 1-based numbers and exact part sizes (full parts except the
// last), then Complete with the collected ETags; the assembled object and the
// returned digest match the source.
func TestS3MultipartUploadSequence(t *testing.T) {
	s, f := multipartTestS3(t, 8, 4)
	payload := []byte("0123456789x") // 11 bytes -> parts of 4, 4, 3
	obj, err := s.Put(context.Background(), multipartTestKey, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if obj.Key != multipartTestKey || obj.Size != int64(len(payload)) || obj.SHA256 != payloadDigest(payload) {
		t.Fatalf("object = %+v, want digest %s size %d", obj, payloadDigest(payload), len(payload))
	}
	calls := f.recordedCalls()
	if len(calls) == 0 || !isCreateCall(calls[0]) {
		t.Fatalf("first call must be CreateMultipartUpload, got: %s", summarizeCalls(calls))
	}
	if last := calls[len(calls)-1]; !isCompleteCall(last) {
		t.Fatalf("last call must be CompleteMultipartUpload, got: %s", summarizeCalls(calls))
	}
	if n := countCalls(calls, isCreateCall); n != 1 {
		t.Fatalf("create calls = %d, want 1", n)
	}
	if n := countCalls(calls, isCompleteCall); n != 1 {
		t.Fatalf("complete calls = %d, want 1", n)
	}
	if n := countCalls(calls, isAbortCall); n != 0 {
		t.Fatalf("abort calls = %d, want 0", n)
	}
	var partCalls []fakeS3Call
	for _, c := range calls {
		if isPartCall(c) {
			partCalls = append(partCalls, c)
		}
	}
	if len(partCalls) != 3 {
		t.Fatalf("part calls = %d, want 3: %s", len(partCalls), summarizeCalls(calls))
	}
	wantSizes := []int{4, 4, 3}
	offset := 0
	for i, pc := range partCalls {
		if pc.PartNumber != i+1 {
			t.Fatalf("part %d numbered %d (parts must be contiguous from 1)", i+1, pc.PartNumber)
		}
		if len(pc.Body) != wantSizes[i] {
			t.Fatalf("part %d size = %d, want %d", pc.PartNumber, len(pc.Body), wantSizes[i])
		}
		if !bytes.Equal(pc.Body, payload[offset:offset+wantSizes[i]]) {
			t.Fatalf("part %d body = %q, want %q", pc.PartNumber, pc.Body, payload[offset:offset+wantSizes[i]])
		}
		offset += wantSizes[i]
	}
	if got, ok := f.storedObject(multipartTestKey); !ok || !bytes.Equal(got, payload) {
		t.Fatalf("assembled object = %q (ok=%v), want %q", got, ok, payload)
	}
}

// TestS3MultipartPartRetriesThenSucceeds proves a retryable part failure is
// retried with the same buffered bytes and the upload still completes.
func TestS3MultipartPartRetriesThenSucceeds(t *testing.T) {
	s, f := multipartTestS3(t, 4, 4)
	f.failPart = func(part, attempt int) *fakeS3Reply {
		if part == 2 && attempt == 1 {
			return &fakeS3Reply{status: http.StatusServiceUnavailable, body: "part overloaded"}
		}
		return nil
	}
	payload := []byte("abcdefghijkl") // 12 bytes -> 3 parts
	obj, err := s.Put(context.Background(), multipartTestKey, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put must retry the failed part and succeed: %v", err)
	}
	if obj.SHA256 != payloadDigest(payload) {
		t.Fatalf("digest = %s, want %s", obj.SHA256, payloadDigest(payload))
	}
	calls := f.recordedCalls()
	if n := countCalls(calls, func(c fakeS3Call) bool { return isPartCall(c) && c.PartNumber == 2 }); n != 2 {
		t.Fatalf("part 2 attempts = %d, want 2", n)
	}
	if n := countCalls(calls, isAbortCall); n != 0 {
		t.Fatalf("abort calls = %d, want 0", n)
	}
	if got, ok := f.storedObject(multipartTestKey); !ok || !bytes.Equal(got, payload) {
		t.Fatalf("assembled object = %q (ok=%v), want %q", got, ok, payload)
	}
}

// TestS3MultipartPermanentPartFailureAborts proves a part that fails both
// attempts aborts the incomplete upload, returns the part error, never calls
// Complete, and stores nothing.
func TestS3MultipartPermanentPartFailureAborts(t *testing.T) {
	s, f := multipartTestS3(t, 4, 4)
	f.failPart = func(part, attempt int) *fakeS3Reply {
		if part == 2 {
			return &fakeS3Reply{status: http.StatusInternalServerError, body: "part boom"}
		}
		return nil
	}
	_, err := s.Put(context.Background(), multipartTestKey, bytes.NewReader([]byte("abcdefghijkl")), 12)
	if err == nil {
		t.Fatal("a permanently failing part must fail the Put")
	}
	if !strings.Contains(err.Error(), "part 2") || !strings.Contains(err.Error(), "part boom") {
		t.Fatalf("error = %v, want the part failure", err)
	}
	calls := f.recordedCalls()
	if n := countCalls(calls, func(c fakeS3Call) bool { return isPartCall(c) && c.PartNumber == 2 }); n != 2 {
		t.Fatalf("part 2 attempts = %d, want exactly 2", n)
	}
	if n := countCalls(calls, isCompleteCall); n != 0 {
		t.Fatalf("complete calls = %d, want 0", n)
	}
	aborts := 0
	var abortCall fakeS3Call
	for _, c := range calls {
		if isAbortCall(c) {
			aborts++
			abortCall = c
		}
	}
	if aborts != 1 {
		t.Fatalf("abort calls = %d, want 1: %s", aborts, summarizeCalls(calls))
	}
	create, ok := firstCall(calls, isCreateCall)
	if !ok || abortCall.UploadID != create.UploadID {
		t.Fatalf("abort upload id = %q, create upload id = %q", abortCall.UploadID, create.UploadID)
	}
	if _, ok := f.storedObject(multipartTestKey); ok {
		t.Fatal("a failed upload must not store an object")
	}
}

// TestS3MultipartAbortFailureIsSurfacedWithoutMaskingPrimary proves an abort
// that fails too is joined into the returned error while the primary part
// failure remains visible.
func TestS3MultipartAbortFailureIsSurfacedWithoutMaskingPrimary(t *testing.T) {
	s, f := multipartTestS3(t, 4, 4)
	f.failPart = func(part, attempt int) *fakeS3Reply {
		if part == 2 {
			return &fakeS3Reply{status: http.StatusInternalServerError, body: "part boom"}
		}
		return nil
	}
	f.failAbort = &fakeS3Reply{status: http.StatusBadGateway, body: "abort down"}
	_, err := s.Put(context.Background(), multipartTestKey, bytes.NewReader([]byte("abcdefghijkl")), 12)
	if err == nil {
		t.Fatal("Put must fail")
	}
	if !strings.Contains(err.Error(), "part boom") {
		t.Fatalf("primary error masked: %v", err)
	}
	if !strings.Contains(err.Error(), "abort down") {
		t.Fatalf("abort failure not surfaced: %v", err)
	}
	if !errors.Is(err, errS3MultipartAbort) {
		t.Fatalf("error = %v, want it to match errS3MultipartAbort", err)
	}
}

// TestS3MultipartLostCompleteResponseWithVisibleObjectSucceeds proves the
// response-loss recovery: a Complete whose response was lost is treated as
// successful when a bounded HEAD finds the object at the expected size, and
// the completed upload is never aborted.
func TestS3MultipartLostCompleteResponseWithVisibleObjectSucceeds(t *testing.T) {
	s, f := multipartTestS3(t, 4, 4)
	f.completeDrop = true
	f.completeStore = true
	payload := []byte("lost response but the object is stored")
	obj, err := s.Put(context.Background(), multipartTestKey, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("recovery must treat a visible object as success: %v", err)
	}
	if obj.SHA256 != payloadDigest(payload) || obj.Size != int64(len(payload)) {
		t.Fatalf("recovered object = %+v", obj)
	}
	calls := f.recordedCalls()
	if n := countCalls(calls, isHeadCall); n != 1 {
		t.Fatalf("recovery HEAD calls = %d, want 1: %s", n, summarizeCalls(calls))
	}
	if n := countCalls(calls, isAbortCall); n != 0 {
		t.Fatalf("abort calls = %d, want 0 (a completed upload must never be aborted)", n)
	}
	if got, ok := f.storedObject(multipartTestKey); !ok || !bytes.Equal(got, payload) {
		t.Fatalf("stored object = %q (ok=%v), want %q", got, ok, payload)
	}
}

// TestS3MultipartLostCompleteResponseWithoutObjectAborts proves the other
// recovery branch: a lost Complete response with no object (or a differently
// sized one) aborts the incomplete upload and fails.
func TestS3MultipartLostCompleteResponseWithoutObjectAborts(t *testing.T) {
	s, f := multipartTestS3(t, 4, 4)
	f.completeDrop = true
	f.completeStore = false
	_, err := s.Put(context.Background(), multipartTestKey, bytes.NewReader([]byte("never completed")), 15)
	if err == nil {
		t.Fatal("a lost Complete response without a visible object must fail")
	}
	calls := f.recordedCalls()
	if n := countCalls(calls, isHeadCall); n != 1 {
		t.Fatalf("recovery HEAD calls = %d, want 1: %s", n, summarizeCalls(calls))
	}
	if n := countCalls(calls, isAbortCall); n != 1 {
		t.Fatalf("abort calls = %d, want 1: %s", n, summarizeCalls(calls))
	}
	if _, ok := f.storedObject(multipartTestKey); ok {
		t.Fatal("no object must be stored")
	}
}

// TestS3MultipartCompleteErrorsAbort proves a non-transport Complete failure
// (an error status or the HTTP 200 with an embedded <Error> trap) aborts the
// upload and fails without a recovery HEAD.
func TestS3MultipartCompleteErrorsAbort(t *testing.T) {
	cases := map[string]struct {
		configure func(*fakeS3Multipart)
		want      string
	}{
		"status": {
			configure: func(f *fakeS3Multipart) {
				f.failComplete = &fakeS3Reply{status: http.StatusInternalServerError, body: "complete down"}
			},
			want: "complete down",
		},
		"embedded": {
			configure: func(f *fakeS3Multipart) { f.completeEmbeddedError = "assembly failed" },
			want:      "assembly failed",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, f := multipartTestS3(t, 4, 4)
			tc.configure(f)
			_, err := s.Put(context.Background(), multipartTestKey, bytes.NewReader([]byte("abcdefghijkl")), 12)
			if err == nil {
				t.Fatal("Put must fail")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
			calls := f.recordedCalls()
			if n := countCalls(calls, isAbortCall); n != 1 {
				t.Fatalf("abort calls = %d, want 1: %s", n, summarizeCalls(calls))
			}
			if n := countCalls(calls, isHeadCall); n != 0 {
				t.Fatalf("non-transport complete errors must not trigger a recovery HEAD: %s", summarizeCalls(calls))
			}
		})
	}
}

// TestS3MultipartRejectsTooManyPartsBeforeCreate proves a declared size that
// would exceed the 10000-part limit is rejected before any request is made
// and before the source is read.
func TestS3MultipartRejectsTooManyPartsBeforeCreate(t *testing.T) {
	s, f := multipartTestS3(t, 1, 8)
	size := int64(s3MaxMultipartParts)*8 + 1
	_, err := s.Put(context.Background(), multipartTestKey, panicOnRead{t: t}, size)
	if !errors.Is(err, errS3MultipartPartsExceeded) {
		t.Fatalf("err = %v, want errS3MultipartPartsExceeded", err)
	}
	if !strings.Contains(err.Error(), "10000") {
		t.Fatalf("error must name the limit: %v", err)
	}
	if calls := f.recordedCalls(); len(calls) != 0 {
		t.Fatalf("rejection must happen before any request: %s", summarizeCalls(calls))
	}
}

// panicOnRead fails the test if the source is read at all.
type panicOnRead struct{ t *testing.T }

func (p panicOnRead) Read([]byte) (int, error) {
	p.t.Error("the source must not be read when the size is rejected")
	return 0, io.EOF
}

// TestS3MultipartDigestMatchesSinglePut proves both write paths return the
// digest of the streamed bytes (the key is not verified by the backend in
// either path), so a caller's own digest check behaves identically.
func TestS3MultipartDigestMatchesSinglePut(t *testing.T) {
	payload := []byte("digest consistency across both S3 write paths")
	want := payloadDigest(payload)

	single, _ := newFakeS3Multipart(t)
	one, err := single.Put(context.Background(), multipartTestKey, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("single Put: %v", err)
	}
	multi, _ := multipartTestS3(t, 4, 4)
	many, err := multi.Put(context.Background(), multipartTestKey, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("multipart Put: %v", err)
	}
	if one.SHA256 != want || many.SHA256 != want {
		t.Fatalf("digests = single %s, multipart %s, want %s", one.SHA256, many.SHA256, want)
	}
	if one.SHA256 != many.SHA256 {
		t.Fatalf("paths disagree: single %s, multipart %s", one.SHA256, many.SHA256)
	}
}

// TestS3MultipartSizeMismatchFailsAndAborts proves the multipart path
// enforces the declared size exactly like the single PUT path: a short stream
// never completes, and an over-long stream fails closed; both abort.
func TestS3MultipartSizeMismatchFailsAndAborts(t *testing.T) {
	ctx := context.Background()

	t.Run("short", func(t *testing.T) {
		s, f := multipartTestS3(t, 4, 4)
		_, err := s.Put(ctx, multipartTestKey, bytes.NewReader([]byte("abc")), 12)
		if err == nil || !strings.Contains(err.Error(), "size mismatch") {
			t.Fatalf("short stream error = %v", err)
		}
		calls := f.recordedCalls()
		if n := countCalls(calls, isCompleteCall); n != 0 {
			t.Fatalf("complete calls = %d, want 0", n)
		}
		if n := countCalls(calls, isAbortCall); n != 1 {
			t.Fatalf("abort calls = %d, want 1: %s", n, summarizeCalls(calls))
		}
	})

	t.Run("long", func(t *testing.T) {
		s, f := multipartTestS3(t, 4, 4)
		_, err := s.Put(ctx, multipartTestKey, bytes.NewReader([]byte("abcdefghijklm")), 12)
		if err == nil || !strings.Contains(err.Error(), "longer than the declared") {
			t.Fatalf("over-long stream error = %v", err)
		}
		calls := f.recordedCalls()
		if n := countCalls(calls, isCompleteCall); n != 0 {
			t.Fatalf("complete calls = %d, want 0", n)
		}
		if n := countCalls(calls, isAbortCall); n != 1 {
			t.Fatalf("abort calls = %d, want 1: %s", n, summarizeCalls(calls))
		}
	})
}

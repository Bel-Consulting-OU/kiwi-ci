package blob

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// s3UnsignedPayload is the SigV4 payload-hash sentinel Put signs with. Put
// streams the caller's reader straight to the endpoint and therefore cannot
// hash the body before signing, so the body is sent as UNSIGNED-PAYLOAD
// instead of being spooled into a full local copy first. The destination
// hashes the streamed bytes while they are sent, so digest violations are
// still detected, and TLS (required by AWS for UNSIGNED-PAYLOAD) protects the
// bytes in transit.
const s3UnsignedPayload = "UNSIGNED-PAYLOAD"

// byteCounter counts the bytes read from an underlying reader; Put uses it to
// enforce the advertised size exactly without buffering the payload.
type byteCounter struct {
	r io.Reader
	n atomic.Int64
}

func (c *byteCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// count reads the byte total race-free: the HTTP transport may still be
// writing the request body when client.Do returns (a server can answer
// before consuming it), so the counter is written from the transport's
// write goroutine and read from the caller's.
func (c *byteCounter) count() int64 { return c.n.Load() }

// s3RequestDeadlines bound requests whose caller context carries no
// deadline, so a stalled S3 endpoint can never hang a request forever.
// Streamed GET bodies are deliberately NOT bounded here: a body is bounded by
// the sliding BodyInactivityTimeout watchdog instead, so a transfer that
// keeps making progress may run for an unbounded total time (the same
// philosophy as the runner's streaming client and the cache store guard).
const (
	s3PutTimeout    = 30 * time.Minute
	s3DeleteTimeout = 2 * time.Minute
)

// Multipart upload limits. AWS caps one PUT at 5 GiB while the Kiwi blob
// contract admits 8 GiB objects, so oversized objects must use the S3
// multipart protocol instead of a single request.
const (
	// s3MultipartThreshold is the object size above which Put switches from a
	// single PUT to a multipart upload. 256 MiB keeps ordinary artifacts on
	// the simple single-request path while leaving a wide margin below the
	// 5 GiB single-PUT cap.
	s3MultipartThreshold = 256 << 20

	// s3MultipartPartSize is the size of every multipart part except the last
	// (which may be smaller). It is far above the 5 MiB S3 minimum for
	// non-final parts and far below the 5 GiB ceiling for one part; Kiwi's
	// maximum 8 GiB object needs 128 parts at this size, well inside the
	// 10000-part limit.
	s3MultipartPartSize = 64 << 20

	// s3MultipartMinPartSize and s3MultipartMaxPartSize are the S3 protocol
	// bounds for a configured part size: every part except the last must be
	// at least 5 MiB, and no single part may exceed 5 GiB. The resolvers
	// enforce them so an invalid advanced configuration fails before any
	// request instead of a remote rejection halfway through an upload.
	s3MultipartMinPartSize int64 = 5 << 20
	s3MultipartMaxPartSize int64 = 5 << 30

	// s3MaxMultipartParts is S3's ceiling on the number of parts in one
	// multipart upload. A declared size that would need more parts is
	// rejected before the upload is created, so an impossible upload never
	// leaves an incomplete multipart upload behind.
	s3MaxMultipartParts = 10000
)

// Multipart request bounds. Like s3PutTimeout these only apply when the
// caller's context carries no deadline of its own; the caller's deadline
// always wins. Every part upload is bounded and retried on its own, so one
// slow or failed part never consumes the budget of the parts around it.
const (
	// s3MultipartPartTimeout bounds one UploadPart request.
	s3MultipartPartTimeout = 15 * time.Minute
	// s3MultipartPartAttempts is the number of tries one part gets before the
	// whole upload fails and is aborted.
	s3MultipartPartAttempts = 2
	// s3MultipartCreateTimeout bounds CreateMultipartUpload.
	s3MultipartCreateTimeout = 2 * time.Minute
	// s3MultipartCompleteTimeout bounds CompleteMultipartUpload: S3 may spend
	// a while assembling every part of a large object.
	s3MultipartCompleteTimeout = 15 * time.Minute
	// s3MultipartAbortTimeout bounds the best-effort AbortMultipartUpload
	// cleanup of a failed upload.
	s3MultipartAbortTimeout = 2 * time.Minute
	// s3MultipartResponseBytes bounds a create/complete XML response read.
	s3MultipartResponseBytes = 1 << 20
)

// errS3MultipartPartsExceeded reports a declared object size that needs more
// than s3MaxMultipartParts parts: the upload is rejected before Create, so no
// incomplete upload is ever started for it.
var errS3MultipartPartsExceeded = errors.New("blob: s3 multipart part limit exceeded")

// errS3MultipartAbort marks a failure to clean up an incomplete multipart
// upload. It is joined with (never substituted for) the primary failure that
// triggered the abort, so callers can detect both.
var errS3MultipartAbort = errors.New("blob: s3 multipart abort failed")

// s3InitiateMultipartUploadResult is the subset of the
// InitiateMultipartUpload XML response Put needs.
type s3InitiateMultipartUploadResult struct {
	UploadID string `xml:"UploadId"`
}

// s3CompletePart is one <Part> entry of the CompleteMultipartUpload request.
type s3CompletePart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// s3CompleteMultipartUpload is the CompleteMultipartUpload request body.
type s3CompleteMultipartUpload struct {
	XMLName xml.Name         `xml:"CompleteMultipartUpload"`
	Parts   []s3CompletePart `xml:"Part"`
}

// s3CompleteMultipartUploadResult is the subset of the
// CompleteMultipartUpload XML response Put inspects. S3 may answer HTTP 200
// with an embedded <Error> element instead of a completed upload, so that
// element is decoded and treated as a failure rather than acknowledged.
type s3CompleteMultipartUploadResult struct {
	Error *s3MultipartEmbeddedError `xml:"Error"`
}

type s3MultipartEmbeddedError struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// s3MultipartTransportError marks a multipart control request that failed at
// the transport level: the request may have reached S3 even though its
// response was lost. Only CompleteMultipartUpload treats such an error as a
// recovery candidate (a bounded HEAD can prove the upload completed).
type s3MultipartTransportError struct{ err error }

func (e *s3MultipartTransportError) Error() string { return e.err.Error() }
func (e *s3MultipartTransportError) Unwrap() error { return e.err }

// DefaultBodyInactivityTimeout is the default sliding inactivity window for a
// streamed S3 response body (S3.BodyInactivityTimeout): when no byte arrives
// for this long the request is aborted. Every successful read re-arms the
// window, so the window bounds silence, never the total transfer duration.
const DefaultBodyInactivityTimeout = 60 * time.Second

// DefaultListPageTimeout is the default bound on a single ListObjectsV2 page
// request, including reading and decoding its response body
// (S3.ListPageTimeout). The caller's context bounds the enumeration as a
// whole; each page gets this fresh window of its own.
const DefaultListPageTimeout = 30 * time.Second

// ErrBodyStalled reports an S3 response body aborted by the sliding
// inactivity watchdog: no byte arrived for the configured window. The
// returned error also wraps context.DeadlineExceeded, so callers may treat it
// as a timeout-class failure; a caller's own context cancellation is passed
// through unchanged instead.
var ErrBodyStalled = errors.New("blob: s3 response body stalled")

// s3ListPageSize is the bounded ListObjectsV2 page size: the store never
// asks the endpoint for more than this many keys per request, so a listing
// of a huge bucket streams in bounded pages instead of one unbounded
// response.
const s3ListPageSize = 1000

// s3ListObjectsResult is the subset of the ListObjectsV2 XML response the
// enumerator needs.
type s3ListObjectsResult struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
}

// withDeadline returns ctx unchanged when it already has a deadline,
// otherwise a copy bounded by d. The returned cancel is a no-op in the
// former case.
func withDeadline(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

// s3BodyGuard is a sliding inactivity watchdog for one streamed S3 response
// body. It cancels the request when no byte has moved for idle, and every
// successful read re-arms it, so a body that keeps making progress is never
// cut by a total-duration bound while a body that stops sending is aborted in
// bounded time. It mirrors the runner-side streaming guard and the cache
// store guard: a single timer is armed per transfer and stopped when the body
// is closed, leaving no timer behind.
type s3BodyGuard struct {
	cancel context.CancelFunc
	idle   time.Duration

	mu    sync.Mutex
	timer *time.Timer
	// last is the most recent successful progress instant.
	last time.Time
	// done latches the guard once it has fired or been stopped.
	done bool
	// fired records that the guard itself aborted the transfer, so the read
	// error can be attributed to inactivity rather than caller cancellation.
	fired bool
}

// newS3BodyGuard arms the watchdog on the body's cancelable request context.
func newS3BodyGuard(cancel context.CancelFunc, idle time.Duration) *s3BodyGuard {
	g := &s3BodyGuard{cancel: cancel, idle: idle, last: time.Now()}
	g.timer = time.AfterFunc(idle, g.onIdle)
	return g
}

// onIdle fires when the inactivity timer elapses. Timer.Reset cannot revoke a
// callback that has already been dispatched: if progress arrived after this
// callback was scheduled, cancelling would abort an ACTIVE transfer exactly
// at the idle boundary. The callback therefore re-checks the progress instant
// under the lock and re-arms for the remainder of the window instead of
// cancelling; only a window with no progress at all aborts.
func (g *s3BodyGuard) onIdle() {
	g.mu.Lock()
	if g.done {
		g.mu.Unlock()
		return
	}
	if left := g.idle - time.Since(g.last); left > 0 {
		g.timer.Reset(left)
		g.mu.Unlock()
		return
	}
	g.done = true
	g.fired = true
	g.mu.Unlock()
	g.cancel()
}

// progress records a successful body read and re-arms the watchdog.
func (g *s3BodyGuard) progress() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.done {
		return
	}
	g.last = time.Now()
	g.timer.Reset(g.idle)
}

// stop disarms the watchdog; it is idempotent and a stopped guard never fires.
func (g *s3BodyGuard) stop() {
	g.mu.Lock()
	g.done = true
	g.mu.Unlock()
	g.timer.Stop()
}

// stalled reports whether the watchdog aborted the transfer.
func (g *s3BodyGuard) stalled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fired
}

// s3GuardedBody ties a streamed response body to the request context that
// owns it and to the inactivity watchdog. The cancelable context must outlive
// Open: the caller streams the body after Open returns, so it may only be
// released when the body is closed. Close closes the underlying body first
// (releasing the connection) and then releases the watchdog and the request
// context; the watchdog stays armed through the inner Close because a
// verifying reader may still be draining the remainder of the stream.
type s3GuardedBody struct {
	io.ReadCloser
	guard  *s3BodyGuard
	parent context.Context
	cancel context.CancelFunc
}

func (b *s3GuardedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.guard.progress()
	}
	if err != nil {
		return n, b.mapError(err)
	}
	return n, nil
}

// mapError attributes an aborted read: a watchdog cancellation surfaces as
// ErrBodyStalled wrapping context.DeadlineExceeded, while a caller's own
// context cancellation (or any genuine transport error) is passed through.
func (b *s3GuardedBody) mapError(err error) error {
	if b.guard.stalled() && b.parent.Err() == nil {
		return fmt.Errorf("%w after %s without a byte: %w", ErrBodyStalled, b.guard.idle, context.DeadlineExceeded)
	}
	return err
}

func (b *s3GuardedBody) Close() error {
	// The inner Close may still move bytes (a caller draining to EOF, or a
	// verifying reader draining a partial stream), so the watchdog and the
	// request context stay armed until it returns: disarming first would let
	// a peer that stops sending hang Close forever.
	defer b.guard.stop()
	defer b.cancel()
	return b.ReadCloser.Close()
}

// s3Dialer is the dialer behind the default S3 transport: 10s connection
// establishment and 30s keep-alive.
var s3Dialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
}

// s3Transport builds the default S3 HTTP transport with explicit
// connection timeouts and idle limits: 10s dial, 90s idle connection
// lifetime, 10s TLS handshake, 30s response header, and bounded idle
// connection counts.
func s3Transport() *http.Transport {
	return &http.Transport{
		DialContext:           s3Dialer.DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// S3 is an S3-compatible Store using AWS Signature Version 4 implemented with
// the standard library only.
//
// Endpoint and Bucket are parsed and validated exactly once per store
// instance (see Validate), so an unusable endpoint/bucket/style combination
// fails the first request instead of building a broken URL.
type S3 struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Token           string
	PathStyle       bool
	Client          *http.Client

	// BodyInactivityTimeout is the sliding inactivity window applied to a
	// streamed Open body: when no byte arrives for this long the request is
	// cancelled and the body read fails with an error wrapping
	// ErrBodyStalled and context.DeadlineExceeded. Every successful read
	// re-arms the window, so a body that keeps making progress is never cut
	// by a total-duration bound. Zero means DefaultBodyInactivityTimeout.
	BodyInactivityTimeout time.Duration

	// ListPageTimeout bounds one ListObjectsV2 page request, including
	// reading and decoding its response body. The caller's context still
	// bounds the enumeration as a whole; every page gets a fresh window of
	// its own, so a large but healthy listing can never exhaust one shared
	// deadline. Zero means DefaultListPageTimeout.
	ListPageTimeout time.Duration

	// MultipartThreshold is the object size above which Put uses a multipart
	// upload instead of a single PUT. Zero means s3MultipartThreshold. A
	// negative value is rejected by the resolver before any request. A
	// declared size that would need more than s3MaxMultipartParts parts at
	// MultipartPartSize is rejected before the upload starts.
	MultipartThreshold int64

	// MultipartPartSize is the size of every multipart part except the last.
	// Zero means s3MultipartPartSize. The value exists as an advanced/test
	// seam: the production default is the vetted 64 MiB constant. A
	// configured value outside S3's protocol bounds (at least 5 MiB, at most
	// 5 GiB per part) or negative is rejected by the resolver before any
	// request.
	MultipartPartSize int64

	// multipartTestParts disables the S3 part-size range validation for the
	// package's small in-memory multipart fixtures (see multipartTestS3);
	// production never sets it.
	multipartTestParts bool

	// endpointOnce caches the endpoint resolution: endpointURL is the parsed
	// endpoint and endpointErr is the sticky validation error.
	endpointOnce sync.Once
	endpointURL  *url.URL
	endpointErr  error
}

// bodyInactivityTimeout resolves the effective GET body inactivity window.
func (s *S3) bodyInactivityTimeout() time.Duration {
	if s.BodyInactivityTimeout > 0 {
		return s.BodyInactivityTimeout
	}
	return DefaultBodyInactivityTimeout
}

// listPageTimeout resolves the effective per-page ListObjectsV2 bound.
func (s *S3) listPageTimeout() time.Duration {
	if s.ListPageTimeout > 0 {
		return s.ListPageTimeout
	}
	return DefaultListPageTimeout
}

// multipartThreshold resolves the effective multipart switchover size. A
// negative configured value is invalid and fails before any request.
func (s *S3) multipartThreshold() (int64, error) {
	if s.MultipartThreshold < 0 {
		return 0, fmt.Errorf("blob: s3 multipart threshold must not be negative (got %d)", s.MultipartThreshold)
	}
	if s.MultipartThreshold > 0 {
		return s.MultipartThreshold, nil
	}
	return s3MultipartThreshold, nil
}

// multipartPartSize resolves the effective per-part size and validates the
// configured knob against the S3 protocol bounds (5 MiB minimum for every
// part except the last, 5 GiB maximum per part), so an out-of-range advanced
// configuration fails before any request instead of a remote rejection
// halfway through an upload. multipartTestParts (test-only) bypasses the
// range check for the small in-memory multipart fixtures.
func (s *S3) multipartPartSize() (int64, error) {
	if s.MultipartPartSize == 0 {
		return s3MultipartPartSize, nil
	}
	if s.MultipartPartSize < 0 {
		return 0, fmt.Errorf("blob: s3 multipart part size must not be negative (got %d)", s.MultipartPartSize)
	}
	if !s.multipartTestParts {
		if s.MultipartPartSize < s3MultipartMinPartSize {
			return 0, fmt.Errorf("blob: s3 multipart part size %d is below the S3 minimum of %d bytes", s.MultipartPartSize, s3MultipartMinPartSize)
		}
		if s.MultipartPartSize > s3MultipartMaxPartSize {
			return 0, fmt.Errorf("blob: s3 multipart part size %d exceeds the S3 maximum of %d bytes", s.MultipartPartSize, s3MultipartMaxPartSize)
		}
	}
	return s.MultipartPartSize, nil
}

func (s *S3) client() *http.Client {
	var c *http.Client
	if s.Client != nil {
		cc := *s.Client
		c = &cc
	} else {
		c = &http.Client{Transport: s3Transport()}
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// s3BucketRE matches the URL-safe bucket characters an S3-compatible
// endpoint accepts. The full AWS naming rules (3-63 lowercase characters)
// are deliberately not enforced: local gateways commonly use short or
// mixed-case names, and the coherence rules in resolveS3Target are what keep
// the address resolvable.
var s3BucketRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// parseS3Endpoint parses and structurally validates one S3 endpoint. The
// endpoint must be an absolute http(s) URL with a host and, like every
// credential-bearing URL, must not carry userinfo, a query or a fragment.
// This parse is the single source of truth for both addressing styles.
func parseS3Endpoint(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("blob: s3 endpoint is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("blob: s3 endpoint is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("blob: s3 endpoint must use http:// or https://, got %q", raw)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("blob: s3 endpoint has no host: %q", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("blob: s3 endpoint must not carry userinfo (credentials go in the access key fields)")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("blob: s3 endpoint must not carry a query or fragment")
	}
	return u, nil
}

// validateS3Bucket checks that bucket can be placed in a URL path
// (path-style) or as the first host label (virtual-hosted style).
func validateS3Bucket(bucket string, pathStyle bool) error {
	if bucket == "" {
		return fmt.Errorf("blob: s3 bucket is required")
	}
	if !s3BucketRE.MatchString(bucket) || strings.Contains(bucket, "..") {
		return fmt.Errorf("blob: s3 bucket %q contains characters that cannot appear in an S3 URL", bucket)
	}
	if pathStyle {
		return nil
	}
	for _, label := range strings.Split(bucket, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("blob: s3 bucket %q is not a DNS-compatible host label; use path-style addressing (blob.s3_path_style)", bucket)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("blob: s3 bucket %q is not a DNS-compatible host label; use path-style addressing (blob.s3_path_style)", bucket)
			}
		}
	}
	return nil
}

// resolveS3Target parses the endpoint and validates the endpoint/bucket
// combination for the chosen addressing style:
//
//   - path-style: the endpoint may be an IP literal and may carry a path
//     prefix (a gateway base path); the bucket is appended to that path and
//     the endpoint port is preserved.
//   - virtual-hosted style: the bucket becomes the first host label, so the
//     endpoint host must be a DNS name (an IP literal cannot carry a bucket
//     subdomain), must not carry a path prefix (which cannot be combined
//     with a bucket host), and the bucket must be a DNS-compatible label
//     sequence. Use path-style addressing for any of those cases.
func resolveS3Target(endpoint, bucket string, pathStyle bool) (*url.URL, error) {
	u, err := parseS3Endpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if err := validateS3Bucket(bucket, pathStyle); err != nil {
		return nil, err
	}
	if pathStyle {
		return u, nil
	}
	if net.ParseIP(u.Hostname()) != nil {
		return nil, fmt.Errorf("blob: s3 endpoint %q is an IP address, which cannot carry the virtual-hosted bucket subdomain; use path-style addressing (blob.s3_path_style)", u.Host)
	}
	if strings.Trim(u.Path, "/") != "" {
		return nil, fmt.Errorf("blob: s3 endpoint %q has a path prefix, which virtual-hosted addressing cannot combine with a bucket host; use path-style addressing (blob.s3_path_style)", u.Path)
	}
	return u, nil
}

// ValidateS3Config validates one endpoint/bucket pair for the given
// addressing style exactly as the S3 transport resolves it, so config
// validation can fail an unusable combination at startup instead of at the
// first artifact transfer.
func ValidateS3Config(endpoint, bucket string, pathStyle bool) error {
	_, err := resolveS3Target(endpoint, bucket, pathStyle)
	return err
}

// Validate reports whether the store's endpoint/bucket/style combination is
// usable, parsing the endpoint exactly once. objectURL performs the same
// check, so direct constructors can fail fast at startup with the same error
// the first request would report.
func (s *S3) Validate() error {
	return s.resolveEndpoint()
}

// resolveEndpoint parses and validates the endpoint exactly once per store
// instance and reports the sticky error on every later call.
func (s *S3) resolveEndpoint() error {
	s.endpointOnce.Do(func() {
		s.endpointURL, s.endpointErr = resolveS3Target(s.Endpoint, s.Bucket, s.PathStyle)
	})
	return s.endpointErr
}

// objectURL builds the request URL for one object key in the store's
// addressing style, preserving the endpoint port in both styles. Path-style
// keeps any endpoint path prefix and appends the bucket to it; virtual-hosted
// style prefixes the bucket to the endpoint host and requires the
// endpoint/bucket combination validated by resolveS3Target.
// validateKey is the single key guard: every S3 operation must present a
// canonical 64-hex digest, so a caller-supplied key can never inject path
// segments or query parameters into the signed request URL.
func (s *S3) validateKey(key string) error {
	if !keyRE.MatchString(key) {
		return fmt.Errorf("blob: invalid s3 key %q", key)
	}
	return nil
}

func (s *S3) objectURL(key string) (string, error) {
	if err := s.resolveEndpoint(); err != nil {
		return "", err
	}
	key = strings.TrimPrefix(key, "/")
	if s.PathStyle {
		return strings.TrimRight(s.endpointURL.String(), "/") + "/" + s.Bucket + "/" + key, nil
	}
	host := s.Bucket + "." + s.endpointURL.Hostname()
	if port := s.endpointURL.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	return s.endpointURL.Scheme + "://" + host + "/" + key, nil
}

func (s *S3) sign(req *http.Request, payloadHash string, now time.Time) {
	region := s.Region
	if region == "" {
		region = "us-east-1"
	}
	req.Header.Set("x-amz-date", now.UTC().Format("20060102T150405Z"))
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if s.Token != "" {
		req.Header.Set("x-amz-security-token", s.Token)
	}
	canonical, signedHeaders := canonicalRequest(req, payloadHash)
	scope := now.UTC().Format("20060102") + "/" + region + "/s3/aws4_request"
	sts := stringToSign(now.UTC(), scope, canonical)
	sig := signature(s.SecretAccessKey, now.UTC().Format("20060102"), region, "s3", sts)
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.AccessKeyID, scope, signedHeaders, sig))
}

func canonicalRequest(req *http.Request, payloadHash string) (string, string) {
	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	query := req.URL.Query()
	var qs []string
	for k, vs := range query {
		for _, v := range vs {
			qs = append(qs, awsURIEncode(k, true)+"="+awsURIEncode(v, true))
		}
	}
	sort.Strings(qs)
	canonicalQuery := strings.Join(qs, "&")

	headers := map[string]string{}
	for k, vs := range req.Header {
		headers[strings.ToLower(k)] = strings.Join(vs, ",")
	}
	headers["host"] = req.URL.Host
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var ch []string
	for _, k := range keys {
		ch = append(ch, k+":"+compactSpaces(headers[k])+"\n")
	}
	signedHeaders := strings.Join(keys, ";")
	canonicalHeaders := strings.Join(ch, "")
	return strings.Join([]string{req.Method, uri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash}, "\n"), signedHeaders
}

func compactSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// awsURIEncode implements the SigV4 URI encoding: unreserved characters are
// kept, everything else is percent-encoded, and "/" is only kept when
// encodeSlash is false. Unlike url.QueryEscape it encodes a space as %20,
// which is required for the canonical query string.
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// s3DigestFromKey extracts the content digest an S3 object key addresses.
// The S3 store writes bare digest keys; the two-level sha256/<xx>/<digest>
// layout the FS store uses is accepted too so a bucket migrated between
// backends enumerates the same way.
func s3DigestFromKey(key string) (string, bool) {
	if keyRE.MatchString(key) {
		return key, true
	}
	rest, ok := strings.CutPrefix(key, "sha256/")
	if !ok {
		return "", false
	}
	shard, digest, ok := strings.Cut(rest, "/")
	if !ok || len(shard) != 2 || !keyRE.MatchString(digest) || shard != digest[:2] {
		return "", false
	}
	return digest, true
}

func stringToSign(now time.Time, scope, canonical string) string {
	h := sha256.Sum256([]byte(canonical))
	return "AWS4-HMAC-SHA256\n" + now.UTC().Format("20060102T150405Z") + "\n" + scope + "\n" + hex.EncodeToString(h[:])
}

func signature(secret, date, region, service, sts string) string {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return hex.EncodeToString(hmacSHA256(kSigning, sts))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// Put stores one object. Objects whose declared size is at most
// multipartThreshold are written with a single streaming PUT request (see
// putSingle); larger objects use a multipart upload (see putMultipart),
// because AWS caps one PUT at 5 GiB while the Kiwi blob contract admits 8 GiB
// objects. Both paths hash exactly the bytes streamed, return that digest,
// and reject a source that does not deliver exactly the declared size.
func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64) (Object, error) {
	if !keyRE.MatchString(key) {
		return Object{}, fmt.Errorf("blob: invalid key %q", key)
	}
	if size < 0 {
		return Object{}, fmt.Errorf("blob: negative size")
	}
	threshold, err := s.multipartThreshold()
	if err != nil {
		return Object{}, err
	}
	if size > threshold {
		return s.putMultipart(ctx, key, r, size)
	}
	return s.putSingle(ctx, key, r, size)
}

// putSingle is the small-object path: one streaming PUT.
func (s *S3) putSingle(ctx context.Context, key string, r io.Reader, size int64) (Object, error) {
	if !keyRE.MatchString(key) {
		return Object{}, fmt.Errorf("blob: invalid key %q", key)
	}
	if size < 0 {
		return Object{}, fmt.Errorf("blob: negative size")
	}
	ctx, cancel := withDeadline(ctx, s3PutTimeout)
	defer cancel()
	rawURL, err := s.objectURL(key)
	if err != nil {
		return Object{}, err
	}
	// Stream the payload straight to the endpoint: no full local copy is
	// staged (the previous implementation spooled up to 8 GiB into the system
	// temp directory just to hash it). The source is bounded to the declared
	// size for the transfer, the destination hashes exactly the bytes sent,
	// and one byte past the bound is probed afterwards so an over-long stream
	// is rejected rather than silently truncated.
	src := &byteCounter{r: r}
	h := sha256.New()
	body := io.TeeReader(io.LimitReader(src, size), h)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, body)
	if err != nil {
		return Object{}, err
	}
	req.ContentLength = size
	s.sign(req, s3UnsignedPayload, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		if src.count() < size {
			return Object{}, fmt.Errorf("blob: s3 put size mismatch: read %d bytes, expected %d: %w", src.count(), size, err)
		}
		return Object{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Object{}, fmt.Errorf("blob: s3 put %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if src.count() != size {
		return Object{}, fmt.Errorf("blob: s3 put size mismatch: read %d bytes, expected %d", src.count(), size)
	}
	// The endpoint only received `size` bytes. A source with more is a
	// declared-size violation and must fail closed.
	var extra [1]byte
	if n, _ := src.Read(extra[:]); n > 0 {
		return Object{}, fmt.Errorf("blob: s3 put size mismatch: stream longer than the declared %d bytes", size)
	}
	return Object{Key: key, SHA256: hex.EncodeToString(h.Sum(nil)), Size: size}, nil
}

// putMultipart uploads one oversized object with the S3 multipart protocol:
// create the upload for the same key the single PUT would use (no extra
// object headers, matching putSingle), upload each part sequentially at
// partNumber 1..n with exactly partSize bytes except the last, collect the
// ETags, and complete the upload with them. Every failure after a successful
// Create aborts the incomplete upload with a bounded best-effort request
// derived from the caller's context; an abort that fails too is joined into
// the returned error without masking the primary failure.
//
// A declared size that would need more than s3MaxMultipartParts parts is
// rejected before Create, so an impossible upload never starts. The
// configured part size is validated here (range and sign) before any
// request, so an invalid advanced configuration cannot create an upload it
// could never complete.
func (s *S3) putMultipart(ctx context.Context, key string, r io.Reader, size int64) (Object, error) {
	partSize, err := s.multipartPartSize()
	if err != nil {
		return Object{}, err
	}
	parts := s3MultipartPartCount(size, partSize)
	if parts > s3MaxMultipartParts {
		return Object{}, fmt.Errorf("%w: size %d needs %d parts of %d bytes, limit is %d",
			errS3MultipartPartsExceeded, size, parts, partSize, s3MaxMultipartParts)
	}
	rawURL, err := s.objectURL(key)
	if err != nil {
		return Object{}, err
	}
	uploadID, err := s.createMultipartUpload(ctx, rawURL)
	if err != nil {
		return Object{}, err
	}
	obj, err := s.streamMultipartParts(ctx, key, rawURL, uploadID, r, size, partSize, parts)
	if err == nil {
		return obj, nil
	}
	if abortErr := s.abortMultipartUpload(ctx, rawURL, uploadID); abortErr != nil {
		return Object{}, errors.Join(err, fmt.Errorf("%w: %w", errS3MultipartAbort, abortErr))
	}
	return Object{}, err
}

// s3MultipartPartCount returns how many parts a size of size bytes needs at
// partSize bytes per part (the last part may be smaller).
func s3MultipartPartCount(size, partSize int64) int64 {
	if size <= 0 {
		return 0
	}
	return 1 + (size-1)/partSize
}

// streamMultipartParts reads the source sequentially, hashing the exact bytes
// it buffers, and uploads one part per read. A part is fully buffered before
// it is sent, so the source is consumed exactly once even when a part upload
// is retried; the buffer is bounded by one part (64 MiB in production). The
// running SHA-256 over the streamed bytes is the returned object digest.
//
// If CompleteMultipartUpload fails at the transport level, a bounded HEAD
// disambiguates a lost response from a failed request: a visible object of
// exactly the declared size is the completed upload and is reported as
// success (with the streamed digest) instead of being aborted, while a missing
// or differently sized object returns the transport error for the caller to
// abort. A non-transport Complete error is returned as-is.
func (s *S3) streamMultipartParts(ctx context.Context, key, rawURL, uploadID string, r io.Reader, size, partSize, parts int64) (Object, error) {
	h := sha256.New()
	bufferSize := partSize
	if size < bufferSize {
		bufferSize = size
	}
	buf := make([]byte, bufferSize)
	collected := make([]s3CompletePart, 0, parts)
	remaining := size
	for part := int64(1); part <= parts; part++ {
		n := partSize
		if remaining < n {
			n = remaining
		}
		nRead, err := io.ReadFull(r, buf[:n])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return Object{}, fmt.Errorf("blob: s3 multipart size mismatch: stream ended after %d bytes, advertised %d",
					size-remaining+int64(nRead), size)
			}
			return Object{}, fmt.Errorf("blob: s3 multipart read part %d: %w", part, err)
		}
		h.Write(buf[:n])
		etag, err := s.uploadMultipartPart(ctx, rawURL, uploadID, int(part), buf[:n])
		if err != nil {
			return Object{}, err
		}
		collected = append(collected, s3CompletePart{PartNumber: int(part), ETag: etag})
		remaining -= n
	}
	// The endpoint received exactly size bytes. A source with more is a
	// declared-size violation and must fail closed, exactly like putSingle.
	var extra [1]byte
	if n, _ := r.Read(extra[:]); n > 0 {
		return Object{}, fmt.Errorf("blob: s3 multipart size mismatch: stream longer than the declared %d bytes", size)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if err := s.completeMultipartUpload(ctx, rawURL, uploadID, collected); err != nil {
		var lost *s3MultipartTransportError
		if !errors.As(err, &lost) {
			return Object{}, err
		}
		// The Complete request may have been executed although its response
		// was lost. A bounded HEAD decides: an object of exactly the declared
		// size is this completed upload and must NOT be aborted; anything
		// else returns the error so the caller aborts the incomplete upload.
		if stat, statErr := s.Stat(ctx, key); statErr == nil && stat.Size == size {
			return Object{Key: key, SHA256: digest, Size: size}, nil
		}
		return Object{}, err
	}
	return Object{Key: key, SHA256: digest, Size: size}, nil
}

// createMultipartUpload starts the upload and returns its upload ID. Like the
// single PUT it carries no extra object headers (Content-Type, tags), because
// putSingle sets none.
func (s *S3) createMultipartUpload(ctx context.Context, rawURL string) (string, error) {
	cctx, cancel := withDeadline(ctx, s3MultipartCreateTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("uploads", "")
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, rawURL+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.ContentLength = 0
	s.sign(req, emptyPayloadHash, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("blob: s3 multipart create: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("blob: s3 multipart create %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out s3InitiateMultipartUploadResult
	if err := xml.NewDecoder(io.LimitReader(resp.Body, s3MultipartResponseBytes)).Decode(&out); err != nil {
		return "", fmt.Errorf("blob: s3 multipart create decode: %w", err)
	}
	if out.UploadID == "" {
		return "", fmt.Errorf("blob: s3 multipart create: response carried no upload id")
	}
	return out.UploadID, nil
}

// uploadMultipartPart uploads one buffered part, retrying a retryable failure
// (transport error, 408/429 or 5xx status) at most once. The buffer is stable
// across attempts, so a retry sends the identical bytes and never re-reads
// the source.
func (s *S3) uploadMultipartPart(ctx context.Context, rawURL, uploadID string, part int, data []byte) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= s3MultipartPartAttempts; attempt++ {
		etag, retryable, err := s.uploadMultipartPartOnce(ctx, rawURL, uploadID, part, data)
		if err == nil {
			return etag, nil
		}
		lastErr = err
		if !retryable {
			break
		}
	}
	return "", fmt.Errorf("blob: s3 multipart part %d: %w", part, lastErr)
}

// uploadMultipartPartOnce performs one UploadPart attempt with its own
// bounded context. The buffered part is signed with its real SHA-256 payload
// hash (unlike the streamed single PUT, the bytes are already known).
func (s *S3) uploadMultipartPartOnce(ctx context.Context, rawURL, uploadID string, part int, data []byte) (string, bool, error) {
	pctx, cancel := withDeadline(ctx, s3MultipartPartTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("partNumber", strconv.Itoa(part))
	q.Set("uploadId", uploadID)
	sum := sha256.Sum256(data)
	req, err := http.NewRequestWithContext(pctx, http.MethodPut, rawURL+"?"+q.Encode(), bytes.NewReader(data))
	if err != nil {
		return "", false, err
	}
	req.ContentLength = int64(len(data))
	s.sign(req, hex.EncodeToString(sum[:]), time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return "", true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		etag := strings.TrimSpace(resp.Header.Get("ETag"))
		if etag == "" {
			return "", false, fmt.Errorf("blob: s3 multipart part %d: response carried no ETag", part)
		}
		return etag, false, nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return "", s3RetryableStatus(resp.StatusCode),
		fmt.Errorf("blob: s3 multipart part %d status %d: %s", part, resp.StatusCode, strings.TrimSpace(string(b)))
}

// s3RetryableStatus reports whether a part-upload status may succeed on a
// second attempt: request timeout, throttling, or a server-side error.
func s3RetryableStatus(code int) bool {
	switch {
	case code == http.StatusRequestTimeout, code == http.StatusTooManyRequests:
		return true
	case code >= 500 && code <= 599:
		return true
	default:
		return false
	}
}

// completeMultipartUpload finishes the upload with the collected part ETags.
// A transport-level failure is reported as *s3MultipartTransportError so the
// caller can attempt lost-response recovery; every other failure (a non-2xx
// status or an embedded <Error> in a 200 response) is a definitive S3 error.
func (s *S3) completeMultipartUpload(ctx context.Context, rawURL, uploadID string, parts []s3CompletePart) error {
	body, err := xml.Marshal(s3CompleteMultipartUpload{Parts: parts})
	if err != nil {
		return fmt.Errorf("blob: s3 multipart complete encode: %w", err)
	}
	sum := sha256.Sum256(body)
	cctx, cancel := withDeadline(ctx, s3MultipartCompleteTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("uploadId", uploadID)
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, rawURL+"?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/xml")
	s.sign(req, hex.EncodeToString(sum[:]), time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return &s3MultipartTransportError{err: fmt.Errorf("blob: s3 multipart complete: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("blob: s3 multipart complete %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, s3MultipartResponseBytes))
	if err != nil {
		return &s3MultipartTransportError{err: fmt.Errorf("blob: s3 multipart complete response: %w", err)}
	}
	var out s3CompleteMultipartUploadResult
	if len(bytes.TrimSpace(data)) > 0 {
		if err := xml.Unmarshal(data, &out); err == nil && out.Error != nil {
			return fmt.Errorf("blob: s3 multipart complete rejected: %s: %s", out.Error.Code, out.Error.Message)
		}
	}
	return nil
}

// abortMultipartUpload cleans up an incomplete upload with a bounded,
// best-effort request. The cleanup is deliberately detached from the caller's
// cancellation (context.WithoutCancel) so a cancelled Put still releases the
// upload's parts, but it keeps the caller's values.
func (s *S3) abortMultipartUpload(ctx context.Context, rawURL, uploadID string) error {
	actx, cancel := withDeadline(context.WithoutCancel(ctx), s3MultipartAbortTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("uploadId", uploadID)
	req, err := http.NewRequestWithContext(actx, http.MethodDelete, rawURL+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.ContentLength = 0
	s.sign(req, emptyPayloadHash, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("blob: s3 multipart abort %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// Open returns a stream for the object addressed by key. There is no
// Kiwi-imposed total duration for the transfer: the caller's context bounds
// the request, the default transport bounds the dial, TLS handshake and
// response-header phases, and the returned body is wrapped in a sliding
// inactivity watchdog (BodyInactivityTimeout; DefaultBodyInactivityTimeout
// when unset) that aborts a body which stops making progress. A body that
// keeps receiving bytes runs for exactly as long as it needs, no matter how
// large the object or how slow the link.
//
// The returned reader owns the request: the derived request context stays
// alive while the caller streams and is cancelled by the reader's Close, so
// Open must never cancel on the success path. Every failure path cancels
// immediately, so a failed Open never leaks a request context.
func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, Object, error) {
	if !keyRE.MatchString(key) {
		return nil, Object{}, fmt.Errorf("blob: invalid key %q", key)
	}
	reqCtx, cancel := context.WithCancel(ctx)
	rawURL, err := s.objectURL(key)
	if err != nil {
		cancel()
		return nil, Object{}, err
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		return nil, Object{}, err
	}
	s.sign(req, emptyPayloadHash, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		cancel()
		return nil, Object{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		cancel()
		return nil, Object{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		return nil, Object{}, fmt.Errorf("blob: s3 get %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	guard := newS3BodyGuard(cancel, s.bodyInactivityTimeout())
	return &s3GuardedBody{ReadCloser: resp.Body, guard: guard, parent: ctx, cancel: cancel},
		Object{Key: key, SHA256: key, Size: resp.ContentLength}, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if !keyRE.MatchString(key) {
		return fmt.Errorf("blob: invalid key %q", key)
	}
	ctx, cancel := withDeadline(ctx, s3DeleteTimeout)
	defer cancel()
	rawURL, err := s.objectURL(key)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, rawURL, nil)
	if err != nil {
		return err
	}
	s.sign(req, emptyPayloadHash, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("blob: s3 delete %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// listURL builds the bucket-level ListObjectsV2 URL for one page.
func (s *S3) listURL(continuationToken string) (string, error) {
	base, err := s.objectURL("")
	if err != nil {
		return "", err
	}
	base = strings.TrimSuffix(base, "/")
	q := url.Values{}
	q.Set("list-type", "2")
	q.Set("max-keys", strconv.Itoa(s3ListPageSize))
	if continuationToken != "" {
		q.Set("continuation-token", continuationToken)
	}
	return base + "?" + q.Encode(), nil
}

// List implements Enumerator with ListObjectsV2: it follows the
// continuation-token pagination until the endpoint reports the listing is
// complete, reporting each content-addressed object (bare digest keys and
// the two-level sha256/<xx>/<digest> layout) with its size and LastModified
// time. Non-digest keys, directory placeholders and bucket bookkeeping
// objects are skipped, so the CAS GC can never mistake them for payloads.
// The callback's error stops the walk and is returned unchanged; a truncated
// page without a continuation token is an error rather than a silent stop.
// The caller's context bounds the pass as a whole; each page request gets a
// fresh ListPageTimeout window of its own (see listPage), so a healthy but
// large enumeration is never cut by one shared deadline.
// maxS3ListPageBytes bounds one list-page response; maxS3ListKeys bounds the
// parsed key count independently of the body size (a defensive cap on the XML
// content itself).
const (
	maxS3ListPageBytes = 16 << 20
	maxS3ListKeys      = 100_000
	maxS3ListPages     = 10_000
)

// listPage fetches and parses one ListObjectsV2 page. The page request and
// its response body are bounded by a FRESH timeout derived from ctx
// (ListPageTimeout; DefaultListPageTimeout when unset), so one slow page
// fails page-locally instead of consuming a whole-pass budget, and the
// caller's context still bounds the enumeration as a whole. A caller
// cancellation is returned unchanged; a page timeout is reported with the
// page's window in the error.
func (s *S3) listPage(ctx context.Context, token string) (s3ListObjectsResult, error) {
	pageCtx, cancel := context.WithTimeout(ctx, s.listPageTimeout())
	defer cancel()
	rawURL, err := s.listURL(token)
	if err != nil {
		return s3ListObjectsResult{}, err
	}
	req, err := http.NewRequestWithContext(pageCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return s3ListObjectsResult{}, err
	}
	s.sign(req, emptyPayloadHash, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return s3ListObjectsResult{}, s.listPageError(ctx, err)
	}
	defer resp.Body.Close()
	// Read limit+1 so an over-limit response is DETECTED rather than
	// silently truncated into a parseable prefix.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxS3ListPageBytes+1))
	if readErr != nil {
		return s3ListObjectsResult{}, s.listPageError(ctx, readErr)
	}
	if int64(len(body)) > maxS3ListPageBytes {
		return s3ListObjectsResult{}, fmt.Errorf("blob: s3 list response exceeds %d bytes", int64(maxS3ListPageBytes))
	}
	if resp.StatusCode != http.StatusOK {
		return s3ListObjectsResult{}, fmt.Errorf("blob: s3 list %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var page s3ListObjectsResult
	if err := xml.Unmarshal(body, &page); err != nil {
		return s3ListObjectsResult{}, fmt.Errorf("blob: s3 list decode: %w", err)
	}
	if len(page.Contents) > maxS3ListKeys {
		return s3ListObjectsResult{}, fmt.Errorf("blob: s3 list page declares %d keys, limit is %d", len(page.Contents), maxS3ListKeys)
	}
	return page, nil
}

// listPageError classifies a failed page request. The caller's own context
// cancellation is returned unchanged (the Enumerator contract), while a page
// that hit its own fresh window is reported as a page-local timeout.
func (s *S3) listPageError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("blob: s3 list page exceeded %s: %w", s.listPageTimeout(), err)
	}
	return fmt.Errorf("blob: s3 list page: %w", err)
}

func (s *S3) List(ctx context.Context, fn func(Object) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	token := ""
	seenTokens := map[string]bool{}
	pages := 0
	for {
		page, err := s.listPage(ctx, token)
		if err != nil {
			return err
		}
		for _, entry := range page.Contents {
			digest, ok := s3DigestFromKey(entry.Key)
			if !ok {
				continue
			}
			if err := fn(Object{Key: digest, SHA256: digest, Size: entry.Size, ModTime: entry.LastModified}); err != nil {
				return err
			}
		}
		if !page.IsTruncated {
			return nil
		}
		if page.NextContinuationToken == "" {
			return fmt.Errorf("blob: s3 list truncated without a continuation token")
		}
		pages++
		if pages > maxS3ListPages {
			return fmt.Errorf("blob: s3 list exceeded %d pages", maxS3ListPages)
		}
		if seenTokens[page.NextContinuationToken] {
			return fmt.Errorf("blob: s3 list repeated a continuation token")
		}
		seenTokens[page.NextContinuationToken] = true
		token = page.NextContinuationToken
	}
}

// Stat issues a HeadObject request and reports size and Last-Modified.
func (s *S3) Stat(ctx context.Context, key string) (Object, error) {
	if err := s.validateKey(key); err != nil {
		return Object{}, err
	}
	ctx, cancel := withDeadline(ctx, 2*time.Minute)
	defer cancel()
	rawURL, err := s.objectURL(key)
	if err != nil {
		return Object{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return Object{}, err
	}
	s.sign(req, emptyPayloadHash, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Object{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Object{}, fmt.Errorf("blob: s3 stat %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	obj := Object{Key: key, SHA256: key, Size: resp.ContentLength}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, terr := http.ParseTime(lm); terr == nil {
			obj.ModTime = t
		}
	}
	return obj, nil
}

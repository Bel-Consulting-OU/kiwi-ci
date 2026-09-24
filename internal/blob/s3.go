package blob

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
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
	n int64
}

func (c *byteCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// s3RequestDeadlines bound requests whose caller context carries no
// deadline, so a stalled S3 endpoint can never hang a request forever.
const (
	s3PutTimeout    = 30 * time.Minute
	s3GetTimeout    = 2 * time.Minute
	s3DeleteTimeout = 2 * time.Minute
	s3ListTimeout   = 2 * time.Minute
)

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

// bodyWithCancel ties a response body to the request context that owns it.
// The bounded context must outlive Open: the caller streams the body after
// Open returns, so the context may only be released when the body is closed.
// Close closes the underlying body first (releasing the connection) and then
// cancels the request context exactly once, making repeated closes safe.
type bodyWithCancel struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (b *bodyWithCancel) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cancel)
	return err
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

	// endpointOnce caches the endpoint resolution: endpointURL is the parsed
	// endpoint and endpointErr is the sticky validation error.
	endpointOnce sync.Once
	endpointURL  *url.URL
	endpointErr  error
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

func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64) (Object, error) {
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
		if src.n < size {
			return Object{}, fmt.Errorf("blob: s3 put size mismatch: read %d bytes, expected %d: %w", src.n, size, err)
		}
		return Object{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Object{}, fmt.Errorf("blob: s3 put %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if src.n != size {
		return Object{}, fmt.Errorf("blob: s3 put size mismatch: read %d bytes, expected %d", src.n, size)
	}
	// The endpoint only received `size` bytes. A source with more is a
	// declared-size violation and must fail closed.
	var extra [1]byte
	if n, _ := src.Read(extra[:]); n > 0 {
		return Object{}, fmt.Errorf("blob: s3 put size mismatch: stream longer than the declared %d bytes", size)
	}
	return Object{Key: key, SHA256: hex.EncodeToString(h.Sum(nil)), Size: size}, nil
}

// Open returns a stream for the object addressed by key. The returned reader
// owns the request: the bounded request context stays alive while the caller
// streams and is cancelled by the reader's Close, so Open must never cancel
// on the success path. Every failure path cancels immediately, so a failed
// Open never leaks a request context.
func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, Object, error) {
	if !keyRE.MatchString(key) {
		return nil, Object{}, fmt.Errorf("blob: invalid key %q", key)
	}
	ctx, cancel := withDeadline(ctx, s3GetTimeout)
	rawURL, err := s.objectURL(key)
	if err != nil {
		cancel()
		return nil, Object{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
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
	return &bodyWithCancel{ReadCloser: resp.Body, cancel: cancel}, Object{Key: key, SHA256: key, Size: resp.ContentLength}, nil
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
func (s *S3) List(ctx context.Context, fn func(Object) error) error {
	ctx, cancel := withDeadline(ctx, s3ListTimeout)
	defer cancel()
	token := ""
	for {
		rawURL, err := s.listURL(token)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		s.sign(req, emptyPayloadHash, time.Now().UTC())
		resp, err := s.client().Do(req)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("blob: s3 list %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var page s3ListObjectsResult
		if err := xml.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("blob: s3 list decode: %w", err)
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
		token = page.NextContinuationToken
	}
}

// Stat issues a HeadObject request and reports size and Last-Modified.
func (s *S3) Stat(ctx context.Context, key string) (Object, error) {
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

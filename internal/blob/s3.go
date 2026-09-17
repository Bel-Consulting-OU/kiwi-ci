package blob

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

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

// Test-only seams over the temp-file seek and reopen used by Put. Production
// behavior is unchanged: the defaults are (*os.File).Seek and os.Open.
var (
	seekTemp        = (*os.File).Seek
	openTempForRead = func(name string) (io.ReadCloser, error) { return os.Open(name) }
)

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
type S3 struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Token           string
	PathStyle       bool
	Client          *http.Client
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

func (s *S3) objectURL(key string) string {
	if s.PathStyle {
		return strings.TrimRight(s.Endpoint, "/") + "/" + s.Bucket + "/" + strings.TrimPrefix(key, "/")
	}
	host := strings.Trim(strings.TrimPrefix(s.Endpoint, "https://"), "/")
	return "https://" + s.Bucket + "." + host + "/" + strings.TrimPrefix(key, "/")
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
	// Buffer to compute MD5 and SHA256 before sending; S3 PutObject requires
	// the body hash for SigV4. The read is bounded to size+1 so a stream
	// longer than the declared size is rejected instead of silently
	// uploaded; short streams fail the exact-size check below.
	tmp, err := os.CreateTemp("", "kiwi-s3-put-*")
	if err != nil {
		return Object{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	m := md5.New()
	n, err := io.Copy(io.MultiWriter(tmp, h, m), io.LimitReader(r, size+1))
	if err != nil {
		return Object{}, err
	}
	if n != size {
		return Object{}, fmt.Errorf("blob: s3 put size mismatch: wrote %d bytes, expected %d", n, size)
	}
	if _, err := seekTemp(tmp, 0, io.SeekStart); err != nil {
		return Object{}, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	// Re-read the temp file to compute the exact request body hash for SigV4.
	h2 := sha256.New()
	tmp2, err := openTempForRead(tmp.Name())
	if err != nil {
		return Object{}, err
	}
	if _, err := io.Copy(h2, tmp2); err != nil {
		tmp2.Close()
		return Object{}, err
	}
	tmp2.Close()
	bodyHash := hex.EncodeToString(h2.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.objectURL(key), tmp)
	if err != nil {
		return Object{}, err
	}
	req.ContentLength = n
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(m.Sum(nil)))
	s.sign(req, bodyHash, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Object{}, fmt.Errorf("blob: s3 put %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return Object{Key: key, SHA256: digest, Size: n}, nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key), nil)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.objectURL(key), nil)
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
func (s *S3) listURL(continuationToken string) string {
	base := strings.TrimSuffix(s.objectURL(""), "/")
	q := url.Values{}
	q.Set("list-type", "2")
	q.Set("max-keys", strconv.Itoa(s3ListPageSize))
	if continuationToken != "" {
		q.Set("continuation-token", continuationToken)
	}
	return base + "?" + q.Encode()
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
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.listURL(token), nil)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.objectURL(key), nil)
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

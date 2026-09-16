package blob

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// s3RequestDeadlines bound requests whose caller context carries no
// deadline, so a stalled S3 endpoint can never hang a request forever.
const (
	s3PutTimeout    = 30 * time.Minute
	s3GetTimeout    = 2 * time.Minute
	s3DeleteTimeout = 2 * time.Minute
)

// withDeadline returns ctx unchanged when it already has a deadline,
// otherwise a copy bounded by d. The returned cancel is a no-op in the
// former case.
func withDeadline(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
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
	return "https://" + s.Bucket + "." + strings.TrimLeft(strings.TrimPrefix(s.Endpoint, "https://"), "/") + "/" + strings.TrimPrefix(key, "/")
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
			qs = append(qs, url.QueryEscape(k)+"="+url.QueryEscape(v))
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
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return Object{}, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	// Re-read the temp file to compute the exact request body hash for SigV4.
	h2 := sha256.New()
	tmp2, err := os.Open(tmp.Name())
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

func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, Object, error) {
	ctx, cancel := withDeadline(ctx, s3GetTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key), nil)
	if err != nil {
		return nil, Object{}, err
	}
	s.sign(req, emptyPayloadHash, time.Now().UTC())
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, Object{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, Object{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, Object{}, fmt.Errorf("blob: s3 get %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.Body, Object{Key: key, SHA256: key, Size: resp.ContentLength}, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
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

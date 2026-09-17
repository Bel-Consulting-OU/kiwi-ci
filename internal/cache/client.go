package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Lease headers the job-scoped cache routes require. The control plane
// derives the repository and trust domain from the job itself, so those
// headers must never be sent.
const (
	HeaderRunnerID        = "X-Kiwi-Runner-ID"
	HeaderLeaseToken      = "X-Kiwi-Lease-Token"
	HeaderLeaseGeneration = "X-Kiwi-Lease-Generation"
	// HeaderCacheSHA256 is set by the server on GET responses: the hex
	// SHA-256 digest of the archive bytes. Responses without it skip
	// digest verification.
	HeaderCacheSHA256 = "X-Kiwi-Cache-SHA256"
)

// ErrRemoteNotFound is returned by Client.Restore when the server has no entry
// for the key.
var ErrRemoteNotFound = fmt.Errorf("cache: not found on remote")

// defaultMaxCompressedBytes bounds a restore download when no explicit limit
// is configured (4 GiB, matching the extraction limits).
const defaultMaxCompressedBytes = 4 << 30

// Client is the runner-side cache client targeting the job-scoped cache
// routes: GET/PUT /api/v1/jobs/{jobID}/cache/{key}. Credentials and lease
// headers are attached only to these requests and redirects are never
// followed. Restore streams are bounded by MaxCompressedBytes and verified
// against the server-provided digest.
type Client struct {
	Server string
	Token  string
	HTTP   *http.Client
	// MaxCompressedBytes bounds a restore stream (0 uses the 4 GiB default).
	MaxCompressedBytes int64
	// Logf, when set, receives debug diagnostics such as a missing digest
	// header.
	Logf func(format string, args ...any)
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		cl := *c.HTTP
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &cl
	}
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *Client) auth(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

// applyLeaseHeaders attaches the lease contract headers from the map. Only
// the three runner-tier lease headers are honored.
func (c *Client) applyLeaseHeaders(req *http.Request, leaseHeaders map[string]string) {
	for _, h := range []string{HeaderRunnerID, HeaderLeaseToken, HeaderLeaseGeneration} {
		if v := leaseHeaders[h]; v != "" {
			req.Header.Set(h, v)
		}
	}
}

// cacheURL builds the job-scoped cache route for a key.
func (c *Client) cacheURL(jobID, key string) string {
	return c.Server + "/api/v1/jobs/" + url.PathEscape(jobID) + "/cache/" + url.PathEscape(key)
}

// Restore downloads the cache archive for key from the job-scoped route and
// returns a bounded, digest-verified stream. The stream rejects reads beyond
// MaxCompressedBytes and, when the server provided X-Kiwi-Cache-SHA256,
// hashes the bytes while they are read and errors on mismatch at EOF.
func (c *Client) Restore(ctx context.Context, jobID string, leaseHeaders map[string]string, key string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cacheURL(jobID, key), nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)
	c.applyLeaseHeaders(req, leaseHeaders)
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrRemoteNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("cache restore %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	body := resp.Body
	digest := strings.TrimSpace(resp.Header.Get(HeaderCacheSHA256))
	if digest == "" {
		if c.Logf != nil {
			c.Logf("cache restore %s: server sent no %s header; skipping digest verification", key, HeaderCacheSHA256)
		}
	} else {
		body = &verifyingReadCloser{r: resp.Body, want: digest, h: sha256.New()}
	}
	return &boundedReadCloser{ReadCloser: body, max: c.maxCompressedBytes()}, nil
}

// Upload stores the cache archive at the job-scoped route for key.
func (c *Client) Upload(ctx context.Context, jobID string, leaseHeaders map[string]string, key string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.cacheURL(jobID, key), r)
	if err != nil {
		return err
	}
	c.auth(req)
	c.applyLeaseHeaders(req, leaseHeaders)
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("cache upload %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *Client) maxCompressedBytes() int64 {
	if c.MaxCompressedBytes > 0 {
		return c.MaxCompressedBytes
	}
	return defaultMaxCompressedBytes
}

// boundedReadCloser fails reads once the stream exceeds max bytes. The limit
// applies to the compressed bytes on the wire, so a hostile server cannot
// make the runner stream unbounded.
type boundedReadCloser struct {
	io.ReadCloser
	n   int64
	max int64
}

func (b *boundedReadCloser) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	if b.n > b.max {
		return 0, fmt.Errorf("cache restore exceeds %d compressed bytes", b.max)
	}
	return n, err
}

// verifyingReadCloser hashes the stream while it is read and rejects a
// digest mismatch when the stream ends. A mismatch is latched: every later
// Read and Close reports it instead of falling back to io.EOF or nil.
type verifyingReadCloser struct {
	r    io.ReadCloser
	want string
	h    hash.Hash
	done bool
	err  error
}

func (v *verifyingReadCloser) Read(p []byte) (int, error) {
	if v.err != nil {
		return 0, v.err
	}
	n, err := v.r.Read(p)
	if n > 0 {
		v.h.Write(p[:n])
	}
	if err == io.EOF && !v.done {
		v.done = true
		if got := hex.EncodeToString(v.h.Sum(nil)); got != v.want {
			v.err = fmt.Errorf("cache restore digest mismatch: got %s, want %s", got, v.want)
			return n, v.err
		}
	}
	return n, err
}

func (v *verifyingReadCloser) Close() error {
	closeErr := v.r.Close()
	if v.err != nil {
		return v.err
	}
	return closeErr
}

package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// cacheRoutePrefix is the legacy route shape the local cache.Store builds
// from its RemoteURL. The runner's transport rewrites those requests onto
// the job-scoped control-plane routes and attaches the lease contract.
const cacheRoutePrefix = "/api/v1/cache/"

// cacheTransport adapts the local cache.Store's remote requests to the
// job-scoped cache API: /api/v1/cache/{key} GET/PUT becomes
// /api/v1/jobs/{jobID}/cache/{key} with the runner lease headers. The
// control plane derives the repository and trust domain from the job, so
// the former X-Kiwi-Repository/X-Kiwi-Trust-Domain headers are gone
// entirely. Downloads are bounded and digest-verified inside cache.Client
// and disk availability is checked before a download starts.
type cacheTransport struct {
	client  *cache.Client
	jobID   string
	lease   map[string]string
	root    string
	maxDisk int64
	metrics *Metrics
}

func (t *cacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.Path, cacheRoutePrefix) {
		return t.passthrough(req)
	}
	key := strings.TrimPrefix(req.URL.Path, cacheRoutePrefix)
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	switch req.Method {
	case http.MethodGet:
		if err := safefs.FitsAvailable(t.root, t.maxDisk); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("cache download preflight: %w", err)
		}
		// The restore stream carries no total timeout; the sliding guard
		// cancels the transfer when the peer stops sending bytes.
		guardCtx, cancel := context.WithCancel(ctx)
		guard := newStallGuard(cancel, streamIdleTimeout)
		rc, err := t.client.Restore(guardCtx, t.jobID, t.lease, key)
		if errors.Is(err, cache.ErrRemoteNotFound) {
			guard.stop()
			cancel()
			if t.metrics != nil {
				t.metrics.Counter("kiwi_runner_cache_misses", 1)
			}
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: http.NoBody, Header: http.Header{}, Request: req}, nil
		}
		if err != nil {
			guard.stop()
			cancel()
			return nil, err
		}
		if t.metrics != nil {
			t.metrics.Counter("kiwi_runner_cache_hits", 1)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: &stallGuardedBody{ReadCloser: rc, guard: guard, cancel: cancel}, Header: http.Header{}, Request: req}, nil
	case http.MethodPut:
		guardCtx, cancel := context.WithCancel(ctx)
		guard := newStallGuard(cancel, streamIdleTimeout)
		var body io.Reader = req.Body
		if body != nil {
			body = &stallGuardReader{r: body, guard: guard}
		}
		if err := t.client.Upload(guardCtx, t.jobID, t.lease, key, body); err != nil {
			guard.stop()
			cancel()
			return nil, err
		}
		guard.stop()
		cancel()
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: http.NoBody, Header: http.Header{}, Request: req}, nil
	default:
		return t.passthrough(req)
	}
}

// passthrough forwards non-cache requests on the runner's transport. It
// exists only for safety: the store's client only issues cache requests.
func (t *cacheTransport) passthrough(req *http.Request) (*http.Response, error) {
	if t.client != nil && t.client.HTTP != nil && t.client.HTTP.Transport != nil {
		return t.client.HTTP.Transport.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// newJobCache builds the executor's cache store for one job: local
// content-addressed storage whose remote fallback targets the job-scoped
// control-plane cache routes with the runner's lease contract headers.
func (r *Runner) newJobCache(t server.Task, metrics *Metrics) *cache.Store {
	store := cache.Default()
	if r.Cfg.CacheRoot != "" {
		store.Root = filepath.Join(r.Cfg.CacheRoot, "cache")
	}
	store.RemoteURL = r.Cfg.Server
	store.Token = r.Cfg.Token
	// Cache traffic is bulk streaming traffic: it runs on the streaming
	// client's transport with NO total timeout (an 8 GiB cache archive at any
	// sustainable rate must complete). The per-request stall guard added in
	// RoundTrip bounds inactivity instead. A runner built without an explicit
	// StreamClient (tests) falls back to the control client and inherits its
	// total timeout, preserving the historical bounded behavior.
	stream := r.streamClient()
	transport := http.RoundTripper(http.DefaultTransport)
	var timeout time.Duration
	if stream != nil {
		if stream.Transport != nil {
			transport = stream.Transport
		}
		timeout = stream.Timeout
	}
	client := &cache.Client{
		Server: r.Cfg.Server,
		Token:  r.Cfg.Token,
		HTTP: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Logf: func(format string, args ...any) {
			fmt.Printf("kiwi runner %s: cache: "+format+"\n", append([]any{r.ID}, args...)...)
		},
	}
	store.Client = &http.Client{
		Timeout: timeout,
		Transport: &cacheTransport{
			client: client,
			jobID:  t.Job.ID,
			lease: map[string]string{
				cache.HeaderRunnerID:        r.ID,
				cache.HeaderLeaseToken:      t.LeaseToken,
				cache.HeaderLeaseGeneration: fmt.Sprint(t.LeaseGeneration),
			},
			root:    store.Root,
			maxDisk: store.MaxCacheBytes,
			metrics: metrics,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return store
}

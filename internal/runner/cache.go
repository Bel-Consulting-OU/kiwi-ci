package runner

import (
	"context"
	"errors"
	"fmt"
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
		rc, err := t.client.Restore(ctx, t.jobID, t.lease, key)
		if errors.Is(err, cache.ErrRemoteNotFound) {
			if t.metrics != nil {
				t.metrics.Counter("kiwi_runner_cache_misses", 1)
			}
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: http.NoBody, Header: http.Header{}, Request: req}, nil
		}
		if err != nil {
			return nil, err
		}
		if t.metrics != nil {
			t.metrics.Counter("kiwi_runner_cache_hits", 1)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: rc, Header: http.Header{}, Request: req}, nil
	case http.MethodPut:
		if err := t.client.Upload(ctx, t.jobID, t.lease, key, req.Body); err != nil {
			return nil, err
		}
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
	timeout := time.Duration(65 * time.Second)
	transport := http.RoundTripper(http.DefaultTransport)
	if r.Client != nil {
		if r.Client.Transport != nil {
			transport = r.Client.Transport
		}
		if r.Client.Timeout > 0 {
			timeout = r.Client.Timeout
		}
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

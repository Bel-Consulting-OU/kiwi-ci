package runner

import (
	"net/http"
	"path/filepath"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
)

// cacheTransport injects the repository/trust-domain contract headers the
// control plane requires on cache PUT/GET (used for cache manifest signing)
// and counts remote cache hits/misses. The cache package is not
// runner-owned, so the runner carries the headers on the HTTP layer instead
// of changing cache.Store.
type cacheTransport struct {
	base    http.RoundTripper
	headers http.Header
	metrics *Metrics
}

func (t *cacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	for k, vv := range t.headers {
		for _, v := range vv {
			r2.Header.Add(k, v)
		}
	}
	resp, err := t.base.RoundTrip(r2)
	if err != nil {
		return resp, err
	}
	if t.metrics != nil && req.Method == http.MethodGet && len(req.URL.Path) > len("/api/v1/cache/") && req.URL.Path[:len("/api/v1/cache/")] == "/api/v1/cache/" {
		switch resp.StatusCode {
		case http.StatusOK:
			t.metrics.Counter("kiwi_runner_cache_hits", 1)
		case http.StatusNotFound:
			t.metrics.Counter("kiwi_runner_cache_misses", 1)
		}
	}
	return resp, err
}

// newJobCache builds the executor's cache store for one job: local
// content-addressed storage backed by the control plane's cache endpoints,
// with the repository/trust-domain contract headers the server requires for
// manifest signing. Repository is the job's RepoURL (model.Job carries no
// separate full name; documented runner-side approximation).
func (r *Runner) newJobCache(repoURL string, trusted bool, metrics *Metrics) *cache.Store {
	store := cache.Default()
	if r.Cfg.CacheRoot != "" {
		store.Root = filepath.Join(r.Cfg.CacheRoot, "cache")
	}
	store.RemoteURL = r.Cfg.Server
	store.Token = r.Cfg.Token
	trust := "untrusted"
	if trusted {
		trust = "trusted"
	}
	headers := http.Header{}
	headers.Set("X-Kiwi-Repository", repoURL)
	headers.Set("X-Kiwi-Trust-Domain", trust)
	base := http.DefaultTransport
	if r.Client != nil && r.Client.Transport != nil {
		base = r.Client.Transport
	}
	timeout := time.Duration(65 * time.Second)
	if r.Client != nil {
		timeout = r.Client.Timeout
	}
	store.Client = &http.Client{
		Timeout:   timeout,
		Transport: &cacheTransport{base: base, headers: headers, metrics: metrics},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return store
}

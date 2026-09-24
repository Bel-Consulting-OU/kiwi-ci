package forge

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// App is a GitHub App installation credential provider. It authenticates
// API calls with short-lived installation access tokens minted from an
// RS256-signed JWT, cached per repository until shortly before expiry.
type App struct {
	AppID      int64
	PrivateKey []byte
	Client     *http.Client
	// BaseURL is the API base (default https://api.github.com). Exposed for
	// tests; production deployments use the default.
	BaseURL string

	mu       sync.Mutex
	cache    map[string]cachedInstallationToken // keyed by repoFullName
	inFlight map[string]*installTokenFlight
}

type cachedInstallationToken struct {
	token     string
	expiresAt time.Time
}

// maxCachedInstallationTokens bounds the per-repository installation-token
// cache. Expired entries are always dropped on access; if the cap is still
// exceeded (a burst of distinct repositories), the soonest-expiring entries
// are evicted so the cache cannot grow without bound.
const maxCachedInstallationTokens = 1024

// pruneCacheLocked drops expired tokens and, while the cache is over the cap,
// evicts the soonest-expiring entries. The caller holds a.mu.
func (a *App) pruneCacheLocked(now time.Time) {
	for k, c := range a.cache {
		if !c.expiresAt.After(now) {
			delete(a.cache, k)
		}
	}
	for len(a.cache) > maxCachedInstallationTokens {
		var victim string
		var victimExp time.Time
		first := true
		for k, c := range a.cache {
			if first || c.expiresAt.Before(victimExp) {
				victim, victimExp, first = k, c.expiresAt, false
			}
		}
		if first {
			break
		}
		delete(a.cache, victim)
	}
}

type installTokenFlight struct {
	done chan struct{}
	tok  string
	exp  time.Time
	err  error
}

func NewApp(appID int64, privateKey []byte) *App {
	return &App{AppID: appID, PrivateKey: privateKey, cache: map[string]cachedInstallationToken{}, inFlight: map[string]*installTokenFlight{}}
}

func (a *App) apiBase() string {
	if a.BaseURL != "" {
		return strings.TrimRight(a.BaseURL, "/")
	}
	return defaultGitHubAPI
}

func (a *App) httpClient() *http.Client {
	if a.Client != nil {
		return NoRedirectClient(a.Client)
	}
	return NoRedirectClient(&http.Client{Timeout: 20 * time.Second})
}

// signKey parses an RSA private key in PKCS#1 or PKCS#8 PEM form.
func (a *App) signKey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(a.PrivateKey)
	if block == nil {
		return nil, fmt.Errorf("app private key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse app private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("app private key is not RSA")
	}
	return key, nil
}

// jwt builds an RS256 JWT for the App: iss=AppID, iat now-60s, exp now+10m.
func (a *App) jwt(now time.Time) (string, error) {
	key, err := a.signKey()
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": strconv.FormatInt(a.AppID, 10),
	})
	if err != nil {
		return "", err
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (a *App) doAppRequest(ctx context.Context, method, path string) (*http.Response, error) {
	token, err := a.jwt(time.Now())
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, a.apiBase()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	return a.httpClient().Do(req)
}

// InstallationToken mints an installation access token for the given
// installation. The token expires in one hour.
func (a *App) InstallationToken(ctx context.Context, installationID int64) (string, time.Time, error) {
	resp, err := a.doAppRequest(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", installationID))
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", time.Time{}, fmt.Errorf("GitHub App token API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var v struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", time.Time{}, err
	}
	if v.Token == "" {
		return "", time.Time{}, fmt.Errorf("GitHub App token API returned no token")
	}
	return v.Token, v.ExpiresAt, nil
}

// LookupInstallation resolves the installation ID that can access a
// repository.
func (a *App) LookupInstallation(ctx context.Context, repoFullName string) (int64, error) {
	resp, err := a.doAppRequest(ctx, http.MethodGet, "/repos/"+repoFullName+"/installation")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("GitHub App installation API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var v struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return 0, err
	}
	if v.ID == 0 {
		return 0, fmt.Errorf("GitHub App installation API returned no id")
	}
	return v.ID, nil
}

// TokenFor returns a valid installation token for the repository, caching
// until five minutes before expiry. Concurrent callers share one token
// fetch (single-flight) so a burst of jobs does not hammer the token API.
func (a *App) TokenFor(ctx context.Context, repoFullName string) (string, error) {
	if repoFullName == "" {
		return "", fmt.Errorf("repoFullName required for installation token")
	}
	now := time.Now()
	floor := now.Add(5 * time.Minute)
	a.mu.Lock()
	a.pruneCacheLocked(now)
	if c, ok := a.cache[repoFullName]; ok && c.expiresAt.After(floor) {
		a.mu.Unlock()
		return c.token, nil
	}
	if f, ok := a.inFlight[repoFullName]; ok {
		ch := f.done
		a.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ch:
			if f.err != nil {
				return "", f.err
			}
			return f.tok, nil
		}
	}
	f := &installTokenFlight{done: make(chan struct{})}
	a.inFlight[repoFullName] = f
	a.mu.Unlock()
	installationID, err := a.LookupInstallation(ctx, repoFullName)
	var token string
	var expires time.Time
	if err == nil {
		token, expires, err = a.InstallationToken(ctx, installationID)
	}
	a.mu.Lock()
	if err == nil && token != "" {
		a.cache[repoFullName] = cachedInstallationToken{token: token, expiresAt: expires}
		a.pruneCacheLocked(time.Now())
	}
	f.tok, f.exp, f.err = token, expires, err
	delete(a.inFlight, repoFullName)
	close(f.done)
	a.mu.Unlock()
	if err != nil {
		return "", err
	}
	return token, nil
}

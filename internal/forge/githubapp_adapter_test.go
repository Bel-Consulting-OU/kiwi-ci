package forge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestGitHubAppAdapterFetchFile exercises the full adapter path: the
// GitHub forge adapter authenticated by an App mints an installation token
// from the fake API server and uses it on the contents request.
func TestGitHubAppAdapterFetchFile(t *testing.T) {
	_, pemBytes := testAppKey(t)
	var contentsAuth atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 7})
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "install-token", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		case strings.Contains(r.URL.Path, "/contents/"):
			contentsAuth.Store(r.Header.Get("Authorization"))
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte("version: 1\njobs: {}\n")),
				"encoding": "base64",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	app := NewApp(99, pemBytes)
	app.BaseURL = ts.URL
	g := &GitHub{App: app, BaseURL: ts.URL}
	content, err := g.FetchFile(context.Background(), "octocat/hello-world", ".kiwi/pipeline.yaml", "main")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "version: 1") {
		t.Fatalf("content = %q", content)
	}
	if got, _ := contentsAuth.Load().(string); got != "Bearer install-token" {
		t.Fatalf("contents request Authorization = %q, want installation token", got)
	}
}

// TestGitHubAppAdapterTokenFallback verifies the plain token wins over the
// App when both are configured (the explicit token is authoritative).
func TestGitHubAppAdapterTokenFallback(t *testing.T) {
	g := &GitHub{Token: "pat-token", App: &App{}}
	tok, err := g.TokenFor(context.Background(), "octocat/hello-world")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "pat-token" {
		t.Fatalf("token = %q, want pat-token", tok)
	}
}

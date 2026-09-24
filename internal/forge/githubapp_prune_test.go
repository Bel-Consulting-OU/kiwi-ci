package forge

import (
	"fmt"
	"testing"
	"time"
)

// TestAppTokenCachePrunesExpiredAndBounds is the G2-G githubapp regression:
// the installation-token cache drops expired entries and evicts
// soonest-expiring entries under a hard cap.
func TestAppTokenCachePrunesExpiredAndBounds(t *testing.T) {
	app := NewApp(1, nil)
	now := time.Now()
	app.mu.Lock()
	app.cache["expired"] = cachedInstallationToken{token: "x", expiresAt: now.Add(-time.Minute)}
	for i := 0; i < maxCachedInstallationTokens+20; i++ {
		app.cache[fmt.Sprintf("r%05d", i)] = cachedInstallationToken{token: "t", expiresAt: now.Add(time.Hour)}
	}
	app.pruneCacheLocked(now)
	app.mu.Unlock()
	if len(app.cache) > maxCachedInstallationTokens {
		t.Fatalf("token cache has %d entries, want <= %d", len(app.cache), maxCachedInstallationTokens)
	}
	if _, ok := app.cache["expired"]; ok {
		t.Fatal("expired token survived pruning")
	}
}

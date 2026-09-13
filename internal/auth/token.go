package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// TokenStore maps token digests to principals. Raw tokens are never stored:
// only the hex-encoded SHA-256 digest of a token is kept in memory and
// persisted to disk.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]Principal
}

func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: map[string]Principal{}}
}

// TokenDigest returns the hex-encoded SHA-256 of a raw token.
func TokenDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// AddToken registers raw with principal, keyed by the token digest.
func (t *TokenStore) AddToken(raw string, p Principal) error {
	if raw == "" {
		return fmt.Errorf("auth: token must not be empty")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tokens == nil {
		t.tokens = map[string]Principal{}
	}
	t.tokens[TokenDigest(raw)] = p
	return nil
}

// Authenticate resolves raw to its principal.
func (t *TokenStore) Authenticate(raw string) (Principal, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.tokens[TokenDigest(raw)]
	return p, ok
}

// Empty reports whether no tokens are configured.
func (t *TokenStore) Empty() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.tokens) == 0
}

// Load replaces the store contents with the JSON token file at path
// (map of token digest to principal).
func (t *TokenStore) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m := map[string]Principal{}
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("auth: parse token file %s: %w", path, err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens = m
	return nil
}

// Save atomically writes the store as a 0600 JSON file of token digests to
// principals, creating the parent directory (0700) if needed.
func (t *TokenStore) Save(path string) error {
	t.mu.RLock()
	m := make(map[string]Principal, len(t.tokens))
	for k, v := range t.tokens {
		m[k] = v
	}
	t.mu.RUnlock()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

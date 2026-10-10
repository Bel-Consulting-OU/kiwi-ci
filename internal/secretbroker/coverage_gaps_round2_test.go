package secretbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestParseFallbackOnMatrix pins the configuration contract: nil keeps the
// caller's default, empty means never fall back, only not_found/unavailable
// are accepted, entries are trimmed and deduplicated, and authorization/
// policy classes are refused outright.
func TestParseFallbackOnMatrix(t *testing.T) {
	if got, err := ParseFallbackOn(nil); err != nil || got != nil {
		t.Fatalf("nil = %v/%v, want nil/nil", got, err)
	}
	if got, err := ParseFallbackOn([]string{}); err != nil || len(got) != 0 {
		t.Fatalf("empty = %v/%v, want empty/nil", got, err)
	}
	got, err := ParseFallbackOn([]string{" unavailable ", "not_found", "not_found"})
	if err != nil {
		t.Fatalf("valid entries: %v", err)
	}
	if len(got) != 2 || got[0] != FallbackClassUnavailable || got[1] != FallbackClassNotFound {
		t.Fatalf("normalized = %v", got)
	}
	for _, bad := range []string{ClassUnauthorized, ClassForbidden, ClassMalformed, ClassUnknown, ""} {
		if _, err := ParseFallbackOn([]string{bad}); err == nil || !strings.Contains(err.Error(), "only") {
			t.Fatalf("ParseFallbackOn(%q) = %v, want the policy refusal", bad, err)
		}
	}
}

// TestProviderErrorAndClassHelpers covers the empty error rendering, the nil
// ErrorClass, the OAuth access_denied arm and the AWS header separator split.
func TestProviderErrorAndClassHelpers(t *testing.T) {
	if got := (&ProviderError{}).Error(); got != "secretbroker: provider error" {
		t.Fatalf("empty ProviderError = %q", got)
	}
	if got := ErrorClass(nil); got != "" {
		t.Fatalf("ErrorClass(nil) = %q, want empty", got)
	}
	if got := oauthErrorClass("access_denied", http.StatusOK); !errors.Is(got, ErrForbidden) {
		t.Fatalf("oauthErrorClass(access_denied) = %v, want forbidden", got)
	}

	resp := &http.Response{Header: http.Header{"X-Amzn-Errortype": []string{"com.example#AccessDeniedException;extra"}}}
	if got := awsErrorCode(resp, nil); got != "AccessDeniedException" {
		t.Fatalf("awsErrorCode = %q, want the namespace-stripped code", got)
	}
	if got := awsErrorCode(&http.Response{Header: http.Header{}}, []byte(`{"__type":"ResourceNotFoundException"}`)); got != "ResourceNotFoundException" {
		t.Fatalf("awsErrorCode body = %q", got)
	}
}

// TestBrokerNameEveryProvider pins the diagnostics naming for every known
// provider and the Go-type fallback.
func TestBrokerNameEveryProvider(t *testing.T) {
	cases := []struct {
		broker Broker
		want   string
	}{
		{&VaultClient{}, "vault"},
		{&SecretsManagerClient{}, "aws"},
		{&GCPClient{}, "gcp"},
		{&AzureClient{}, "azure"},
		{&OnePasswordClient{}, "onepassword"},
		{StaticBroker{}, "static"},
		{&OneTime{}, "onetime"},
		{ChainBroker{}, "chain"},
		{unknownBroker{}, "secretbroker.unknownBroker"},
	}
	for _, tc := range cases {
		if got := brokerName(tc.broker); got != tc.want {
			t.Errorf("brokerName(%T) = %q, want %q", tc.broker, got, tc.want)
		}
	}
}

type unknownBroker struct{}

func (unknownBroker) Resolve(context.Context, string, SecretScope) (string, error) { return "", nil }

// TestFirstVaultValueEmptyObject covers an object with no entries: it carries
// no data, so decoding must fail rather than yield an empty secret.
func TestFirstVaultValueEmptyObject(t *testing.T) {
	if _, err := firstVaultValue(json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "no data") {
		t.Fatalf("empty vault data = %v, want the no-data error", err)
	}
}

// TestRemoteEphemeralKeyCacheEviction proves the bounded retry cache evicts
// the oldest key pair (FIFO by keyOrder) when full and purges entries from a
// previous lease generation before minting.
func TestRemoteEphemeralKeyCacheEviction(t *testing.T) {
	p := &RemoteProvider{JobID: "job", LeaseGeneration: 7}
	fill := func(generation int64) {
		p.keyMu.Lock()
		defer p.keyMu.Unlock()
		if p.keys == nil {
			p.keys = map[string]cachedRemoteKey{}
		}
		for i := 0; i < remoteKeyCacheMax; i++ {
			name := fmt.Sprintf("s%02d", i)
			key := p.keyCacheKey(name)
			priv, err := generateX25519Key()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			p.keys[key] = cachedRemoteKey{priv: priv, generation: generation}
			p.keyOrder = append(p.keyOrder, key)
		}
	}
	fill(p.LeaseGeneration)

	if _, err := p.cachedEphemeralKey("fresh"); err != nil {
		t.Fatalf("cachedEphemeralKey: %v", err)
	}
	if len(p.keys) != remoteKeyCacheMax {
		t.Fatalf("cache size = %d, want the bound %d", len(p.keys), remoteKeyCacheMax)
	}
	if _, ok := p.keys[p.keyCacheKey("s00")]; ok {
		t.Fatal("oldest key was not evicted")
	}
	if _, ok := p.keys[p.keyCacheKey("fresh")]; !ok {
		t.Fatal("fresh key was not cached")
	}

	// A new lease generation drops every previous-generation entry, even a
	// freshly cached one.
	p.LeaseGeneration = 8
	if _, err := p.cachedEphemeralKey("fresh"); err != nil {
		t.Fatalf("cachedEphemeralKey(generation 8): %v", err)
	}
	for key, entry := range p.keys {
		if entry.generation != 8 {
			t.Fatalf("stale generation entry %q survived", key)
		}
	}
}

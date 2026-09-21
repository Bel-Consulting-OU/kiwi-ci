package components

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// remoteRef computes the digest-pinned ref the server's spec resolves to.
func remoteRef(t *testing.T, spec Spec) string {
	t.Helper()
	digest, err := Digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	return spec.Name + "@sha256:" + digest
}

// serveRemoteSpec starts a TLS registry that answers every /components/
// request with body.
func serveRemoteSpec(t *testing.T, body []byte) (*RemoteRegistry, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/components/") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)
	reg, err := NewRemoteRegistry(ts.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	reg.Client = ts.Client()
	return reg, ts.URL
}

func TestRemoteRegistryOversizeBodyWithValidJSONPrefixRejected(t *testing.T) {
	spec := Spec{Name: "build", Version: "v1"}
	ref := remoteRef(t, spec)
	prefix, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	// The response starts with a complete, valid JSON document and is then
	// padded past the bound. The bound check must fire before decoding, so
	// the error names the limit instead of a JSON syntax error.
	body := make([]byte, 0, len(prefix)+maxRegistryResponseBytes+1)
	body = append(body, prefix...)
	body = append(body, strings.Repeat("x", maxRegistryResponseBytes+1)...)
	reg, _ := serveRemoteSpec(t, body)
	_, _, err = reg.Resolve(context.Background(), ref)
	if err == nil {
		t.Fatal("oversized registry response must be rejected even with a valid JSON prefix")
	}
	if !strings.Contains(err.Error(), "exceeds") || !strings.Contains(err.Error(), strconv.Itoa(maxRegistryResponseBytes)) {
		t.Fatalf("oversize error must name the %d-byte bound, got %v", maxRegistryResponseBytes, err)
	}
}

func TestRemoteRegistryExactlyAtLimitAccepted(t *testing.T) {
	// A body of exactly maxRegistryResponseBytes bytes is valid JSON and must
	// resolve: the bound rejects only strictly larger responses.
	head := `{"name":"build","version":"`
	tail := `","steps":[{"run":"echo hi"}]}`
	pad := maxRegistryResponseBytes - len(head) - len(tail)
	if pad <= 0 {
		t.Fatalf("template too large for the %d-byte bound", maxRegistryResponseBytes)
	}
	body := []byte(head + strings.Repeat("v", pad) + tail)
	if len(body) != maxRegistryResponseBytes {
		t.Fatalf("test body = %d bytes, want %d", len(body), maxRegistryResponseBytes)
	}
	var spec Spec
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatal(err)
	}
	wantDigest, err := Digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := serveRemoteSpec(t, body)
	got, digest, err := reg.Resolve(context.Background(), "build@sha256:"+wantDigest)
	if err != nil {
		t.Fatalf("exactly-at-limit body rejected: %v", err)
	}
	if got.Name != "build" || digest != wantDigest {
		t.Fatalf("resolve name = %q, digest = %q, want build/%s", got.Name, digest, wantDigest)
	}
}

func TestRemoteRegistryTrailingMaterialRejected(t *testing.T) {
	spec := Spec{Name: "build", Version: "v1"}
	ref := remoteRef(t, spec)
	prefix, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	for name, trailing := range map[string]string{
		"garbage":              `}`,
		"second JSON value":    `{"name":"evil"}`,
		"whitespace + garbage": "  \n\tnot json",
		"encoded second value": `null`,
	} {
		t.Run(name, func(t *testing.T) {
			body := append(append([]byte{}, prefix...), []byte(trailing)...)
			if len(body) > maxRegistryResponseBytes {
				t.Fatalf("test body unexpectedly oversize: %d", len(body))
			}
			reg, _ := serveRemoteSpec(t, body)
			if _, _, err := reg.Resolve(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "decode") {
				t.Fatalf("trailing %q accepted: %v", trailing, err)
			}
		})
	}
}

func TestRemoteRegistryHardensCustomClientAndRedirects(t *testing.T) {
	var followed atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/components/") {
			http.Redirect(w, r, "/followed", http.StatusFound)
			return
		}
		followed.Add(1)
		_ = json.NewEncoder(w).Encode(Spec{Name: "build"})
	}))
	defer ts.Close()

	// The custom client has no timeout and the default redirect policy, so
	// without hardening it would both hang forever and follow the 3xx.
	custom := &http.Client{Transport: ts.Client().Transport}
	reg, err := NewRemoteRegistry(ts.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	reg.Client = custom

	cl := reg.client()
	if cl == custom {
		t.Fatal("custom client must be copied, not returned as-is")
	}
	if cl.Timeout != defaultRegistryTimeout {
		t.Fatalf("hardened Timeout = %v, want %v", cl.Timeout, defaultRegistryTimeout)
	}
	if cl.Transport != custom.Transport {
		t.Fatal("caller transport must be preserved in the hardened copy")
	}
	if err := cl.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("hardened CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	if custom.Timeout != 0 || custom.CheckRedirect != nil {
		t.Fatalf("hardening must not mutate the caller's client: %+v", custom)
	}

	if _, _, err := reg.Resolve(context.Background(), "build@sha256:"+strings.Repeat("ab", 32)); err == nil {
		t.Fatal("redirecting registry resolved")
	}
	if n := followed.Load(); n != 0 {
		t.Fatalf("redirect was followed %d time(s); the hardened policy must refuse it", n)
	}
}

func TestNewRemoteRegistryRejectsUserinfoQueryFragmentAndCase(t *testing.T) {
	rejected := []struct {
		name string
		raw  string
		want string
	}{
		{"userinfo with password", "https://user:pass@registry.example.com", "userinfo"},
		{"userinfo name only", "https://user@registry.example.com", "userinfo"},
		{"percent-encoded userinfo", "https://user%3Apass@registry.example.com", "userinfo"},
		{"userinfo under upper-case scheme", "HTTPS://user:pass@registry.example.com", "userinfo"},
		{"query", "https://registry.example.com?token=abc", "query"},
		{"empty query", "https://registry.example.com?", "query"},
		{"query after a path", "https://registry.example.com/base?x=1", "query"},
		{"fragment", "https://registry.example.com#top", "fragment"},
		{"fragment after a path", "https://registry.example.com/base#top", "fragment"},
		{"case-variant scheme", "HTTPS://registry.example.com", "lowercase"},
		{"mixed-case scheme", "hTtPs://registry.example.com", "lowercase"},
		{"case-variant scheme with query", "HTTPS://registry.example.com?x=1", "query"},
		{"case-variant scheme with fragment", "HTTPS://registry.example.com#x", "fragment"},
		{"percent-encoded scheme", "https%3A//registry.example.com", "must use https"},
		{"percent-encoded host", "https://reg%75stry.example.com", "parse remote registry URL"},
		{"invalid port", "https://registry.example.com:bad", "parse remote registry URL"},
		{"non-https scheme", "ftp://registry.example.com", "must use https"},
		{"no host", "https://", "no host"},
	}
	for _, tc := range rejected {
		if _, err := NewRemoteRegistry(tc.raw, ""); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: NewRemoteRegistry(%q) error = %v, want %q", tc.name, tc.raw, err, tc.want)
		}
	}

	// Percent-encoding cannot fabricate components: "%3F" is path data, not
	// a query delimiter, so the URL stays a valid bare-origin base URL.
	reg, err := NewRemoteRegistry("https://registry.example.com/base%3Fq", "")
	if err != nil {
		t.Fatalf("encoded delimiter in the path must stay path data: %v", err)
	}
	if reg.BaseURL != "https://registry.example.com/base%3Fq" {
		t.Fatalf("BaseURL = %q", reg.BaseURL)
	}
}

package components

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const buildComponentYAML = `name: build
version: v1
steps:
  - run: echo building
env:
  MODE: ci
`

func TestLocalRegistryFromDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "components", "build.yaml"), []byte(buildComponentYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "components", "lint.json"),
		[]byte(`{"name":"lint","steps":[{"run":"echo linting"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := NewLocalRegistryFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Bare relative path.
	spec, digest, err := reg.Resolve(context.Background(), "components/build.yaml")
	if err != nil {
		t.Fatalf("resolve components/build.yaml: %v", err)
	}
	if spec.Name != "build" || digest == "" {
		t.Fatalf("spec = %+v digest = %q", spec, digest)
	}
	// Directory-relative path.
	if _, _, err := reg.Resolve(context.Background(), "components/lint.json"); err != nil {
		t.Fatalf("resolve components/lint.json: %v", err)
	}
	// Name-pinned remote-style ref against the local registry.
	pinned, err := Digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.Resolve(context.Background(), "build@sha256:"+pinned); err != nil {
		t.Fatalf("resolve pinned build: %v", err)
	}
	// Unknown refs and invalid refs are rejected.
	if _, _, err := reg.Resolve(context.Background(), "components/missing.yaml"); err == nil {
		t.Fatal("missing component resolved")
	}
	if _, _, err := reg.Resolve(context.Background(), "../etc/passwd"); err == nil {
		t.Fatal("path traversal ref accepted")
	}
	if _, _, err := reg.Resolve(context.Background(), "build@sha256:deadbeef"); err == nil {
		t.Fatal("bad pinned ref accepted")
	}
}

func TestLocalRegistryFromDirRejectsDuplicatesAndAnonymous(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("name: dup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("name: dup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalRegistryFromDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate names accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "b.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anon.yaml"), []byte("steps: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalRegistryFromDir(dir); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("anonymous component accepted: %v", err)
	}
}

func TestRemoteRegistryResolve(t *testing.T) {
	var spec Spec
	if err := json.Unmarshal([]byte(`{"name":"build","version":"v1","steps":[{"run":"echo hi"}]}`), &spec); err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	var sawAuth atomicString
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.set(r.Header.Get("Authorization"))
		if !strings.HasPrefix(r.URL.Path, "/components/") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(spec)
	}))
	defer ts.Close()

	reg, err := NewRemoteRegistry(ts.URL, "reg-token")
	if err != nil {
		t.Fatal(err)
	}
	reg.Client = ts.Client()
	got, gotDigest, err := reg.Resolve(context.Background(), "build@sha256:"+digest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "build" || gotDigest != digest {
		t.Fatalf("resolve = %+v %q, want build/%s", got, gotDigest, digest)
	}
	if sawAuth.get() != "Bearer reg-token" {
		t.Fatalf("Authorization = %q, want bearer token", sawAuth.get())
	}
	// Unpinned refs are rejected: the remote registry only serves pins.
	if _, _, err := reg.Resolve(context.Background(), "build.yaml"); err == nil {
		t.Fatal("unpinned ref accepted by remote registry")
	}
	// Digest mismatch is refused.
	if _, _, err := reg.Resolve(context.Background(), "build@sha256:"+strings.Repeat("ab", 32)); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("digest mismatch accepted: %v", err)
	}
}

func TestRemoteRegistryStrictHTTPSAndNoRedirect(t *testing.T) {
	if _, err := NewRemoteRegistry("http://registry.example.com", ""); err == nil {
		t.Fatal("http base URL accepted")
	}
	// A redirecting server must not be followed: the client surfaces the
	// 3xx as an error instead of leaking the bearer token onward.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	defer ts.Close()
	reg, err := NewRemoteRegistry(ts.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	// The registry client never follows redirects; the 302 surfaces as an
	// error instead of leaking the bearer token onward.
	c := ts.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	reg.Client = c
	if _, _, err := reg.Resolve(context.Background(), "build@sha256:"+strings.Repeat("ab", 32)); err == nil {
		t.Fatal("redirecting registry resolved")
	}
}

// atomicString is a tiny race-free string holder for httptest handlers.
type atomicString struct {
	mu sync.Mutex
	v  string
}

func (a *atomicString) set(v string) { a.mu.Lock(); a.v = v; a.mu.Unlock() }
func (a *atomicString) get() string  { a.mu.Lock(); defer a.mu.Unlock(); return a.v }

package cache

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireNonRootCache(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not apply to root")
	}
}

const gapCacheKey = "deadbeef"

// cacheTripper is a deterministic http.RoundTripper.
type cacheTripper struct {
	resp *http.Response
	err  error
}

func (c cacheTripper) RoundTrip(*http.Request) (*http.Response, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.resp, nil
}

// bodyReader fails after emitting some bytes.
type bodyReader struct {
	data []byte
	err  error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, b.err
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func okResp(status int, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Body: body, Header: http.Header{}}
}

// TestDefaultStoreRoot proves Default anchors the store under the user's home.
func TestDefaultStoreRoot(t *testing.T) {
	home := t.TempDir()
	testutil.SetHome(t, home)
	s := Default()
	if want := filepath.Join(home, ".kiwi", "cache"); s.Root != want {
		t.Fatalf("Default().Root = %q, want %q", s.Root, want)
	}
}

// TestKeyErrors proves workspace-open and file-read failures are surfaced.
func TestKeyErrors(t *testing.T) {
	testutil.UnixChmod(t)
	s := &Store{Root: t.TempDir()}
	if _, err := s.Key("base", filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("missing workspace must fail")
	}

	// Copy failure on an opened hash file (injected through the test seam).
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "lock.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	origCopy := copyCacheDigest
	copyCacheDigest = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("copy refused") }
	_, err := s.Key("base", ws, []string{"lock.bin"})
	copyCacheDigest = origCopy
	if err == nil || !strings.Contains(err.Error(), "copy refused") {
		t.Fatalf("copy failure = %v, want copy error", err)
	}

	requireNonRootCache(t)
	locked := filepath.Join(ws, "lock.bin")
	if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
	if _, err := s.Key("base", ws, []string{"lock.bin"}); err == nil {
		t.Fatal("unreadable hash file must fail")
	}
}

// TestRestoreLocalFileErrors proves missing, unreadable, and unopenable
// destinations are handled.
func TestRestoreLocalFileErrors(t *testing.T) {
	testutil.UnixChmod(t)
	// Missing archive: a clean miss.
	s := &Store{Root: t.TempDir()}
	hit, err := s.Restore(gapCacheKey, t.TempDir(), nil)
	if err != nil || hit {
		t.Fatalf("missing archive = (%v, %v), want (false, nil)", hit, err)
	}

	requireNonRootCache(t)
	// Unreadable archive.
	root := t.TempDir()
	archive := filepath.Join(root, gapCacheKey+".tar.gz")
	if err := os.WriteFile(archive, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archive, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(archive, 0o600) })
	if hit, err := (&Store{Root: root}).Restore(gapCacheKey, t.TempDir(), nil); err == nil || hit {
		t.Fatalf("unreadable archive = (%v, %v), want error", hit, err)
	}
}

// TestRestoreLocalDestinationErrors proves workspace creation and root-open
// failures are surfaced.
func TestRestoreLocalDestinationErrors(t *testing.T) {
	root := t.TempDir()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	key, err := (&Store{Root: root}).Key("k", src, []string{"f"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Store{Root: root}).Save(key, src, []string{"f"}); err != nil {
		t.Fatal(err)
	}

	// Workspace path under a regular file: MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hit, err := (&Store{Root: root}).Restore(key, filepath.Join(blocker, "dest"), nil); err == nil || hit {
		t.Fatalf("dest under a file = (%v, %v), want error", hit, err)
	}

	// Symlinked destination root: the no-follow open rejects it.
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if hit, err := (&Store{Root: root}).Restore(key, link, nil); err == nil || hit {
		t.Fatalf("symlinked dest = (%v, %v), want error", hit, err)
	}

	// Sanity: a valid restore succeeds.
	if hit, err := (&Store{Root: root}).Restore(key, t.TempDir(), []string{"f"}); err != nil || !hit {
		t.Fatalf("valid restore = (%v, %v)", hit, err)
	}
}

// testArchive builds a one-file cache archive and returns its bytes.
func testArchive(t *testing.T) []byte {
	t.Helper()
	root := t.TempDir()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Store{Root: root}
	key, err := s.Key("k", src, []string{"f"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(key, src, []string{"f"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, key+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRestoreRemoteMatrix proves remote fallback semantics: a remote miss is
// a clean miss, a remote failure surfaces, and a remote hit restores locally.
func TestRestoreRemoteMatrix(t *testing.T) {
	archive := testArchive(t)
	key := gapCacheKey

	// 404: clean miss.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	s := &Store{Root: t.TempDir(), RemoteURL: srv.URL}
	if hit, err := s.Restore(key, t.TempDir(), []string{"f"}); err != nil || hit {
		t.Fatalf("remote miss = (%v, %v), want (false, nil)", hit, err)
	}

	// 500: error.
	srvErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "cache down", http.StatusInternalServerError)
	}))
	t.Cleanup(srvErr.Close)
	s = &Store{Root: t.TempDir(), RemoteURL: srvErr.URL}
	if hit, err := s.Restore(key, t.TempDir(), []string{"f"}); err == nil || hit {
		t.Fatalf("remote failure = (%v, %v), want error", hit, err)
	} else if !strings.Contains(err.Error(), "cache down") {
		t.Fatalf("remote failure body missing: %v", err)
	}

	// 200: the archive is fetched and restored.
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srvOK.Close)
	s = &Store{Root: t.TempDir(), RemoteURL: srvOK.URL, Token: "tok"}
	ws := t.TempDir()
	hit, err := s.Restore(key, ws, []string{"f"})
	if err != nil || !hit {
		t.Fatalf("remote hit = (%v, %v), want (true, nil)", hit, err)
	}
	b, err := os.ReadFile(filepath.Join(ws, "f"))
	if err != nil || string(b) != "payload" {
		t.Fatalf("restored content = %q, %v", b, err)
	}
}

// TestSaveSetupErrors proves store-root creation, free-space, temp-file, and
// rename failures are surfaced.
func TestSaveSetupErrors(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Store root under a regular file.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Store{Root: blocker}).Save(gapCacheKey, ws, []string{"f"}); err == nil {
		t.Fatal("store root under a file must fail")
	}

	// Impossible quota.
	if err := (&Store{Root: t.TempDir(), MaxCacheBytes: 1 << 62}).Save(gapCacheKey, ws, []string{"f"}); err == nil {
		t.Fatal("impossible cache quota must fail the free-space check")
	}

	// Temp-file path occupied by a directory.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, gapCacheKey+".tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (&Store{Root: root}).Save(gapCacheKey, ws, []string{"f"}); err == nil {
		t.Fatal("temp path occupied by a directory must fail")
	}

	// Destination archive path occupied by a directory.
	root2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root2, gapCacheKey+".tar.gz"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (&Store{Root: root2}).Save(gapCacheKey, ws, []string{"f"}); err == nil {
		t.Fatal("archive path occupied by a directory must fail the rename")
	}

	// Malformed store root (empty) with a valid workspace still succeeds.
	if err := (&Store{Root: filepath.Join(t.TempDir(), "ok")}).Save(gapCacheKey, ws, []string{"f"}); err != nil {
		t.Fatalf("valid save: %v", err)
	}
}

// TestSaveCloseError proves a close failure is surfaced and leaves no temp
// file behind (injected through the test seam).
func TestSaveCloseError(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := closeCacheFile
	closeCacheFile = func(*os.File) error { return errors.New("close refused") }
	defer func() { closeCacheFile = orig }()
	root := t.TempDir()
	if err := (&Store{Root: root}).Save(gapCacheKey, ws, []string{"f"}); err == nil {
		t.Fatal("close failure must surface")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("close failure left %q behind", e.Name())
	}
}

// TestStoreClientFactory proves the store client honors a custom client and
// refuses redirects in both configurations.
func TestStoreClientFactory(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}
	s := &Store{Client: custom}
	got := s.client()
	if got == custom || got.Timeout != 5*time.Second {
		t.Fatalf("custom client not copied: %+v", got)
	}
	if custom.CheckRedirect != nil {
		t.Fatal("caller's client was mutated")
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("custom CheckRedirect = %v", err)
	}

	def := (&Store{}).client()
	if def.CheckRedirect == nil {
		t.Fatal("default client must refuse redirects")
	}
	if err := def.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("default CheckRedirect = %v", err)
	}
}

// TestFetchRemoteValidationAndTransportErrors proves invalid keys, invalid
// URLs, transport failures, and non-200 statuses surface.
func TestFetchRemoteValidationAndTransportErrors(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	if err := s.fetchRemote("bad/key"); err == nil {
		t.Fatal("invalid key must fail")
	}
	s.RemoteURL = "http://[::1"
	if err := s.fetchRemote(gapCacheKey); err == nil {
		t.Fatal("invalid remote URL must fail")
	}
	boom := errors.New("connection refused")
	s = &Store{Root: t.TempDir(), RemoteURL: "http://cache.test", Client: &http.Client{Transport: cacheTripper{err: boom}}}
	if err := s.fetchRemote(gapCacheKey); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v, want %v", err, boom)
	}
	s = &Store{Root: t.TempDir(), RemoteURL: "http://cache.test", Client: &http.Client{Transport: cacheTripper{resp: okResp(http.StatusInternalServerError, io.NopCloser(strings.NewReader("download refused")))}}}
	if err := s.fetchRemote(gapCacheKey); err == nil || !strings.Contains(err.Error(), "download refused") {
		t.Fatalf("status error = %v, want body", err)
	}
	// 404 maps to the remote-not-found sentinel.
	s = &Store{Root: t.TempDir(), RemoteURL: "http://cache.test", Client: &http.Client{Transport: cacheTripper{resp: okResp(http.StatusNotFound, io.NopCloser(strings.NewReader("")))}}}
	if err := s.fetchRemote(gapCacheKey); !errors.Is(err, errRemoteNotFound) {
		t.Fatalf("404 = %v, want errRemoteNotFound", err)
	}
}

// TestFetchRemoteStoreErrors proves destination-root creation, temp-file
// creation, copy, close, and rename failures surface.
func TestFetchRemoteStoreErrors(t *testing.T) {
	freshTripper := func() cacheTripper {
		return cacheTripper{resp: okResp(http.StatusOK, io.NopCloser(strings.NewReader("archive")))}
	}

	// Root under a regular file.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{Root: blocker, RemoteURL: "http://cache.test", Client: &http.Client{Transport: freshTripper()}}
	if err := s.fetchRemote(gapCacheKey); err == nil {
		t.Fatal("uncreatable store root must fail")
	}

	// Temp path occupied by a directory.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, gapCacheKey+".remote.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	s = &Store{Root: root, RemoteURL: "http://cache.test", Client: &http.Client{Transport: freshTripper()}}
	if err := s.fetchRemote(gapCacheKey); err == nil {
		t.Fatal("temp path occupied by a directory must fail")
	}

	// Body copy failure.
	root2 := t.TempDir()
	s = &Store{Root: root2, RemoteURL: "http://cache.test", Client: &http.Client{Transport: cacheTripper{resp: okResp(http.StatusOK, io.NopCloser(&bodyReader{data: []byte("partial"), err: errors.New("stream broke")}))}}}
	if err := s.fetchRemote(gapCacheKey); err == nil || !strings.Contains(err.Error(), "stream broke") {
		t.Fatalf("copy failure = %v, want stream error", err)
	}
	if _, err := os.Stat(filepath.Join(root2, gapCacheKey+".remote.tmp")); !os.IsNotExist(err) {
		t.Fatal("copy failure left a temp file behind")
	}

	// Close failure (injected).
	orig := closeCacheFile
	closeCacheFile = func(*os.File) error { return errors.New("close refused") }
	root3 := t.TempDir()
	s = &Store{Root: root3, RemoteURL: "http://cache.test", Client: &http.Client{Transport: freshTripper()}}
	if err := s.fetchRemote(gapCacheKey); err == nil || !strings.Contains(err.Error(), "close refused") {
		t.Fatalf("close failure = %v, want close error", err)
	}
	closeCacheFile = orig

	// Rename failure: destination occupied by a directory.
	root4 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root4, gapCacheKey+".tar.gz"), 0o755); err != nil {
		t.Fatal(err)
	}
	s = &Store{Root: root4, RemoteURL: "http://cache.test", Client: &http.Client{Transport: freshTripper()}}
	if err := s.fetchRemote(gapCacheKey); err == nil {
		t.Fatal("destination occupied by a directory must fail the rename")
	}

	// Happy path writes the archive.
	root5 := t.TempDir()
	s = &Store{Root: root5, RemoteURL: "http://cache.test", Client: &http.Client{Transport: freshTripper()}}
	if err := s.fetchRemote(gapCacheKey); err != nil {
		t.Fatalf("valid fetch: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(root5, gapCacheKey+".tar.gz")); err != nil || string(b) != "archive" {
		t.Fatalf("fetched archive = %q, %v", b, err)
	}
}

// TestPushRemoteMatrix proves upload validation, local-open, transport,
// status, and success paths.
func TestPushRemoteMatrix(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	if err := s.pushRemote("bad/key"); err == nil {
		t.Fatal("invalid key must fail")
	}
	// Local archive missing.
	s = &Store{Root: t.TempDir(), RemoteURL: "http://cache.test"}
	if err := s.pushRemote(gapCacheKey); err == nil {
		t.Fatal("missing local archive must fail")
	}
	// Invalid remote URL.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, gapCacheKey+".tar.gz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s = &Store{Root: root, RemoteURL: "http://[::1"}
	if err := s.pushRemote(gapCacheKey); err == nil {
		t.Fatal("invalid remote URL must fail")
	}
	// Transport failure.
	boom := errors.New("connection refused")
	s = &Store{Root: root, RemoteURL: "http://cache.test", Client: &http.Client{Transport: cacheTripper{err: boom}}}
	if err := s.pushRemote(gapCacheKey); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v, want %v", err, boom)
	}
	// Non-2xx status.
	s = &Store{Root: root, RemoteURL: "http://cache.test", Client: &http.Client{Transport: cacheTripper{resp: okResp(http.StatusBadGateway, io.NopCloser(strings.NewReader("upload refused")))}}}
	if err := s.pushRemote(gapCacheKey); err == nil || !strings.Contains(err.Error(), "upload refused") {
		t.Fatalf("status error = %v, want body", err)
	}
	// Success.
	s = &Store{Root: root, RemoteURL: "http://cache.test", Client: &http.Client{Transport: cacheTripper{resp: okResp(http.StatusCreated, io.NopCloser(strings.NewReader("")))}}}
	if err := s.pushRemote(gapCacheKey); err != nil {
		t.Fatalf("valid push: %v", err)
	}
}

// ---------- client.go ----------

// TestClientFactoryAndHelpers proves client construction, auth, lease
// headers, URL building, and the compressed-byte default.
func TestClientFactoryAndHelpers(t *testing.T) {
	custom := &http.Client{Timeout: 3 * time.Second}
	c := &Client{HTTP: custom}
	got := c.client()
	if got == custom || got.Timeout != 3*time.Second {
		t.Fatalf("custom client not copied: %+v", got)
	}
	if custom.CheckRedirect != nil {
		t.Fatal("caller's client was mutated")
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("custom CheckRedirect = %v", err)
	}
	def := (&Client{}).client()
	if err := def.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("default CheckRedirect = %v", err)
	}

	c.Token = "tok"
	r2, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	c.auth(r2)
	if r2.Header.Get("Authorization") != "Bearer tok" {
		t.Fatal("auth header missing")
	}
	(&Client{}).auth(r2)

	lease := map[string]string{
		HeaderRunnerID:        "runner-1",
		HeaderLeaseToken:      "lease",
		HeaderLeaseGeneration: "7",
		"X-Kiwi-Repository":   "evil/repo",
		"X-Kiwi-Empty":        "",
	}
	r3, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	c.applyLeaseHeaders(r3, lease)
	for _, h := range []string{HeaderRunnerID, HeaderLeaseToken, HeaderLeaseGeneration} {
		if r3.Header.Get(h) == "" {
			t.Fatalf("lease header %s missing", h)
		}
	}
	if r3.Header.Get("X-Kiwi-Repository") != "" {
		t.Fatal("non-lease header was attached")
	}

	if got := c.cacheURL("job/1", "key 2"); !strings.Contains(got, "job%2F1") || !strings.Contains(got, "key%202") {
		t.Fatalf("cacheURL = %q", got)
	}

	if (&Client{}).maxCompressedBytes() != defaultMaxCompressedBytes {
		t.Fatal("default compressed bound wrong")
	}
	if (&Client{MaxCompressedBytes: 42}).maxCompressedBytes() != 42 {
		t.Fatal("explicit compressed bound ignored")
	}
}

// TestClientRestoreMatrix proves restore request construction, status
// handling, digest verification, and the compressed bound.
func TestClientRestoreMatrix(t *testing.T) {
	payload := []byte("cache archive payload")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	key := gapCacheKey
	lease := map[string]string{HeaderLeaseToken: "lease"}

	// Server matrix: status codes, digest header correctness, body size.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		if r.Header.Get(HeaderLeaseToken) != "lease" {
			http.Error(w, "no lease", http.StatusUnauthorized)
			return
		}
		switch filepath.Base(r.URL.Path) {
		case "missing":
			http.NotFound(w, r)
		case "failure":
			http.Error(w, "cache down", http.StatusInternalServerError)
		case "nodigest":
			_, _ = w.Write(payload)
		case "wrongdigest":
			w.Header().Set(HeaderCacheSHA256, strings.Repeat("0", 64))
			_, _ = w.Write(payload)
		default:
			w.Header().Set(HeaderCacheSHA256, digest)
			_, _ = w.Write(payload)
		}
	}))
	t.Cleanup(srv.Close)
	c := &Client{Server: srv.URL, Token: "tok"}

	if _, err := c.Restore(context.Background(), "job", lease, "missing"); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("404 = %v, want ErrRemoteNotFound", err)
	}
	if _, err := c.Restore(context.Background(), "job", lease, "failure"); err == nil || !strings.Contains(err.Error(), "cache down") {
		t.Fatalf("500 = %v, want body", err)
	}

	// Missing digest header logs and skips verification.
	var logged []string
	c.Logf = func(format string, args ...any) { logged = append(logged, format) }
	rc, err := c.Restore(context.Background(), "job", lease, "nodigest")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, payload) || len(logged) != 1 {
		t.Fatalf("no-digest restore = %q, logged %d", b, len(logged))
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}

	// Wrong digest fails at EOF.
	rc, err = c.Restore(context.Background(), "job", lease, "wrongdigest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("wrong digest = %v, want mismatch", err)
	}
	_ = rc.Close()

	// Correct digest streams the payload.
	rc, err = c.Restore(context.Background(), "job", lease, key)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(rc); err != nil || !bytes.Equal(b, payload) {
		t.Fatalf("verified restore = %q, %v", b, err)
	}
	_ = rc.Close()

	// Compressed bound.
	bound := &Client{Server: srv.URL, Token: "tok", MaxCompressedBytes: 4}
	rc, err = bound.Restore(context.Background(), "job", lease, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("bounded restore = %v, want exceeds error", err)
	}
	_ = rc.Close()

	// Request construction failure.
	bad := &Client{Server: "://bad"}
	if _, err := bad.Restore(context.Background(), "job", nil, key); err == nil {
		t.Fatal("invalid server URL must fail")
	}

	// Transport failure.
	boom := errors.New("connection refused")
	down := &Client{Server: "http://cache.test", HTTP: &http.Client{Transport: cacheTripper{err: boom}}}
	if _, err := down.Restore(context.Background(), "job", nil, key); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v, want %v", err, boom)
	}
}

// TestClientUploadMatrix proves upload request construction, status
// handling, and success.
func TestClientUploadMatrix(t *testing.T) {
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- b
		if r.URL.Path == "/api/v1/jobs/job/cache/failure" {
			http.Error(w, "upload refused", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	c := &Client{Server: srv.URL, Token: "tok", Logf: nil}

	if err := c.Upload(context.Background(), "job", map[string]string{HeaderRunnerID: "r1"}, gapCacheKey, strings.NewReader("bytes")); err != nil {
		t.Fatal(err)
	}
	if b := <-got; string(b) != "bytes" {
		t.Fatalf("uploaded body = %q", b)
	}
	if err := c.Upload(context.Background(), "job", nil, "failure", strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "upload refused") {
		t.Fatalf("status error = %v, want body", err)
	}

	bad := &Client{Server: "://bad"}
	if err := bad.Upload(context.Background(), "job", nil, gapCacheKey, strings.NewReader("x")); err == nil {
		t.Fatal("invalid server URL must fail")
	}
	boom := errors.New("connection refused")
	down := &Client{Server: "http://cache.test", HTTP: &http.Client{Transport: cacheTripper{err: boom}}}
	if err := down.Upload(context.Background(), "job", nil, gapCacheKey, strings.NewReader("x")); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v, want %v", err, boom)
	}
}

// TestBoundedReadCloser proves the bound is enforced and pass-through reads
// are unchanged.
func TestBoundedReadCloser(t *testing.T) {
	// Under the bound.
	b := &boundedReadCloser{ReadCloser: io.NopCloser(strings.NewReader("abcd")), max: 8}
	if got, err := io.ReadAll(b); err != nil || string(got) != "abcd" {
		t.Fatalf("under bound = %q, %v", got, err)
	}
	// Over the bound.
	b = &boundedReadCloser{ReadCloser: io.NopCloser(strings.NewReader("abcdefghij")), max: 4}
	if _, err := io.ReadAll(b); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("over bound = %v, want exceeds error", err)
	}
	// Exactly at the bound passes.
	b = &boundedReadCloser{ReadCloser: io.NopCloser(strings.NewReader("abcd")), max: 4}
	if got, err := io.ReadAll(b); err != nil || string(got) != "abcd" {
		t.Fatalf("at bound = %q, %v", got, err)
	}
}

// TestVerifyingReadCloser proves digest verification and close delegation.
func TestVerifyingReadCloser(t *testing.T) {
	payload := []byte("verified payload")
	sum := sha256.Sum256(payload)

	v := &verifyingReadCloser{r: io.NopCloser(bytes.NewReader(payload)), want: hex.EncodeToString(sum[:]), h: sha256.New()}
	calls := 0
	buf := make([]byte, 3)
	for {
		n, err := v.Read(buf)
		calls++
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read %d: %v", calls, err)
		}
		_ = n
	}
	// A second read after EOF still returns EOF without re-verifying.
	if _, err := v.Read(buf); err != io.EOF {
		t.Fatalf("read after EOF = %v", err)
	}

	v = &verifyingReadCloser{r: io.NopCloser(bytes.NewReader(payload)), want: strings.Repeat("0", 64), h: sha256.New()}
	if _, err := io.ReadAll(v); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("mismatch = %v, want digest mismatch", err)
	}

	// The mismatch latches: a later Read returns the same error instead of
	// reverting to io.EOF, and Close reports it too.
	v = &verifyingReadCloser{r: io.NopCloser(bytes.NewReader(payload)), want: strings.Repeat("0", 64), h: sha256.New()}
	var err1 error
	for i := 0; i < 100; i++ {
		if _, err := v.Read(buf); err != nil {
			err1 = err
			break
		}
	}
	if err1 == nil || !strings.Contains(err1.Error(), "digest mismatch") {
		t.Fatalf("first mismatch read = %v, want digest mismatch", err1)
	}
	n, err2 := v.Read(buf)
	if n != 0 || err2 == nil || err2.Error() != err1.Error() {
		t.Fatalf("latched read = (%d, %v), want (0, %v)", n, err2, err1)
	}
	if err3 := v.Close(); err3 == nil || err3.Error() != err1.Error() {
		t.Fatalf("latched close = %v, want %v", err3, err1)
	}

	closed := false
	v = &verifyingReadCloser{r: closeRecorder{Reader: bytes.NewReader(payload), closed: &closed}, want: hex.EncodeToString(sum[:]), h: sha256.New()}
	if err := v.Close(); err != nil || !closed {
		t.Fatalf("close = %v, closed=%v", err, closed)
	}
}

type closeRecorder struct {
	*bytes.Reader
	closed *bool
}

func (c closeRecorder) Close() error {
	*c.closed = true
	return nil
}

// ---------- infer.go ----------

// TestInferLockfilesSkipsUnknownAndDirectories proves unknown first-level
// files are skipped and directories never count as lock files.
func TestInferLockfilesSkipsUnknownAndDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "go.sum"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := InferLockfiles(dir); len(got) != 0 {
		t.Fatalf("unknown files and directories must not be reported: %v", got)
	}
}

// TestVerifyLockfileEscapeShapes proves absolute paths, dot, and dot-dot are
// rejected outright, and directories are rejected.
func TestVerifyLockfileEscapeShapes(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"/etc/passwd", ".", ".."} {
		if err := VerifyLockfile(dir, name); err == nil {
			t.Errorf("VerifyLockfile(%q) accepted", name)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLockfile(dir, "sub"); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("directory lockfile = %v, want directory error", err)
	}
}

// ---------- manifest.go ----------

// TestValidateManifestRejectsNegativeSize proves the size guard.
func TestValidateManifestRejectsNegativeSize(t *testing.T) {
	m := CacheManifest{Version: 1, LogicalKey: "key", BlobSHA256: strings.Repeat("a", 64), BlobSize: -1}
	if err := ValidateManifest(m); err == nil {
		t.Fatal("negative blob size must be rejected")
	}
}

// TestSignManifestErrors proves invalid manifests and unencodable timestamps
// are rejected at signing time.
func TestSignManifestErrors(t *testing.T) {
	_, priv := sigKeyCache(t)
	if _, err := SignManifest(CacheManifest{}, "kid", priv); err == nil {
		t.Fatal("invalid manifest must fail")
	}
	bad := CacheManifest{Version: 1, LogicalKey: "k", BlobSHA256: strings.Repeat("a", 64), CreatedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := SignManifest(bad, "kid", priv); err == nil {
		t.Fatal("unrepresentable timestamp must fail encoding")
	}
}

// TestVerifyManifestErrorMatrix proves every rejection branch of
// VerifyManifest plus the happy path.
func TestVerifyManifestErrorMatrix(t *testing.T) {
	pub, priv := sigKeyCache(t)
	signed, err := SignManifest(validManifest(), "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(signed, pub); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}

	// Decode failure.
	if _, err := VerifyManifest([]byte("{"), pub); err == nil {
		t.Fatal("invalid envelope JSON must fail")
	}
	// Wrong payload type.
	var env manifestEnvelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	wrongType := env
	wrongType.PayloadType = "text/plain"
	raw, _ := json.Marshal(wrongType)
	if _, err := VerifyManifest(raw, pub); err == nil {
		t.Fatal("wrong payload type must fail")
	}
	// No signature.
	noSig := env
	noSig.Signatures = nil
	raw, _ = json.Marshal(noSig)
	if _, err := VerifyManifest(raw, pub); err == nil {
		t.Fatal("missing signature must fail")
	}
	// Bad payload base64.
	badPayload := env
	badPayload.Payload = "!!!"
	raw, _ = json.Marshal(badPayload)
	if _, err := VerifyManifest(raw, pub); err == nil {
		t.Fatal("bad payload base64 must fail")
	}
	// Bad signature base64.
	badSig := env
	badSig.Signatures = []signature{{KeyID: "kid", Sig: "!!!"}}
	raw, _ = json.Marshal(badSig)
	if _, err := VerifyManifest(raw, pub); err == nil {
		t.Fatal("bad signature base64 must fail")
	}

	// Correctly signed but non-JSON payload: decode failure after the
	// signature check.
	raw = signedEnvelopeBytes(t, []byte("not json"), priv)
	if _, err := VerifyManifest(raw, pub); err == nil {
		t.Fatal("non-JSON manifest payload must fail")
	}
	// Correctly signed manifest that fails validation.
	raw = signedEnvelopeBytes(t, []byte(`{"version":2}`), priv)
	if _, err := VerifyManifest(raw, pub); err == nil {
		t.Fatal("invalid signed manifest must fail validation")
	}
}

func sigKeyCache(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func validManifest() CacheManifest {
	return CacheManifest{
		Version:     1,
		Repository:  "example/repo",
		TrustDomain: "td",
		LogicalKey:  "key",
		BlobSHA256:  strings.Repeat("a", 64),
		BlobSize:    10,
		ProducerRun: "run",
		ProducerJob: "job",
		CreatedAt:   time.Unix(0, 0).UTC(),
	}
}

func signedEnvelopeBytes(t *testing.T, payload []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, dssePAE(ManifestPayloadType, payload))
	raw, err := json.Marshal(manifestEnvelope{
		PayloadType: ManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []signature{{KeyID: "kid", Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestManifestDigest proves the digest is deterministic and that encoding
// failures surface.
func TestManifestDigest(t *testing.T) {
	m := validManifest()
	d1, err := ManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("digest = %q vs %q", d1, d2)
	}
	bad := m
	bad.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := ManifestDigest(bad); err == nil {
		t.Fatal("unrepresentable timestamp must fail the digest")
	}
}

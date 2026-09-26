package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCleanRootsMatrix pins Y3-C's restriction validation: invalid shapes are
// an error (never silently dropped), "." is the sole explicit whole-root
// marker, and an empty input yields an empty list.
func TestCleanRootsMatrix(t *testing.T) {
	invalid := []string{
		"../../x", "/etc", `C:\Windows`, "C:/Windows", `..\foo`, "..", "a/../b",
		`a\b`, "a\x00b", "",
	}
	for _, in := range invalid {
		if got, err := cleanRoots([]string{in}); err == nil {
			t.Errorf("cleanRoots(%q) = %v, want error", in, got)
		}
	}

	roots, err := cleanRoots([]string{"."})
	if err != nil || len(roots) != 1 || roots[0] != "." {
		t.Fatalf("cleanRoots(\".\") = %v, %v; want [\".\"]", roots, err)
	}
	// The deliberate whole-root choice dominates any other entry.
	roots, err = cleanRoots([]string{"a", ".", "b"})
	if err != nil || len(roots) != 1 || roots[0] != "." {
		t.Fatalf("cleanRoots with \".\" = %v, %v; want [\".\"]", roots, err)
	}
	// Empty input is none, not all.
	roots, err = cleanRoots(nil)
	if err != nil || len(roots) != 0 {
		t.Fatalf("cleanRoots(nil) = %v, %v; want empty", roots, err)
	}
	// Valid roots are normalized to slash form.
	roots, err = cleanRoots([]string{"cache/./dir//x", "a", "b/c"})
	if err != nil || strings.Join(roots, ",") != "cache/dir/x,a,b/c" {
		t.Fatalf("cleanRoots valid = %v, %v", roots, err)
	}
}

// TestRestoreRejectsInvalidPathRestriction proves an invalid restriction is
// surfaced by RestoreContext/restoreLocal and nothing is extracted; it can no
// longer collapse to an empty Allowed list equal to "whole archive".
func TestRestoreRejectsInvalidPathRestriction(t *testing.T) {
	s, key, _ := savedCache(t)
	for _, paths := range [][]string{
		{"../../not-allowed"},
		{"/etc"},
		{`C:\Windows`},
		{`..\foo`},
	} {
		dest := t.TempDir()
		hit, err := s.Restore(key, dest, paths)
		if err == nil || hit {
			t.Fatalf("Restore(paths=%q) = (%v, %v), want error", paths, hit, err)
		}
		if _, statErr := os.Stat(filepath.Join(dest, "f")); !os.IsNotExist(statErr) {
			t.Fatalf("Restore(paths=%q) extracted an entry", paths)
		}
	}
}

// TestRestoreEmptyPathsWritesNothing proves an empty path list is "none",
// never "whole archive".
func TestRestoreEmptyPathsWritesNothing(t *testing.T) {
	s, key, _ := savedCache(t)
	dest := t.TempDir()
	hit, err := s.Restore(key, dest, nil)
	if err != nil || !hit {
		t.Fatalf("Restore(nil paths) = (%v, %v), want verified hit with nothing written", hit, err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "f")); !os.IsNotExist(statErr) {
		t.Fatal("empty path list extracted the archive")
	}
}

// TestRestoreDotIsExplicitWholeRoot proves "." remains the deliberate
// whole-root choice.
func TestRestoreDotIsExplicitWholeRoot(t *testing.T) {
	s, key, _ := savedCache(t)
	dest := t.TempDir()
	hit, err := s.Restore(key, dest, []string{"."})
	if err != nil || !hit {
		t.Fatalf("Restore(\".\") = (%v, %v), want hit", hit, err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "f")); err != nil || string(b) != "payload" {
		t.Fatalf("whole-root restore content = %q, %v", b, err)
	}
}

// TestRestoreContextHonorsCancellation proves the context-native API cancels
// an in-flight remote restore.
func TestRestoreContextHonorsCancellation(t *testing.T) {
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(blocked.Close)

	s := &Store{Root: t.TempDir(), RemoteURL: blocked.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if hit, err := s.RestoreContext(ctx, "deadbeef", t.TempDir(), []string{"."}); err == nil || hit {
		t.Fatalf("canceled restore = (%v, %v), want error", hit, err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("canceled restore took %v; the context did not reach the request", elapsed)
	}

	// A canceled context is refused before any work.
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := s.RestoreContext(canceled, "deadbeef", t.TempDir(), []string{"."}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled restore = %v, want context.Canceled", err)
	}
}

// TestStoreContextDefaults proves the legacy wrappers are bounded when the
// Store owns its client and defer to a caller-supplied client otherwise.
func TestStoreContextDefaults(t *testing.T) {
	s := &Store{}
	ctx, cancel := s.defaultContext()
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("default store context must carry a finite deadline")
	}
	s.Client = &http.Client{}
	ctx, cancel = s.defaultContext()
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("a caller-supplied client owns its own bounds; context must be unbounded")
	}
}

// TestDefaultHTTPClientsBoundedPhases proves the default Store and Client
// clients bound each control phase but never set a total transfer deadline.
func TestDefaultHTTPClientsBoundedPhases(t *testing.T) {
	clients := map[string]*http.Client{
		"store":  (&Store{}).client(),
		"client": (&Client{}).client(),
	}
	for name, c := range clients {
		if c.Timeout != 0 {
			t.Fatalf("%s default client has a total timeout %v; bulk bodies must not be capped", name, c.Timeout)
		}
		tr, ok := c.Transport.(*http.Transport)
		if !ok || tr == nil {
			t.Fatalf("%s default client transport = %T, want *http.Transport", name, c.Transport)
		}
		if tr.DialContext == nil || tr.TLSHandshakeTimeout <= 0 || tr.ResponseHeaderTimeout <= 0 || tr.IdleConnTimeout <= 0 {
			t.Fatalf("%s transport phases not all bounded: dial=%v tls=%v header=%v idle=%v",
				name, tr.DialContext != nil, tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, tr.IdleConnTimeout)
		}
		if c.CheckRedirect == nil {
			t.Fatalf("%s default client must refuse redirects", name)
		}
	}
}

// countReadCloser records how many bytes were read and whether it closed.
type countReadCloser struct {
	r      *bytes.Reader
	read   int
	closed bool
}

func (c *countReadCloser) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func (c *countReadCloser) Close() error {
	c.closed = true
	return nil
}

// TestVerifyingReadCloserCloseDrains pins Y3-F: Close drains the remaining
// bounded stream, validates, and reports the drain failure.
func TestVerifyingReadCloserCloseDrains(t *testing.T) {
	payload := []byte("cache archive payload")
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])

	// Early close drains and validates.
	src := &countReadCloser{r: bytes.NewReader(payload)}
	v := &verifyingReadCloser{
		r:    &boundedReadCloser{ReadCloser: src, max: int64(len(payload)) + 8},
		want: good,
		h:    sha256.New(),
	}
	if err := v.Close(); err != nil {
		t.Fatalf("early close = %v, want nil after draining and verifying", err)
	}
	if src.read != len(payload) {
		t.Fatalf("early close drained %d of %d bytes", src.read, len(payload))
	}
	if !src.closed {
		t.Fatal("early close did not close the underlying stream")
	}

	// A corrupt tail fails Close even with no prior read.
	v = &verifyingReadCloser{r: io.NopCloser(bytes.NewReader(payload)), want: strings.Repeat("0", 64), h: sha256.New()}
	if err := v.Close(); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("corrupt-tail close = %v, want digest mismatch", err)
	}

	// An oversized tail respects the compressed-byte bound: the drain stops
	// at the bound instead of consuming the whole body.
	oversized := bytes.Repeat([]byte("x"), 1<<20)
	v = &verifyingReadCloser{
		r:    &boundedReadCloser{ReadCloser: io.NopCloser(bytes.NewReader(oversized)), max: 64},
		want: good,
		h:    sha256.New(),
	}
	if err := v.Close(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized-tail close = %v, want compressed-byte bound error", err)
	}

	// Reading the full payload validates, and a later Close stays clean.
	v = &verifyingReadCloser{r: io.NopCloser(bytes.NewReader(payload)), want: good, h: sha256.New()}
	if b, err := io.ReadAll(v); err != nil || !bytes.Equal(b, payload) {
		t.Fatalf("full read = %q, %v", b, err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("post-EOF close = %v, want nil", err)
	}
}

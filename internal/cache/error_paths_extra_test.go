package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// TestSaveContextValidationAndSeamFailures drives the checked failure
// branches of the local save path with the existing seams.
func TestSaveContextValidationAndSeamFailures(t *testing.T) {
	writeWS := func(t *testing.T) string {
		ws := t.TempDir()
		if err := os.WriteFile(filepath.Join(ws, "f"), []byte("payload"), 0o644); err != nil {
			t.Fatal(err)
		}
		return ws
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, store *Store) (key, ws string, want string)
	}{
		{
			name: "invalid key",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				return "bad/key", t.TempDir(), "invalid cache key"
			},
		},
		{
			name: "canceled context",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				return "key1", t.TempDir(), "" // ctx injected below
			},
		},
		{
			name: "missing workspace",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				return "key1", filepath.Join(t.TempDir(), "missing"), ""
			},
		},
		{
			name: "workspace is a file",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				p := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return "key1", p, ""
			},
		},
		{
			name: "rename failure",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				orig := renameCacheFile
				renameCacheFile = func(string, string) error { return errors.New("rename refused") }
				t.Cleanup(func() { renameCacheFile = orig })
				return "key1", writeWS(t), "rename refused"
			},
		},
		{
			name: "sync failure",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				orig := syncCacheFile
				syncCacheFile = func(*os.File) error { return errors.New("sync refused") }
				t.Cleanup(func() { syncCacheFile = orig })
				return "key1", writeWS(t), "sync refused"
			},
		},
		{
			name: "close failure",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				orig := closeCacheFile
				closeCacheFile = func(*os.File) error { return errors.New("close refused") }
				t.Cleanup(func() { closeCacheFile = orig })
				return "key1", writeWS(t), "close refused"
			},
		},
		{
			name: "digest write failure",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				if err := os.MkdirAll(s.stripChecksumPath("key1"), 0o700); err != nil {
					t.Fatal(err)
				}
				return "key1", writeWS(t), "key1"
			},
		},
		{
			name: "manager budget refusal",
			setup: func(t *testing.T, s *Store) (string, string, string) {
				s.MaxCacheBytes = 100
				s.Manager = mustManager(t, s.Root, RetentionPolicy{MaxBytes: 50})
				return "key1", writeWS(t), "budget"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &Store{Root: t.TempDir()}
			key, ws, want := tc.setup(t, store)
			ctx := context.Background()
			if tc.name == "canceled context" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := store.SaveContext(ctx, key, ws, []string{"f"})
			if err == nil {
				t.Fatal("SaveContext succeeded")
			}
			if want != "" && !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want it to contain %q", err, want)
			}
		})
	}
}

// TestRestoreContextLocalValidationErrors drives the local archive validation
// and extraction failure branches.
func TestRestoreContextLocalValidationErrors(t *testing.T) {
	t.Run("symlink archive", func(t *testing.T) {
		store := &Store{Root: t.TempDir()}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, store.archivePath("key1")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreContext(context.Background(), "key1", t.TempDir(), []string{"."}); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink archive = %v", err)
		}
	})
	t.Run("directory archive", func(t *testing.T) {
		store := &Store{Root: t.TempDir()}
		if err := os.MkdirAll(store.archivePath("key1"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreContext(context.Background(), "key1", t.TempDir(), []string{"."}); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("directory archive = %v", err)
		}
	})
	t.Run("oversized archive", func(t *testing.T) {
		store := &Store{Root: t.TempDir(), MaxCacheBytes: 8}
		if err := os.WriteFile(store.archivePath("key1"), []byte("0123456789"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.stripChecksumPath("key1"), []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreContext(context.Background(), "key1", t.TempDir(), []string{"."}); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversized archive = %v", err)
		}
	})
	t.Run("digest mismatch", func(t *testing.T) {
		store := &Store{Root: t.TempDir()}
		if err := os.WriteFile(store.archivePath("key1"), []byte("archive"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.stripChecksumPath("key1"), []byte(strings.Repeat("b", 64)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RestoreContext(context.Background(), "key1", t.TempDir(), []string{"."}); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatalf("digest mismatch = %v", err)
		}
	})
	t.Run("extraction failure with live context", func(t *testing.T) {
		src, key, ws := savedCache(t)
		_ = ws
		dst := t.TempDir()
		orig := extractCacheArchive
		extractCacheArchive = func(*safefs.Root, io.Reader, safefs.ExtractLimits) (*safefs.ExtractStats, error) {
			return nil, errors.New("extract refused")
		}
		t.Cleanup(func() { extractCacheArchive = orig })
		if _, err := src.RestoreContext(context.Background(), key, dst, []string{"."}); err == nil || !strings.Contains(err.Error(), "extract refused") {
			t.Fatalf("extraction failure = %v", err)
		}
	})
}

// TestKeyContextWorkspaceErrors pins the workspace and per-file failure
// branches of the key hash.
func TestKeyContextWorkspaceErrors(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	if _, err := store.KeyContext(context.Background(), "base", filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("missing workspace hashed successfully")
	}
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "dir.bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.KeyContext(context.Background(), "base", ws, []string{"dir.bin"}); err == nil {
		t.Fatal("hashing a directory succeeded")
	}
	// Canceled between glob patterns and matched files.
	if err := os.WriteFile(filepath.Join(ws, "f1"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background()}
	ctx.remaining.Store(3)
	if _, err := store.KeyContext(ctx, "base", ws, []string{"f*"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-hash cancel = %v, want context.Canceled", err)
	}
}

// TestFetchRemoteContextErrors pins the remote download's validation, seam
// and reservation failure branches.
func TestFetchRemoteContextErrors(t *testing.T) {
	body := []byte("archive-bytes")
	cases := []struct {
		name  string
		setup func(t *testing.T, s *Store) (ctx context.Context, key, want string)
	}{
		{
			name: "canceled",
			setup: func(t *testing.T, s *Store) (context.Context, string, string) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, "key1", "canceled"
			},
		},
		{
			name: "invalid key",
			setup: func(t *testing.T, s *Store) (context.Context, string, string) {
				return context.Background(), "bad/key", "invalid cache key"
			},
		},
		{
			name: "sync failure",
			setup: func(t *testing.T, s *Store) (context.Context, string, string) {
				orig := syncCacheFile
				syncCacheFile = func(*os.File) error { return errors.New("sync refused") }
				t.Cleanup(func() { syncCacheFile = orig })
				return context.Background(), "key1", "sync refused"
			},
		},
		{
			name: "close failure",
			setup: func(t *testing.T, s *Store) (context.Context, string, string) {
				orig := closeCacheFile
				closeCacheFile = func(*os.File) error { return errors.New("close refused") }
				t.Cleanup(func() { closeCacheFile = orig })
				return context.Background(), "key1", "close refused"
			},
		},
		{
			name: "rename failure",
			setup: func(t *testing.T, s *Store) (context.Context, string, string) {
				orig := renameCacheFile
				renameCacheFile = func(string, string) error { return errors.New("rename refused") }
				t.Cleanup(func() { renameCacheFile = orig })
				return context.Background(), "key1", "rename refused"
			},
		},
		{
			name: "manager budget refusal",
			setup: func(t *testing.T, s *Store) (context.Context, string, string) {
				s.MaxCacheBytes = 100
				s.Manager = mustManager(t, s.Root, RetentionPolicy{MaxBytes: 50})
				return context.Background(), "key1", "budget"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The budget-refusal case needs an UNKNOWN length (chunked), or
			// the exact Content-Length would substitute for the bound.
			chunked := tc.name == "manager budget refusal"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if chunked {
					if fl, ok := w.(http.Flusher); ok {
						fl.Flush()
					}
				} else {
					w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				}
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			store := &Store{Root: t.TempDir(), RemoteURL: srv.URL, Client: srv.Client()}
			ctx, key, want := tc.setup(t, store)
			err := store.fetchRemoteContext(ctx, key)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("fetch = %v, want it to contain %q", err, want)
			}
		})
	}
	t.Run("non-200 with body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		defer srv.Close()
		store := &Store{Root: t.TempDir(), RemoteURL: srv.URL, Client: srv.Client()}
		if err := store.fetchRemoteContext(context.Background(), "key1"); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("non-200 = %v", err)
		}
	})
}

// TestPushRemoteContextErrors pins the upload's validation and failure
// branches.
func TestPushRemoteContextErrors(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	if err := store.pushRemoteContext(context.Background(), "bad/key"); err == nil {
		t.Fatal("invalid key uploaded")
	}
	if err := store.pushRemoteContext(context.Background(), "missing"); err == nil {
		t.Fatal("missing archive uploaded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.pushRemoteContext(ctx, "missing"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled push = %v", err)
	}
	// Non-2xx response with a body.
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveContext(context.Background(), "key1", ws, []string{"f"}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()
	store.RemoteURL = srv.URL
	store.Client = srv.Client()
	if err := store.pushRemoteContext(context.Background(), "key1"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("non-2xx push = %v", err)
	}
}

// TestMaxStoredBytesResolved pins the exported one-bound resolver.
func TestMaxStoredBytesResolved(t *testing.T) {
	if got := (&Store{}).MaxStoredBytes(); got != defaultCacheArchiveBytes {
		t.Fatalf("default MaxStoredBytes = %d", got)
	}
	if got := (&Store{MaxCacheBytes: 42}).MaxStoredBytes(); got != 42 {
		t.Fatalf("configured MaxStoredBytes = %d", got)
	}
}

// TestOpenExtractRootErrors pins the destination validation branches.
func TestOpenExtractRootErrors(t *testing.T) {
	if _, err := openExtractRoot(""); err == nil {
		t.Fatal("empty destination accepted")
	}
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openExtractRoot(file); err == nil {
		t.Fatal("file destination accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openExtractRoot(link); err == nil {
		t.Fatal("symlink destination accepted")
	}
}

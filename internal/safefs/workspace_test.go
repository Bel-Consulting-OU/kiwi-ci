package safefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestOpenWorkspaceRootRejectsSymlinkDest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWorkspaceRoot(link); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("expected ErrSymlinkParent, got %v", err)
	}
}

func TestOpenWorkspaceRootRequiresExistingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := OpenWorkspaceRoot(missing); err == nil {
		t.Fatal("expected error for missing workspace")
	}
}

func TestOpenRelReadsAndRejects(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "b.txt"), []byte("beta"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	f, err := root.OpenRel("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "alpha" {
		t.Fatalf("OpenRel(a.txt) = %q, %v", b, err)
	}

	f, err = root.OpenRel("sub/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err = io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "beta" {
		t.Fatalf("OpenRel(sub/b.txt) = %q, %v", b, err)
	}

	// A directory is not a regular file.
	if _, err := root.OpenRel("sub"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("OpenRel(sub) error = %v, want ErrNotRegular", err)
	}
	// Traversal is rejected before any syscall.
	for _, rel := range []string{"..", "../x", "a/../../x", "/etc/passwd", ""} {
		if _, err := root.OpenRel(rel); err == nil {
			t.Fatalf("OpenRel(%q) accepted a traversal path", rel)
		}
	}
}

func TestOpenRelRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(ws, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ws, "ok.txt"), filepath.Join(ws, "sub", "inner.txt")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	// A symlink in the final component is rejected without being followed.
	if _, err := root.OpenRel("link.txt"); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("OpenRel(link.txt) error = %v, want ErrSymlinkParent", err)
	}
	// A symlink in an intermediate component is rejected, even when the
	// symlink points back inside the workspace (no-follow is absolute).
	if _, err := root.OpenRel("sub/inner.txt"); !errors.Is(err, ErrSymlinkParent) {
		t.Fatalf("OpenRel(sub/inner.txt) error = %v, want ErrSymlinkParent", err)
	}
}

// TestOpenRelSwapNeverFollows exercises the TOCTOU race directly: a
// goroutine repeatedly replaces a validated regular file with a symlink to
// an outside file while OpenRel runs. The open must either return the
// original file's descriptor or fail — the outside content must never be
// readable through it.
func TestOpenRelSwapNeverFollows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink/rename swap needs unix semantics")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	secret := []byte("OUTSIDE-SECRET-BYTES")
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(ws, "target.txt")
	original := []byte("original-workspace-bytes")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	// The attacker swaps the file for a symlink using atomic renames so the
	// regular-file state always carries the full original content.
	backup := filepath.Join(t.TempDir(), "target.backup")
	if err := os.WriteFile(backup, original, 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Remove(target)
			_ = os.Symlink(filepath.Join(outside, "secret.txt"), target)
			time.Sleep(50 * time.Microsecond)
			_ = os.Remove(target)
			_ = os.Rename(backup, target)
			if err := os.WriteFile(backup, original, 0o644); err != nil {
				return
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()

	for i := 0; i < 500; i++ {
		f, err := root.OpenRel("target.txt")
		if err != nil {
			if errors.Is(err, ErrSymlinkParent) {
				continue
			}
			// A raced unlink surfaces as ENOENT: also a safe failure.
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("OpenRel unexpected error: %v", err)
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatalf("OpenRel read error: %v", err)
		}
		if bytes.Contains(b, secret) {
			t.Fatalf("outside bytes exfiltrated through swapped file: %q", b)
		}
		if !bytes.Equal(b, original) {
			t.Fatalf("unexpected content: %q", b)
		}
	}
	close(stop)
	wg.Wait()
}

func readTarGzEntries(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			out[h.Name] = b
		}
	}
}

// TestWriteTarGzFromRootSwapNeverExfiltrates races archive capture against a
// swap attack: a goroutine replaces a validated file with a symlink to an
// outside file mid-capture. Every captured archive must either contain the
// original bytes or the capture must fail — the outside file's bytes must
// never appear in any archive.
func TestWriteTarGzFromRootSwapNeverExfiltrates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink/rename swap needs unix semantics")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	secret := []byte("OUTSIDE-SECRET-BYTES")
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(ws, "target.txt")
	original := []byte("original-workspace-bytes")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	// The attacker swaps the file for a symlink using atomic renames so the
	// regular-file state always carries the full original content.
	backup := filepath.Join(t.TempDir(), "target.backup")
	if err := os.WriteFile(backup, original, 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Remove(target)
			_ = os.Symlink(filepath.Join(outside, "secret.txt"), target)
			time.Sleep(50 * time.Microsecond)
			_ = os.Remove(target)
			_ = os.Rename(backup, target)
			if err := os.WriteFile(backup, original, 0o644); err != nil {
				return
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()

	succeeded := 0
	for i := 0; i < 50; i++ {
		var buf bytes.Buffer
		if err := WriteTarGzFromRoot(&buf, root, []string{"."}); err != nil {
			continue
		}
		succeeded++
		for name, content := range readTarGzEntries(t, buf.Bytes()) {
			if bytes.Contains(content, secret) {
				t.Fatalf("attempt %d: outside bytes exfiltrated via entry %q: %q", i, name, content)
			}
			if name == "target.txt" && !bytes.Equal(content, original) {
				t.Fatalf("attempt %d: target.txt content corrupted: %q", i, content)
			}
		}
	}
	close(stop)
	wg.Wait()
	if succeeded == 0 {
		t.Fatal("no capture attempt succeeded; the attack window made capture impossible")
	}
}

func TestWriteTarGzFromRootMatchesPathWriter(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var b1, b2 bytes.Buffer
	if err := WriteTarGzFromRoot(&b1, root, []string{"."}); err != nil {
		t.Fatal(err)
	}
	if err := WriteTarGz(&b2, ws, []string{"."}, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Fatal("root-based archive diverges from the path-based writer")
	}
}

package artifact

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// benchArtifactTree writes a representative artifact tree: 12 files of
// 4 KiB across three directories.
func benchArtifactTree(b *testing.B) (dir string, paths []string) {
	b.Helper()
	dir = b.TempDir()
	for d := 0; d < 3; d++ {
		sub := filepath.Join(dir, "dir", string(rune('a'+d)))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			b.Fatal(err)
		}
		for f := 0; f < 4; f++ {
			p := filepath.Join("dir", string(rune('a'+d)), filepath.Base(sub)+strconv.Itoa(f)+".bin")
			if err := os.WriteFile(filepath.Join(dir, p), make([]byte, 4096), 0o644); err != nil {
				b.Fatal(err)
			}
			paths = append(paths, p)
		}
	}
	return dir, paths
}

// BenchmarkArtifactSaveExtract measures the artifact round trip (tar.gz
// creation + digest, then confined extraction) for a 48 KiB tree.
func BenchmarkArtifactSaveExtract(b *testing.B) {
	src, paths := benchArtifactTree(b)
	store := Store{Root: b.TempDir()}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		archive, err := store.Save("run", "job", "art", src, paths)
		if err != nil {
			b.Fatal(err)
		}
		dst, err := os.MkdirTemp("", "artifact-bench-")
		if err != nil {
			b.Fatal(err)
		}
		ws, err := safefs.OpenWorkspaceRoot(dst)
		if err != nil {
			b.Fatal(err)
		}
		if err := Extract(archive, ws.Root, ""); err != nil {
			ws.Close()
			os.RemoveAll(dst)
			b.Fatal(err)
		}
		ws.Close()
		if err := os.RemoveAll(dst); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkArtifactSave measures archive creation alone (the runner-side
// hot path per declared artifact).
func BenchmarkArtifactSave(b *testing.B) {
	src, paths := benchArtifactTree(b)
	store := Store{Root: b.TempDir()}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := store.Save("run", "job", "art", src, paths); err != nil {
			b.Fatal(err)
		}
	}
}

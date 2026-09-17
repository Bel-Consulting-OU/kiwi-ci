//go:build !windows

package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestVerifyArchiveFIFOSeekRefusal pins the seek-refusal path: a FIFO whose
// content and digest match still cannot be rewound. Unix-only (mkfifo).
func TestVerifyArchiveFIFOSeekRefusal(t *testing.T) {
	dir := t.TempDir()
	data := []byte("some archive bytes")
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	go func() {
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		_, _ = w.Write(data)
		_ = w.Close()
	}()
	if err := VerifyArchive(fifo, manifestFor(data)); err == nil || !strings.Contains(err.Error(), "seek") {
		t.Fatalf("fifo archive = %v, want seek failure", err)
	}
}

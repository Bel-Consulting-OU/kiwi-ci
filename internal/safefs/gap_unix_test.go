//go:build !windows

package safefs

import (
	"archive/tar"
	"bytes"
	"errors"
	"strings"
	"syscall"
	"testing"
)

// syscallMkfifo creates a FIFO for capture-skip tests.
func syscallMkfifo(t *testing.T, path string) error {
	t.Helper()
	return syscall.Mkfifo(path, 0o600)
}

// TestOpenParentChainDupFailure proves a descriptor-duplication failure is
// surfaced (test seam, unix-only: dupRootFD is defined in extract_unix.go).
func TestOpenParentChainDupFailure(t *testing.T) {
	orig := dupRootFD
	dupRootFD = func(int) (int, error) { return -1, errors.New("dup refused") }
	defer func() { dupRootFD = orig }()

	dest := t.TempDir()
	root, err := OpenRootNoFollow(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data := tarGz(t, []tarEntry{{name: "f.txt", data: []byte("x"), typeflag: tar.TypeReg}})
	if _, err := Extract(root, bytes.NewReader(data), ExtractLimits{AllowAll: true}); err == nil || !strings.Contains(err.Error(), "dup refused") {
		t.Fatalf("dup failure = %v", err)
	}
}

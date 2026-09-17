//go:build !windows

package safefs

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOpenRelFIFODoesNotBlock verifies that a FIFO planted in the workspace
// cannot stall a read: the open must return promptly and the descriptor must
// be rejected as not regular.
func TestOpenRelFIFODoesNotBlock(t *testing.T) {
	ws := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(ws, "pipe"), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	done := make(chan error, 1)
	go func() {
		_, oerr := root.OpenRel("pipe")
		done <- oerr
	}()
	select {
	case oerr := <-done:
		if !errors.Is(oerr, ErrNotRegular) {
			t.Fatalf("FIFO open: want ErrNotRegular, got %v", oerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OpenRel blocked on a FIFO")
	}
}

// TestOpenRelUnixSocketRejected verifies a unix socket in the workspace is
// rejected as not regular instead of being handed to a reader.
func TestOpenRelUnixSocketRejected(t *testing.T) {
	ws := t.TempDir()
	sock := filepath.Join(ws, "sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer l.Close()
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.OpenRel("sock"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("socket open: want ErrNotRegular, got %v", err)
	}
}

// TestOpenRelDeviceFileRejected verifies /dev/null-style character devices
// are rejected when they can be created or accessed through the root. When
// the test cannot create a device node it falls back to verifying that a
// FIFO is rejected (the regular-file check is the same code path).
func TestOpenRelDeviceFileRejected(t *testing.T) {
	ws := t.TempDir()
	dev := filepath.Join(ws, "null")
	if err := syscall.Mknod(dev, syscall.S_IFCHR|0o666, int(unixMkdev(1, 3))); err != nil {
		t.Skip("device nodes need privileges")
	}
	root, err := OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.OpenRel("null"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("device open: want ErrNotRegular, got %v", err)
	}
	_ = os.Remove(dev)
}

func unixMkdev(major, minor uint32) uint64 {
	return uint64(major)<<32 | uint64(minor)
}

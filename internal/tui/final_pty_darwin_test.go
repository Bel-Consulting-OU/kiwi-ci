//go:build darwin

package tui

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// PTY ioctls from <sys/ttycom.h> on darwin.
const (
	tiocptyGrant = 0x20007454
	tiocptyUnlk  = 0x20007452
	tiocptyGname = 0x40807453
)

// openPTY allocates a real pty pair. Tests skip when the environment provides
// no pty (no /dev/ptmx or a blocked ioctl), so the terminal paths are covered
// wherever a pty exists.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty master available: %v", err)
	}
	ioctl := func(fd uintptr, req uintptr, arg unsafe.Pointer) error {
		_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, req, uintptr(arg), 0, 0, 0)
		if errno != 0 {
			return errno
		}
		return nil
	}
	if err := ioctl(m.Fd(), tiocptyGrant, nil); err != nil {
		_ = m.Close()
		t.Skipf("grantpt: %v", err)
	}
	if err := ioctl(m.Fd(), tiocptyUnlk, nil); err != nil {
		_ = m.Close()
		t.Skipf("unlockpt: %v", err)
	}
	name := make([]byte, 128)
	if err := ioctl(m.Fd(), tiocptyGname, unsafe.Pointer(&name[0])); err != nil {
		_ = m.Close()
		t.Skipf("ptsname: %v", err)
	}
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	s, err := os.OpenFile(string(name), os.O_RDWR, 0)
	if err != nil {
		_ = m.Close()
		t.Skipf("open pty slave %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = s.Close()
		_ = m.Close()
	})
	return m, s
}

// TestFinalRawModeOnPTY proves raw mode actually engages on a real pty:
// rawMode must succeed, clear ECHO/ICANON, and Restore must put the
// original settings back. (The write constant previously encoded TIOCGETA
// with the write direction bit — 0x80487413 — which darwin rejects with
// ENOTTY, so the interactive TUI could never start; darwin's TIOCSETA is
// 0x80487414 and Linux's TCSETS is 0x5402.)
func TestFinalRawModeOnPTY(t *testing.T) {
	_, slave := openPTY(t)
	if !isTerminal(slave.Fd()) {
		t.Fatal("pty slave is not reported as a terminal")
	}
	var before syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, slave.Fd(), ioctlReadTermios, uintptr(unsafe.Pointer(&before)), 0, 0, 0); errno != 0 {
		t.Fatalf("read termios: %v", errno)
	}
	ts, err := rawMode(int(slave.Fd()))
	if err != nil {
		t.Fatalf("rawMode failed: %v (ioctlWriteTermios = %#x)", err, ioctlWriteTermios)
	}
	var raw syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, slave.Fd(), ioctlReadTermios, uintptr(unsafe.Pointer(&raw)), 0, 0, 0); errno != 0 {
		t.Fatalf("read raw termios: %v", errno)
	}
	if raw.Lflag&syscall.ECHO != 0 || raw.Lflag&syscall.ICANON != 0 {
		t.Fatalf("raw mode did not clear ECHO/ICANON: lflag=%#x", raw.Lflag)
	}
	ts.Restore()
	var restored syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, slave.Fd(), ioctlReadTermios, uintptr(unsafe.Pointer(&restored)), 0, 0, 0); errno != 0 {
		t.Fatalf("read restored termios: %v", errno)
	}
	if restored.Lflag != before.Lflag {
		t.Fatalf("Restore did not restore lflag: %#x -> %#x", before.Lflag, restored.Lflag)
	}
}

// TestFinalTermStateRestore covers Restore on a captured state. rawMode
// cannot produce a live state on this host (see TestFinalRawModeOnPTY), so the
// state rawMode would return is constructed here; the restore ioctl and the
// ok reset are the code under test.
func TestFinalTermStateRestore(t *testing.T) {
	_, slave := openPTY(t)
	var captured syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, slave.Fd(), ioctlReadTermios, uintptr(unsafe.Pointer(&captured)), 0, 0, 0); errno != 0 {
		t.Skipf("cannot capture termios: %v", errno)
	}
	ts := &termState{fd: int(slave.Fd()), oldTerm: captured, ok: true}
	ts.Restore()
	if ts.ok {
		t.Fatal("Restore did not reset the state")
	}
	ts.Restore()
}

// ptyFollowServer serves a one-entry backlog and a follow stream that
// delivers one fresh matching entry and stays open until released.
func ptyFollowServer(t *testing.T, release <-chan struct{}) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs/stream") {
			flush := w.(http.Flusher)
			_, _ = w.Write([]byte(`data: {"seq":2,"job_key":"build","step":"s","line":"fresh"}` + "\n\n"))
			flush.Flush()
			select {
			case <-release:
			case <-r.Context().Done():
			}
			_, _ = w.Write([]byte("event: done\n\n"))
			flush.Flush()
			return
		}
		_, _ = w.Write([]byte(`[{"seq":1,"job_key":"build","step":"s","line":"initial"}]`))
	}))
	t.Cleanup(ts.Close)
	return ts
}

// TestFinalRunTerminalStdoutDegrades covers Run's terminal-stdout branch when
// raw mode cannot be enabled: the stdout terminal check passes, rawMode(stdin)
// is attempted, the failed state falls back to rawMode(0), and both failing
// degrades to the plain renderer. Stdin (and fd 0, which the fallback reads)
// point at a non-terminal file while stdout carries the pty, so both ioctls
// fail deterministically.
func TestFinalRunTerminalStdoutDegrades(t *testing.T) {
	_, slave := openPTY(t)
	release := make(chan struct{})
	defer close(release)
	ts := ptyFollowServer(t, release)

	nonTTY, err := os.CreateTemp("", "kiwi-not-a-tty")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nonTTY.Close() })
	if nonTTY.Fd() == 0 {
		t.Skip("temp file landed on fd 0")
	}
	savedStdin, err := syscall.Dup(0)
	if err != nil {
		t.Skipf("cannot duplicate fd 0: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Dup2(savedStdin, 0)
		_ = syscall.Close(savedStdin)
	})
	if err := syscall.Dup2(int(nonTTY.Fd()), 0); err != nil {
		t.Skipf("cannot move the non-terminal onto fd 0: %v", err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = nonTTY, slave
	t.Cleanup(func() { os.Stdin, os.Stdout = oldIn, oldOut })

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Run(ctx, Config{Server: ts.URL, RunID: "run-1", Follow: true}, &out, strings.NewReader("")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[2J") {
		t.Fatalf("interactive frame rendered despite the raw-mode failure: %q", out.String())
	}
	if !strings.Contains(out.String(), "build > s | initial") {
		t.Fatalf("plain render missing the backlog: %q", out.String())
	}
}

// TestFinalRunZeroFdFallback covers the rawMode(0) fallback success path: fd 0
// carries the pty while os.Stdin points at an unrelated non-terminal file, so
// the first rawMode fails, the fallback succeeds against a terminal fd, and
// Run drives the interactive renderer.
func TestFinalRunZeroFdFallback(t *testing.T) {
	_, slave := openPTY(t)
	savedStdin, err := syscall.Dup(0)
	if err != nil {
		t.Skipf("cannot duplicate fd 0: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Dup2(savedStdin, 0)
		_ = syscall.Close(savedStdin)
	})
	if err := syscall.Dup2(int(slave.Fd()), 0); err != nil {
		t.Skipf("cannot move the pty onto fd 0: %v", err)
	}
	nonTTY, err := os.CreateTemp("", "kiwi-not-a-tty")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nonTTY.Close() })
	if nonTTY.Fd() == 0 {
		t.Skip("temp file landed on fd 0")
	}

	release := make(chan struct{})
	defer close(release)
	ts := ptyFollowServer(t, release)

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = nonTTY, slave
	t.Cleanup(func() { os.Stdin, os.Stdout = oldIn, oldOut })

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Run(ctx, Config{Server: ts.URL, RunID: "run-1", Follow: true}, &out, strings.NewReader("")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.String(), "\x1b[2J") {
		t.Fatalf("interactive frame not rendered through the rawMode(0) fallback: %q", out.String())
	}
	if !strings.Contains(out.String(), "build > s | initial") {
		t.Fatalf("plain render missing the backlog: %q", out.String())
	}
}

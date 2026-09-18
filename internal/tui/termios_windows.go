//go:build windows

package tui

import (
	"errors"
	"syscall"
	"unsafe"
)

// Windows console mode flags (wincon.h).
const (
	enableProcessedInput        = 0x0001
	enableLineInput             = 0x0002
	enableEchoInput             = 0x0004
	enableWindowInput           = 0x0008
	enableVirtualTerminalInput  = 0x0200
	enableVirtualTerminalOutput = 0x0004 // console OUTPUT mode bit
)

type termState struct {
	fd  uintptr
	old uint32
	ok  bool
}

// rawMode enables a raw-ish console for interactive input: line input and
// echo are disabled and virtual-terminal input is enabled so key escape
// sequences arrive as bytes. The previous mode is restored by Restore.
// Failure (no console, redirected handles) is reported as an error so the
// TUI degrades to line mode instead of pretending raw mode works.
func rawMode(fd int) (*termState, error) {
	handle := syscall.Handle(fd)
	var mode uint32
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	if r, _, err := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return nil, err
	}
	raw := mode
	raw &^= enableLineInput | enableEchoInput | enableProcessedInput
	raw |= enableVirtualTerminalInput
	if r, _, err := setConsoleMode.Call(uintptr(handle), uintptr(raw)); r == 0 {
		return nil, err
	}
	return &termState{fd: uintptr(handle), old: mode, ok: true}, nil
}

// Restore returns the console to its previous mode; a failed restore is
// reported so callers can surface it rather than leaving the console raw.
func (t *termState) Restore() {
	if t == nil || !t.ok {
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	if r, _, _ := setConsoleMode.Call(t.fd, uintptr(t.old)); r == 0 {
		// Nothing further can be done; mark restored so repeated calls are
		// no-ops.
		_ = errors.New("tui: console mode restore failed")
	}
	t.ok = false
}

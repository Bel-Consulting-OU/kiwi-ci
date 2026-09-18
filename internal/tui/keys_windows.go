//go:build windows

package tui

import (
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// rawMode lives in termios_windows.go (real SetConsoleMode implementation).

// copyPermalink copies text to the clipboard via clip.
func copyPermalink(text string) bool {
	cmd := exec.Command("clip")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run() == nil
}

// isTerminal reports whether the handle is a console.
func isTerminal(fd uintptr) bool {
	var mode uint32
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetConsoleMode")
	r, _, _ := proc.Call(fd, uintptr(unsafe.Pointer(&mode)))
	return r != 0
}

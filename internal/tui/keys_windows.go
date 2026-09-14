//go:build windows

package tui

import (
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

type termState struct{ ok bool }

func rawMode(fd int) (*termState, error) {
	return &termState{ok: true}, nil
}

func (t *termState) Restore() { t.ok = false }

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
	r, _, _ := proc.Call(fd, uintptr(unsafePtr(&mode)))
	return r != 0
}

func unsafePtr(p *uint32) uintptr { return uintptr(unsafe.Pointer(p)) }

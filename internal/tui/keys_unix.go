//go:build !windows

package tui

import (
	"syscall"
	"unsafe"
)

type termState struct {
	fd      int
	oldTerm syscall.Termios
	ok      bool
}

// rawMode puts the terminal into raw mode; Restore returns it.
func rawMode(fd int) (*termState, error) {
	var old syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), ioctlReadTermios, uintptr(unsafe.Pointer(&old)), 0, 0, 0); errno != 0 {
		return nil, errno
	}
	raw := old
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), ioctlWriteTermios, uintptr(unsafe.Pointer(&raw)), 0, 0, 0); errno != 0 {
		return nil, errno
	}
	return &termState{fd: fd, oldTerm: old, ok: true}, nil
}

func (t *termState) Restore() {
	if t == nil || !t.ok {
		return
	}
	_, _, _ = syscall.Syscall6(syscall.SYS_IOCTL, uintptr(t.fd), ioctlWriteTermios, uintptr(unsafe.Pointer(&t.oldTerm)), 0, 0, 0)
	t.ok = false
}

const (
	ioctlReadTermios  = 0x40487413
	ioctlWriteTermios = 0x80487413
)

// isTerminal reports whether fd is a character device terminal.
func isTerminal(fd uintptr) bool {
	var term syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, ioctlReadTermios, uintptr(unsafe.Pointer(&term)), 0, 0, 0)
	return errno == 0
}

// copyPermalink copies text to the system clipboard via the first available
// platform tool.
func copyPermalink(text string) bool {
	for _, tool := range []struct {
		name string
		args []string
	}{
		{"pbcopy", nil},
		{"wl-copy", nil},
		{"xclip", []string{"-selection", "clipboard"}},
		{"xsel", []string{"--clipboard", "--input"}},
	} {
		if err := execTool(tool.name, tool.args, text); err == nil {
			return true
		}
	}
	return false
}

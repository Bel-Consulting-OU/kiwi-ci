//go:build darwin

package tui

// Darwin termios ioctl request numbers:
//
//	TIOCGETA = _IOR('t', 19, struct termios) = 0x40487413
//	TIOCSETA = _IOW('t', 20, struct termios) = 0x80487414
//
// The write request was previously misdeclared as 0x80487413 (TIOCGETA with
// the write direction bit), which macOS rejects with ENOTTY, so raw mode
// never engaged. Keep TIOCSETA's own number.
const (
	ioctlReadTermios  = 0x40487413
	ioctlWriteTermios = 0x80487414
)

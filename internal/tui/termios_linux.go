//go:build linux

package tui

// Linux termios ioctl request numbers (asm-generic):
//
//	TCGETS = 0x5401
//	TCSETS = 0x5402
const (
	ioctlReadTermios  = 0x5401
	ioctlWriteTermios = 0x5402
)

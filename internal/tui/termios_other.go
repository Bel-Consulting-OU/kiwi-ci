//go:build !windows && !darwin && !linux

package tui

// Unsupported Unix: raw mode is unavailable; callers degrade to line mode
// because rawMode fails closed (the request numbers below never succeed).
const (
	ioctlReadTermios  = 0
	ioctlWriteTermios = 0
)

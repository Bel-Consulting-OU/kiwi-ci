package executor

import (
	"fmt"
	"runtime"
	"strconv"
)

// nativeScript returns the POSIX script on Unix hosts and the PowerShell
// script on Windows hosts. Tests that drive the native backend through a
// real shell use it so the same fixture runs on both host families without
// POSIX-only tools (test, touch, dd, ln).
func nativeScript(posix, windows string) string {
	if runtime.GOOS == "windows" {
		return windows
	}
	return posix
}

// writeBytesScript returns a native-shell one-liner that writes a file of n
// zero bytes at path (the `dd if=/dev/zero` equivalent for both host
// families).
func writeBytesScript(path string, n int) string {
	return nativeScript(
		"dd if=/dev/zero of="+path+" bs="+strconv.Itoa(n)+" count=1 2>/dev/null",
		fmt.Sprintf("[IO.File]::WriteAllBytes('%s', [byte[]]::new(%d))", path, n),
	)
}

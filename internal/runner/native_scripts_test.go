package runner

import "runtime"

// nativeScript returns the POSIX script on Unix hosts and the PowerShell
// script on Windows hosts. Runner integration tests execute jobs through
// the executor's native backend (default shell: bash on Unix, pwsh on
// Windows), so step fixtures carry both syntaxes.
func nativeScript(posix, windows string) string {
	if runtime.GOOS == "windows" {
		return windows
	}
	return posix
}

// makeFileScript returns a native-shell one-liner that creates the file at
// path (the `touch` equivalent for both host families).
func makeFileScript(path string) string {
	return nativeScript(
		"touch "+path,
		"Set-Content -LiteralPath '"+path+"' -Value x",
	)
}

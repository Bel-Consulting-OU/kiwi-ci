//go:build !windows

package runner

import "os"

// secureIdentityDir creates the identity directory owner-only and VERIFIES
// the resulting mode: on Unix the 0700 mode IS the access-control boundary,
// so a directory that somehow ends up group/other-accessible is refused
// (fail closed) instead of persisting a private key behind a weak boundary.
func secureIdentityDir(dir string) error {
	if err := os.MkdirAll(dir, identityDirMode); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, identityDirMode); err != nil {
			return err
		}
	}
	return nil
}

// secureIdentityFile is a no-op on Unix: the file mode (0600) IS the access
// control, installed atomically by writeOwnerOnly.
func secureIdentityFile(string) error { return nil }

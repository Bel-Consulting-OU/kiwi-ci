//go:build unix

package app

import (
	"fmt"
	"os"
	"syscall"
)

// verifyUpStateDirOwner refuses a state directory the effective user does not
// own: on a shared host an attacker-owned directory could serve planted state
// or capture the persisted token.
func verifyUpStateDirOwner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("not owned by the current user")
	}
	return nil
}

// verifyUpTokenFileOwner refuses a token file the effective user does not own.
func verifyUpTokenFileOwner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("not owned by the current user")
	}
	return nil
}

// verifyUpTokenFileMode refuses a token file that is readable or writable by
// anyone but its owner.
func verifyUpTokenFileMode(info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm != 0o600 {
		return fmt.Errorf("has mode %o, want 0600 (chmod 600 it or remove it to regenerate)", perm)
	}
	return nil
}

// openUpTokenRead opens the token file refusing a symlink as the final path
// component (O_NOFOLLOW), so a swapped-in link cannot redirect the read; the
// caller re-verifies the opened descriptor.
func openUpTokenRead(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// createUpTokenExclusive creates the token file exclusively: O_EXCL fails if
// anything already exists at the path (including a symlink), so the generated
// credential can never be written through an attacker-planted path.
func createUpTokenExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
}

//go:build windows

package executor

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteOwnerOnly writes data into a fresh file inside the caller's
// user-scoped local application-data directory (os.UserCacheDir, i.e.
// %LOCALAPPDATA%). Directory-level ACLs there are the Windows owner-only
// equivalent: Windows file modes do not encode permissions and files created
// even with mode 0 still inherit the surrounding directory ACL, so instead of
// a fragile file-level DACL the file is placed where only the calling user
// can already read it. The base name of path is preserved under a kiwi
// specific MkdirTemp subdirectory, so every call yields a new, non-clobbering
// file scoped to the current user. It RETURNS the path actually written: the
// requested path is not used on Windows, and silently writing elsewhere while
// claiming success at the caller's path violated this function's contract.
func WriteOwnerOnly(path string, data []byte) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user-scoped directory: %w", err)
	}
	dir, err := os.MkdirTemp(base, "kiwi-keys-")
	if err != nil {
		return "", fmt.Errorf("create user-scoped key directory: %w", err)
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = "key"
	}
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dst, nil
}

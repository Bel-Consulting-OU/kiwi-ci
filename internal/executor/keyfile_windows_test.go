//go:build windows

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteOwnerOnlyWindowsScope asserts the Windows implementation lands the
// file inside the caller's user-scoped %LOCALAPPDATA% tree and that it is
// readable with the written content. Directory ACLs there are the Windows
// owner-only equivalent, so no file-level DACL assertion is made (Windows
// file modes do not encode access control).
func TestWriteOwnerOnlyWindowsScope(t *testing.T) {
	name := "kiwi-keyfile-test-key"
	if err := WriteOwnerOnly(filepath.Join(t.TempDir(), name), []byte("secret")); err != nil {
		t.Fatal(err)
	}
	local, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := os.ReadDir(local)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range dirs {
		if !d.IsDir() || !strings.HasPrefix(d.Name(), "kiwi-keys-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(local, d.Name(), name))
		if err == nil && string(data) == "secret" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no owner-only key file with matching content found under %s/kiwi-keys-*/%s", local, name)
	}
}

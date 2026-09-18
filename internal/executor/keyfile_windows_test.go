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
	requested := filepath.Join(t.TempDir(), name)
	written, err := WriteOwnerOnly(requested, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// The contract is the RETURNED path: Windows deliberately writes into a
	// user-scoped directory instead of the requested location, and callers
	// must use what the function reports.
	if written == "" || written == requested {
		t.Fatalf("WriteOwnerOnly returned %q; want the actual user-scoped path", written)
	}
	if b, rerr := os.ReadFile(written); rerr != nil || string(b) != "secret" {
		t.Fatalf("returned path unreadable: %v", rerr)
	}
	if _, statErr := os.Stat(requested); statErr == nil {
		t.Fatal("requested path must not exist (the function writes elsewhere on Windows)")
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

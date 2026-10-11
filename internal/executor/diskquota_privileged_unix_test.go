//go:build unix

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidatePrivilegedToolRefusals covers the path-shape, stat and
// ownership gates of the recorded-helper proof. The property it checks —
// executable bits and filesystem ownership — is a unix property, so the test
// lives on unix, not only on Linux.
func TestValidatePrivilegedToolRefusals(t *testing.T) {
	if err := validatePrivilegedTool("relative/tool"); err == nil {
		t.Fatal("relative tool accepted")
	}
	if err := validatePrivilegedTool("/usr/bin/../bin/true"); err == nil {
		t.Fatal("dot-dot tool accepted")
	}
	if err := validatePrivilegedTool(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing tool accepted")
	}
	if err := validatePrivilegedTool("/dev/null"); err == nil {
		t.Fatal("non-regular tool accepted")
	}
	if os.Geteuid() != 0 {
		if err := validatePrivilegedTool("/bin/sh"); err == nil || !strings.Contains(err.Error(), "not owned by the runner") {
			t.Fatalf("foreign-owned tool = %v", err)
		}
	}
}

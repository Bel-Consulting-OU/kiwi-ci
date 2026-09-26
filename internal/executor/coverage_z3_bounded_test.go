package executor

import (
	"testing"
	"time"

	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

// TestBoundedToolCommandNilParent pins the nil-parent contract: a caller with
// no context still gets the detached bounded execution instead of a panic.
func TestBoundedToolCommandNilParent(t *testing.T) {
	testutil.UnixShell(t)
	fake := writeCleanupScript(t, "tool", "#!/bin/sh\nexit 0\n")
	//lint:ignore SA1012 the nil-parent branch is the behavior under test
	if _, err := boundedToolCommand(nil, 5*time.Second, fake, "delete"); err != nil {
		t.Fatalf("boundedToolCommand(nil parent) = %v", err)
	}
}

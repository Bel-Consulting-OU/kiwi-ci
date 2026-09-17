//go:build !windows

package tui

import "testing"

// TestTermStateRestoreNonOK covers Restore on a state that never engaged
// (unix termState carries fd; the Windows variant has a different shape).
func TestTermStateRestoreNonOK(t *testing.T) {
	notOK := &termState{fd: -1}
	notOK.Restore()
	if notOK.ok {
		t.Fatal("Restore must leave the state non-ok")
	}
}

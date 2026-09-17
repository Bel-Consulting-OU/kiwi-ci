//go:build windows

package safefs

import (
	"errors"
	"testing"
)

// syscallMkfifo is unavailable on windows; callers log and continue.
func syscallMkfifo(t *testing.T, path string) error {
	t.Helper()
	return errors.New("mkfifo unsupported")
}

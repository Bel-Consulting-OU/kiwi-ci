package runner

import (
	"os"
	"testing"
)

// TestMain isolates the whole runner test binary from the developer's real
// home: the stable bearer identity persists under ~/.kiwi, so an unisolated
// run would both depend on and pollute the invoking user's actual runner
// identity. KIWI_TEST_REAL_HOME=1 opts out for debugging.
func TestMain(m *testing.M) {
	if os.Getenv("KIWI_TEST_REAL_HOME") == "" {
		if dir, err := os.MkdirTemp("", "kiwi-runner-test-home-"); err == nil {
			_ = os.Setenv("HOME", dir)
			code := m.Run()
			_ = os.RemoveAll(dir)
			os.Exit(code)
		}
	}
	os.Exit(m.Run())
}

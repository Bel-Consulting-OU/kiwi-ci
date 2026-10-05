package runner

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates the whole runner test binary from the developer's real
// home: the stable bearer identity persists under ~/.kiwi, so an unisolated
// run would both depend on and pollute the invoking user's actual runner
// identity. KIWI_TEST_REAL_HOME=1 opts out for debugging.
func TestMain(m *testing.M) {
	if os.Getenv("KIWI_TEST_REAL_HOME") == "" {
		realHome, _ := os.UserHomeDir()
		if dir, err := os.MkdirTemp("", "kiwi-runner-test-home-"); err == nil {
			_ = os.Setenv("HOME", dir)
			// The process-boundary test builds the kiwi binary in a child
			// `go build`: with an isolated HOME the Go module/build caches
			// would fall back to empty paths and the build would try to
			// re-download the module graph (hanging when the network is
			// restricted). Pin the REAL caches explicitly.
			if realHome != "" {
				pin := func(key, fallback string) {
					if os.Getenv(key) == "" {
						_ = os.Setenv(key, fallback)
					}
				}
				pin("GOPATH", filepath.Join(realHome, "go"))
				pin("GOMODCACHE", filepath.Join(realHome, "go", "pkg", "mod"))
				pin("GOCACHE", filepath.Join(realHome, ".cache", "go-build"))
			}
			code := m.Run()
			_ = os.RemoveAll(dir)
			os.Exit(code)
		}
	}
	os.Exit(m.Run())
}

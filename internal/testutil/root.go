package testutil

import (
	"os"
	"testing"
)

// RequireNonRoot skips the calling (sub)test when it runs as root. Failure
// injection that relies on permission bits (chmod making a directory
// unwritable or a file unreadable/unopenable) can only fail for a non-root
// process: uid 0 bypasses the read/write/execute permission checks (POSIX
// CAP_DAC_OVERRIDE), so the OS would happily perform the "forbidden"
// operation and the assertion would silently become a tautology in a root
// container. Prefer a real failure seam, or a root-proof injection (a
// non-directory in the way, a directory where a file is renamed), over this
// skip; use it only where the invariant genuinely is "the OS denies this
// write/read for an unprivileged process".
func RequireNonRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-bit failure injection requires a non-root euid: root bypasses chmod read/write restrictions")
	}
}

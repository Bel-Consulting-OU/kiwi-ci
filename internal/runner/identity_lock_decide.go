package runner

import (
	"strconv"
	"strings"
)

// identityLockOutcome is the conservative classification of an existing
// identity lock file on platforms without flock.
type identityLockOutcome int

const (
	// identityLockLive: a live owner (or one Kiwi cannot prove dead) holds
	// the identity. The competitor must refuse.
	identityLockLive identityLockOutcome = iota
	// identityLockStale: the recorded owner PID is positively parsed and
	// positively proven dead. The file may be reclaimed.
	identityLockStale
)

// classifyIdentityLock decides whether an existing lock file may be
// reclaimed. Doubt means LIVE: an empty, partially written, malformed or
// unparsable file may be a concurrent creator between O_EXCL and its PID
// publication (the creation window), so it must NEVER be removed on that
// basis. Only a positively parsed, positively dead PID is reclaimable.
// This mirrors the staging/cache ownership rule (unknown = live).
func classifyIdentityLock(data []byte, alive func(pid int) bool) identityLockOutcome {
	// The writer publishes "%d\n": a file without the terminating newline is
	// a PARTIAL write (the owner may still be mid-publication), so a numeric
	// prefix like "12" must not be mistaken for PID 12.
	if !strings.HasSuffix(string(data), "\n") {
		return identityLockLive
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		// Creation may still be in progress: doubt is LIVE.
		return identityLockLive
	}
	if alive == nil || alive(pid) {
		return identityLockLive
	}
	return identityLockStale
}

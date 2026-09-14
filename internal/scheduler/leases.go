package scheduler

import "time"

// LeaseExpiry returns the lease expiration for a claim taken at now. A
// non-positive duration falls back to DefaultLeaseDuration so a misconfigured
// scheduler degrades to the safe default instead of issuing instantly
// expired (or far-future) leases.
func LeaseExpiry(now time.Time, dur time.Duration) time.Time {
	if dur <= 0 {
		dur = DefaultLeaseDuration
	}
	return now.Add(dur)
}

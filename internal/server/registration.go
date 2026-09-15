package server

import (
	"fmt"
	"math"
	"regexp"
)

// runnerLabelRegexp matches the label grammar shared with the pipeline
// language (internal/pipeline): a leading alphanumeric followed by up to 63
// alphanumerics, dots, colons, underscores or hyphens.
var runnerLabelRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:_-]{0,63}$`)

// runnerRegionRegexp matches a runner region: up to 64 characters of
// alphanumerics, dots, underscores or hyphens (e.g. "east", "us-east-1",
// "eu.west").
var runnerRegionRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// maxRunnerCapacity bounds the advertised concurrency of a single runner.
const maxRunnerCapacity = 4096

// validateRunnerRegistration enforces the server-side invariants of a
// runner registration: capacity within 0..4096, every label matching the
// label grammar, a region within the region grammar, the protocol range
// overlapping [ProtocolMin, ProtocolMax] (clamped to it), and finite,
// non-negative cost/energy rates (NaN/Inf/negative would silently corrupt
// usage accounting and must never be accepted). ActiveJobs/CurrentJob and
// other server-owned state are deliberately ignored: the server
// reconstructs them.
func validateRunnerRegistration(in *RunnerInfo) error {
	if in == nil {
		return fmt.Errorf("runner registration is required")
	}
	if in.ProtocolMin == 0 && in.ProtocolMax == 0 {
		return fmt.Errorf("protocol version required")
	}
	if in.ProtocolMax < ProtocolMin || in.ProtocolMin > ProtocolMax {
		return fmt.Errorf("unsupported protocol version")
	}
	if in.ProtocolMin < ProtocolMin {
		in.ProtocolMin = ProtocolMin
	}
	if in.ProtocolMax > ProtocolMax {
		in.ProtocolMax = ProtocolMax
	}
	if in.Capacity < 0 || in.Capacity > maxRunnerCapacity {
		return fmt.Errorf("capacity must be in 0..%d, got %d", maxRunnerCapacity, in.Capacity)
	}
	for _, l := range in.Labels {
		if !runnerLabelRegexp.MatchString(l) {
			return fmt.Errorf("invalid runner label %q", l)
		}
	}
	if in.Region != "" && !runnerRegionRegexp.MatchString(in.Region) {
		return fmt.Errorf("invalid runner region %q", in.Region)
	}
	if !finiteNonNegative(in.CostPerHour) {
		return fmt.Errorf("cost_per_hour must be finite and non-negative, got %v", in.CostPerHour)
	}
	if !finiteNonNegative(in.PowerWatts) {
		return fmt.Errorf("power_watts must be finite and non-negative, got %v", in.PowerWatts)
	}
	return nil
}

// finiteNonNegative reports whether v is a finite number >= 0.
func finiteNonNegative(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

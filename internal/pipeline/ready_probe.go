package pipeline

import (
	"fmt"
	"strconv"
	"strings"
)

// validateReadyProbe enforces the exact readiness grammar so the executor
// can trust declarations at runtime:
//
//	tcp:<port>
//	http:<port>/<path>
//
// Anything else (including http:8123 without a path) is rejected at
// validation time.
func validateReadyProbe(probe string) error {
	kind, rest, ok := strings.Cut(probe, ":")
	if !ok {
		return fmt.Errorf("ready probe %q must be tcp:<port> or http:<port>/<path>", probe)
	}
	switch kind {
	case "tcp":
		port, err := strconv.Atoi(rest)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("ready probe %q: tcp port must be 1-65535", probe)
		}
		return nil
	case "http":
		i := strings.IndexByte(rest, '/')
		if i <= 0 {
			return fmt.Errorf("ready probe %q must be http:<port>/<path> (path required)", probe)
		}
		port, err := strconv.Atoi(rest[:i])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("ready probe %q: http port must be 1-65535", probe)
		}
		if rest[i:] == "/" || strings.ContainsAny(rest[i:], " \t") {
			return fmt.Errorf("ready probe %q: http path must be a non-empty path without spaces", probe)
		}
		return nil
	default:
		// Historical probes: pg_isready:5432 and healthcheck scripts.
		// Keep accepting kind:rest for non-native container helpers that
		// already use custom probes, but only after a non-empty rest.
		if rest == "" {
			return fmt.Errorf("ready probe %q is empty after kind %q", probe, kind)
		}
		if _, err := strconv.Atoi(rest); err == nil {
			// kind:port form for other probes (pg_isready:5432).
			return nil
		}
		return fmt.Errorf("ready probe %q must be tcp:<port>, http:<port>/<path>, or <kind>:<arg>", probe)
	}
}

// readyProbePort extracts a concrete TCP/HTTP port from a validated probe.
// Returns (0,false) when the probe has no numeric port.
func readyProbePort(probe string) (int, bool) {
	kind, rest, ok := strings.Cut(probe, ":")
	if !ok || (kind != "tcp" && kind != "http") {
		return 0, false
	}
	n := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		n = rest[:i]
	}
	port, err := strconv.Atoi(n)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

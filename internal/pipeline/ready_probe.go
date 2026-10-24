package pipeline

import (
	"fmt"
	"strconv"
	"strings"
)

// ReadyProbeKind is the readiness probe family.
type ReadyProbeKind string

const (
	ReadyProbeTCP  ReadyProbeKind = "tcp"
	ReadyProbeHTTP ReadyProbeKind = "http"
	// ReadyProbeArg is a non-standard helper form such as pg_isready:5432.
	ReadyProbeArg ReadyProbeKind = "arg"
)

// ReadyProbe is the single parsed form of a service readiness declaration.
// Validation and the executor share this parser so grammar cannot diverge.
type ReadyProbe struct {
	Kind ReadyProbeKind
	// Port is the concrete TCP port (0 only for ReadyProbeArg without a numeric arg).
	Port uint16
	// Path is the HTTP path including the leading slash (http only).
	Path string
	// Arg is the raw remainder for ReadyProbeArg.
	Arg string
}

// ParseReadyProbe parses `tcp:<port>`, `http:<port>/<path>`, or
// `<kind>:<arg>` (for example pg_isready:5432). Anything else is an error.
func ParseReadyProbe(probe string) (ReadyProbe, error) {
	kind, rest, ok := strings.Cut(probe, ":")
	if !ok || rest == "" {
		return ReadyProbe{}, fmt.Errorf("ready probe %q must be tcp:<port>, http:<port>/<path>, or <kind>:<arg>", probe)
	}
	switch kind {
	case "tcp":
		port, err := parsePort(rest)
		if err != nil {
			return ReadyProbe{}, fmt.Errorf("ready probe %q: %w", probe, err)
		}
		return ReadyProbe{Kind: ReadyProbeTCP, Port: port}, nil
	case "http":
		i := strings.IndexByte(rest, '/')
		if i <= 0 {
			return ReadyProbe{}, fmt.Errorf("ready probe %q must be http:<port>/<path> (path required)", probe)
		}
		port, err := parsePort(rest[:i])
		if err != nil {
			return ReadyProbe{}, fmt.Errorf("ready probe %q: %w", probe, err)
		}
		path := rest[i:]
		if path == "/" || strings.ContainsAny(path, " \t") {
			return ReadyProbe{}, fmt.Errorf("ready probe %q: http path must be a non-empty path without spaces", probe)
		}
		return ReadyProbe{Kind: ReadyProbeHTTP, Port: port, Path: path}, nil
	default:
		if p, err := strconv.Atoi(rest); err == nil {
			if p < 1 || p > 65535 {
				return ReadyProbe{}, fmt.Errorf("ready probe %q: port must be 1-65535", probe)
			}
			return ReadyProbe{Kind: ReadyProbeArg, Port: uint16(p), Arg: rest}, nil
		}
		return ReadyProbe{}, fmt.Errorf("ready probe %q must be tcp:<port>, http:<port>/<path>, or <kind>:<arg>", probe)
	}
}

func parsePort(s string) (uint16, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be 1-65535, got %q", s)
	}
	return uint16(port), nil
}

// readyProbePort extracts a concrete TCP/HTTP port from a probe string.
// Returns (0,false) when the probe has no numeric TCP/HTTP port.
func readyProbePort(probe string) (int, bool) {
	p, err := ParseReadyProbe(probe)
	if err != nil || (p.Kind != ReadyProbeTCP && p.Kind != ReadyProbeHTTP) {
		return 0, false
	}
	if p.Port == 0 {
		return 0, false
	}
	return int(p.Port), true
}

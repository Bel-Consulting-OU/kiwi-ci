// Package version holds build-time identity for the kiwi binary and the
// protocol/schema versions the control plane and pipeline format speak.
//
// Version, Commit, BuildDate and Dirty are intended to be overridden with
// -ldflags at release time (see the Makefile in a later phase); the defaults
// here describe an unreleased development build.
package version

import "runtime"

var (
	// Version is the semantic version of this build. Development builds are
	// "0.1.0-dev"; releases set the exact tag via ldflags.
	Version = "0.1.0-dev"
	// Commit is the VCS revision the binary was built from (empty for
	// unannotated dev builds).
	Commit = ""
	// BuildDate is the RFC3339 timestamp of the build (empty for dev builds).
	BuildDate = ""
	// Dirty is "true" when the working tree had uncommitted changes at build
	// time, "false" or empty otherwise.
	Dirty = ""
	// GoVersion is the Go toolchain used to compile the binary.
	GoVersion = runtime.Version()
	// ProtocolVersion is the runner API protocol version range this binary
	// speaks (matches server.ProtocolMin/ProtocolMax).
	ProtocolVersion = "3"
	// PipelineSchemaVersion is the pipeline YAML schema version.
	PipelineSchemaVersion = "1"
	// StorageSchemaVersion is the persisted state snapshot schema version.
	StorageSchemaVersion = "1"
)

// String returns the human-readable version: the semver plus the commit when
// known, e.g. "0.1.0-dev" or "1.2.3 (a1b2c3d)".
func String() string {
	s := Version
	if Commit != "" {
		s += " (" + Commit + ")"
	}
	return s
}

// Full returns every build identity field as a map, suitable for `kiwi
// version --full` style output or embedding in telemetry.
func Full() map[string]string {
	return map[string]string{
		"version":                 Version,
		"commit":                  Commit,
		"build_date":              BuildDate,
		"dirty":                   Dirty,
		"go_version":              GoVersion,
		"protocol_version":        ProtocolVersion,
		"pipeline_schema_version": PipelineSchemaVersion,
		"storage_schema_version":  StorageSchemaVersion,
	}
}

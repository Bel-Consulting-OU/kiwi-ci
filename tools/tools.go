//go:build tools

// Package tools pins the build-time analysis binaries used by the release
// gates so their versions and the x/tools override live in one module,
// separate from the shipped module graph.
package tools

import _ "honnef.co/go/tools/cmd/staticcheck"

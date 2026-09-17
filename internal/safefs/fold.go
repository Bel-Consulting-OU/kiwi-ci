package safefs

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// foldPath canonicalizes an archive entry name for duplicate detection.
// On case-insensitive filesystems it lowercases and Unicode-normalizes the
// name to NFC: those filesystems (macOS/APFS, Windows/NTFS in their default
// configurations) treat case variants and NFC/NFD-normalization variants as
// the same file, so extraction must reject both as duplicates before any
// write happens. On case-sensitive filesystems the name is returned
// unchanged.
func foldPath(name string) string {
	if !foldCaseInsensitive {
		return name
	}
	return norm.NFC.String(strings.ToLower(name))
}

// foldCaseInsensitive is a test-only seam over the platform
// caseInsensitiveFS constant. Production behavior is unchanged; it lets the
// case-sensitive branch (live on case-sensitive filesystems) be exercised on
// a case-insensitive host.
var foldCaseInsensitive = caseInsensitiveFS

//go:build darwin

package safefs

// macOS filesystems are typically case-insensitive; archive entries that
// collide after case folding would overwrite each other.
const caseInsensitiveFS = true

//go:build darwin

package safefs

// macOS filesystems are typically case-insensitive and
// normalization-insensitive; archive entries that collide after case
// folding or Unicode normalization would overwrite each other. fold.go
// applies both folds.
const caseInsensitiveFS = true

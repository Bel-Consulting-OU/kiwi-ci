//go:build windows

package safefs

// Windows filesystems (NTFS/FAT) are case-insensitive; archive entries that
// collide after case folding would overwrite each other. Folding is also
// Unicode-normalized in fold.go so a case-insensitive destination cannot
// merge two distinct entry names.
const caseInsensitiveFS = true

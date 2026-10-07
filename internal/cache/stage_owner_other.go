//go:build !unix

package cache

import "os"

// stageOwnedByCurrentUser is a no-op ownership gate on platforms without
// Unix file ownership; the exact workspace-scoped prefix still bounds what
// crash reclaim can ever match.
func stageOwnedByCurrentUser(os.FileInfo) bool { return true }

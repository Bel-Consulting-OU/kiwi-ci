package fsutil

import (
	"os"
	"sync"
)

// Hooks overrides individual durability steps of AtomicWriteFile and SyncDir
// so fault-injection tests can prove that a failed step is surfaced and never
// acknowledged. Every phase of AtomicWriteFile is injectable: Write and Chmod
// cover the payload and mode steps, and FileSync/FileClose/Rename/DirSync
// cover the durability steps. A nil field keeps the production behavior
// (f.Write, os.Chmod, RealFileSync, RealFileClose, RealRename, RealSyncDir);
// a hook that needs the real behavior (to wrap or count it) calls the
// corresponding Real* function directly (or f.Write / os.Chmod for the Write
// and Chmod hooks), because calling the hooked entry point from inside a hook
// would recurse.
//
// A FileClose hook that returns an error must still close the file: the
// production path relies on the checked close having released the descriptor,
// and the cleanup path (temp removal after a failed write) uses RealFileClose
// regardless of hooks.
//
// Hooks are process-global and swapped under a mutex, so a concurrent reader
// observes either the whole previous set or the whole new set, and the race
// detector sees no unsynchronized access. Tests must install hooks with
// SetHooks and restore them before any other test depends on the real
// behavior (the returned restore function does this, typically via
// t.Cleanup).
type Hooks struct {
	// Write overrides the payload write step. It receives the temp file and
	// the payload and returns the byte count like os.File.Write; a hook that
	// wants the real write just calls f.Write(b).
	Write func(f *os.File, b []byte) (int, error)
	// Chmod overrides the mode step for the temp file (name is the temp path).
	// A hook that wants the real behavior calls os.Chmod(name, mode).
	Chmod     func(name string, mode os.FileMode) error
	FileSync  func(f *os.File) error
	FileClose func(f *os.File) error
	Rename    func(oldpath, newpath string) error
	DirSync   func(dir string) error
}

var (
	hooksMu sync.RWMutex
	hooks   Hooks
)

// SetHooks installs h for the calling test and returns a function that
// restores the previous hooks. Production code never calls it.
func SetHooks(h Hooks) (restore func()) {
	hooksMu.Lock()
	prev := hooks
	hooks = h
	hooksMu.Unlock()
	return func() {
		hooksMu.Lock()
		hooks = prev
		hooksMu.Unlock()
	}
}

// currentHooks returns a consistent snapshot of the installed hooks.
func currentHooks() Hooks {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	return hooks
}

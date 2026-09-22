package storage

import (
	"os"
	"path/filepath"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// AtomicWriteFile durably replaces path with data. It delegates to the shared
// internal/fsutil primitive:
//
//  1. write the bytes to a UNIQUE temp file in the target directory,
//  2. chmod it to perm,
//  3. Sync the file (checked),
//  4. Close the file (checked),
//  5. rename the temp file over path,
//  6. fsync the parent directory so the rename itself survives a crash.
//
// Any failure before the rename returns an error and removes the temp file;
// the previous file at path is never touched before the rename, so a failed
// write leaves the old contents intact. A parent-directory fsync failure is
// returned after the rename (see fsutil.SyncDir for that documented
// asymmetry).
//
// This wrapper keeps the storage-layer contract of creating the parent
// directory (0700) before writing; fsutil.AtomicWriteFile itself requires the
// directory to exist.
//
// Fault-injection tests use fsutil.SetHooks to fail individual durability
// steps (file sync/close, rename, directory sync).
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(path, data, perm)
}

// SyncDir fsyncs a directory so a rename into it is durable. It is the unix
// directory-fsync step, delegated to fsutil so the storage layer and every
// other store share one implementation. Windows has no directory-fsync
// equivalent, so there it is a documented no-op: the rename itself is still
// atomic and NTFS journals metadata, but a power loss may lose the rename
// sooner than on unix. Callers that stream bytes into a temp file and rename
// (the snapshot archive upload) use this directly because AtomicWriteFile
// only accepts an in-memory buffer.
func SyncDir(dir string) error { return fsutil.SyncDir(dir) }

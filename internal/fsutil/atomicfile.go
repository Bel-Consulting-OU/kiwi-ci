// Package fsutil provides the shared durable-filesystem primitives used by
// the control plane's credential and security-state stores: an atomic,
// crash-durable file replacement built from a unique temp file in the target
// directory, checked write/chmod/fsync/close, a rename over the target, and a
// parent-directory fsync.
//
// The package depends only on the standard library so every store (the
// server's JSON state writers, the storage layer's snapshots and journals,
// and the auth token store) can share one implementation of the durability
// sequence instead of re-deriving it.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// AtomicWriteFile durably replaces path with data:
//
//  1. create a UNIQUE temp file in the target directory (os.CreateTemp with a
//     "."+base+".tmp-*" pattern), so two concurrent writers can never clobber
//     each other's scratch file,
//  2. write the bytes,
//  3. chmod the temp file to the caller-supplied perm,
//  4. fsync the file (checked),
//  5. close the file (checked),
//  6. rename the temp file over path,
//  7. fsync the parent directory so the rename itself survives a crash.
//
// Any failure before the rename removes the temp file and returns an error;
// the previous file at path is never touched before the rename, so a failed
// write leaves the old contents intact. A parent-directory fsync failure is
// returned AFTER the rename: the new bytes are visible but their durability
// is not certified, which is why every caller must treat the error as "not
// acknowledged" (see SyncDir).
//
// The destination directory must already exist. This primitive deliberately
// does not create it: callers that own a data directory create it once at
// startup (or explicitly, like storage.AtomicWriteFile and auth's Save), so a
// write into a missing directory is an error rather than an implicit mkdir.
func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("fsutil: create temp file for %s: %w", path, err)
	}
	tmp := f.Name()
	h := currentHooks()

	if _, err := f.Write(data); err != nil {
		_ = RealFileClose(f)
		_ = os.Remove(tmp)
		return fmt.Errorf("fsutil: write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = RealFileClose(f)
		_ = os.Remove(tmp)
		return fmt.Errorf("fsutil: chmod %s: %w", tmp, err)
	}
	syncFile := RealFileSync
	if h.FileSync != nil {
		syncFile = h.FileSync
	}
	if err := syncFile(f); err != nil {
		_ = RealFileClose(f)
		_ = os.Remove(tmp)
		return fmt.Errorf("fsutil: sync %s: %w", tmp, err)
	}
	closeFile := RealFileClose
	if h.FileClose != nil {
		closeFile = h.FileClose
	}
	if err := closeFile(f); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("fsutil: close %s: %w", tmp, err)
	}
	rename := RealRename
	if h.Rename != nil {
		rename = h.Rename
	}
	if err := rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("fsutil: rename %s to %s: %w", tmp, path, err)
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so a rename into it is durable. It is the unix
// directory-fsync step the durability contract is built on: returning an
// error means the rename may not survive a crash and the write must not be
// acknowledged.
//
// Windows has no directory-fsync equivalent, so there it is a documented
// no-op: the rename itself is still atomic and NTFS journals metadata, but a
// power loss may lose the rename sooner than on unix.
func SyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	syncDir := RealSyncDir
	if h := currentHooks(); h.DirSync != nil {
		syncDir = h.DirSync
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("fsutil: fsync directory %s: %w", dir, err)
	}
	return nil
}

// RealFileSync, RealFileClose, RealRename and RealSyncDir are the production
// durability steps. A test Hook may delegate to them to keep the real
// behavior while wrapping or counting it (calling the hooked entry point from
// inside a hook would recurse).
func RealFileSync(f *os.File) error { return f.Sync() }

func RealFileClose(f *os.File) error { return f.Close() }

func RealRename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func RealSyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

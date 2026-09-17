package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Durable-write seams. atomicFileSync and atomicFileClose are the checked
// file Sync/Close steps of AtomicWriteFile, and atomicDirSync is the parent
// directory fsync after the rename. Tests override them to inject Sync/Close
// failures and to observe that the directory fsync ran; production points
// them at the real os.File methods.
var (
	atomicFileSync  = func(f *os.File) error { return f.Sync() }
	atomicFileClose = func(f *os.File) error { return f.Close() }
	atomicDirSync   = syncDir
)

// AtomicWriteFile durably replaces path with data:
//
//  1. write the bytes to a temp file in the target directory,
//  2. Sync the file (checked),
//  3. Close the file (checked),
//  4. rename the temp file over path,
//  5. fsync the parent directory so the rename itself survives a crash.
//
// Any failure returns an error and removes the temp file; the previous file
// at path is never touched before the rename, so a failed write leaves the
// old contents intact. The caller-supplied perm is applied to the temp file
// before the rename.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = atomicFileClose(f)
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = atomicFileClose(f)
		_ = os.Remove(tmp)
		return err
	}
	if err := atomicFileSync(f); err != nil {
		_ = atomicFileClose(f)
		_ = os.Remove(tmp)
		return fmt.Errorf("storage: sync %s: %w", tmp, err)
	}
	if err := atomicFileClose(f); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("storage: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so a rename into it is durable. It is the
// unix directory-fsync step. Windows has no directory-fsync equivalent, so
// there it is a documented no-op: the rename itself is still atomic and NTFS
// journals metadata, but a power loss may lose the rename sooner than on
// unix. Callers that stream bytes into a temp file and rename (the snapshot
// archive upload) use this directly because AtomicWriteFile only accepts an
// in-memory buffer.
func SyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := atomicDirSync(dir); err != nil {
		return fmt.Errorf("storage: fsync directory %s: %w", dir, err)
	}
	return nil
}

// syncDir is the real directory fsync: open the directory and Sync it.
func syncDir(dir string) error {
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

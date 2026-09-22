package fsutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// CreateFileCAS durably publishes data at path with create-if-absent
// semantics. It is the create-only sibling of AtomicWriteFile and shares its
// crash-durability sequence and typed-error contract:
//
//  1. create a UNIQUE temp file in the target directory (os.CreateTemp with a
//     "<base>.cas-*" pattern), so concurrent creators never clobber each
//     other's scratch file,
//  2. write the bytes (hook-aware),
//  3. chmod the temp file to the caller-supplied perm (hook-aware),
//  4. fsync the temp file (checked, hook-aware),
//  5. close the temp file (checked, hook-aware),
//  6. PUBLISH create-if-absent: a hard link on unix (a link racing an existing
//     file fails with os.ErrExist), or an O_CREATE|O_EXCL open on Windows
//     (where hard links can be unsupported) that is written, explicitly
//     fsynced, and closed,
//  7. fsync the parent directory so the published directory entry survives a
//     crash.
//
// The publish boundary is step 6: a failure before it is definitely not
// published (the temp file is removed and path is untouched, ErrNotPublished),
// while a failure in step 7 is published-but-uncertain
// (ErrPublishedUncertain, Renamed true). A post-publish failure on the Windows
// O_EXCL write/sync/close is likewise reported as Renamed: the directory entry
// is already visible, so the caller must keep it and fail closed rather than
// delete or regenerate it.
//
// A lost create race returns os.ErrExist unwrapped, so callers can keep using
// errors.Is(err, os.ErrExist). The destination directory must already exist.
func CreateFileCAS(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	prePublish := func(phase Phase, err error) error {
		return &AtomicWriteError{Path: path, Phase: phase, Err: err}
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".cas-*")
	if err != nil {
		return prePublish(PhaseCreate, fmt.Errorf("create temp file in %s: %w", dir, err))
	}
	tmp := f.Name()

	h := currentHooks()
	write := h.Write
	if write == nil {
		write = func(f *os.File, b []byte) (int, error) { return f.Write(b) }
	}
	n, werr := write(f, data)
	if werr == nil && n != len(data) {
		werr = io.ErrShortWrite
	}
	if werr != nil {
		_ = RealFileClose(f)
		_ = os.Remove(tmp)
		return prePublish(PhaseWrite, fmt.Errorf("write %s: %w", tmp, werr))
	}
	chmod := h.Chmod
	if chmod == nil {
		chmod = os.Chmod
	}
	if err := chmod(tmp, mode); err != nil {
		_ = RealFileClose(f)
		_ = os.Remove(tmp)
		return prePublish(PhaseChmod, fmt.Errorf("chmod %s: %w", tmp, err))
	}
	syncFile := RealFileSync
	if h.FileSync != nil {
		syncFile = h.FileSync
	}
	if err := syncFile(f); err != nil {
		_ = RealFileClose(f)
		_ = os.Remove(tmp)
		return prePublish(PhaseFileSync, fmt.Errorf("sync %s: %w", tmp, err))
	}
	closeFile := RealFileClose
	if h.FileClose != nil {
		closeFile = h.FileClose
	}
	if err := closeFile(f); err != nil {
		_ = os.Remove(tmp)
		return prePublish(PhaseClose, fmt.Errorf("close %s: %w", tmp, err))
	}

	if runtime.GOOS == "windows" {
		pf, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			if os.IsExist(err) {
				return os.ErrExist
			}
			_ = os.Remove(tmp)
			return prePublish(PhaseRename, fmt.Errorf("create %s: %w", path, err))
		}
		// The publish already happened (the entry is visible); the staging
		// temp file is no longer needed regardless of the outcome below.
		_ = os.Remove(tmp)
		// Every failure from here on is published-but-uncertain
		// (Renamed=true).
		published := func(phase Phase, err error) error {
			return &AtomicWriteError{Path: path, Phase: phase, Renamed: true, Err: err}
		}
		if _, err := pf.Write(data); err != nil {
			_ = RealFileClose(pf)
			return published(PhaseWrite, fmt.Errorf("write %s: %w", path, err))
		}
		// Explicit fsync before the publication is acknowledged: without it a
		// crash could keep the directory entry while losing the bytes.
		if err := pf.Sync(); err != nil {
			_ = RealFileClose(pf)
			return published(PhaseFileSync, fmt.Errorf("sync %s: %w", path, err))
		}
		if err := pf.Close(); err != nil {
			return published(PhaseClose, fmt.Errorf("close %s: %w", path, err))
		}
	} else if err := os.Link(tmp, path); err != nil {
		if os.IsExist(err) {
			return os.ErrExist
		}
		_ = os.Remove(tmp)
		return prePublish(PhaseRename, fmt.Errorf("link %s to %s: %w", tmp, path, err))
	}
	// The temp file is no longer needed (unix: the link made a second name;
	// windows: it was only the durable staging copy).
	_ = os.Remove(tmp)
	if err := SyncDir(dir); err != nil {
		return &AtomicWriteError{Path: path, Phase: PhaseDirSync, Renamed: true, Err: err}
	}
	return nil
}

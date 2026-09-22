package fsutil

import (
	"errors"
	"fmt"
)

// Phase identifies the durability step at which AtomicWriteFile failed. The
// phases are ordered exactly as the write sequence runs, and the rename is
// the publish boundary: a failure in a phase BEFORE PhaseRename means the
// new state was definitely never published (the previous file at Path is
// intact and the unique temp file was removed), while a failure in
// PhaseDirSync means the rename already happened and the new bytes are
// visible at Path even though their crash durability is not certified.
type Phase string

const (
	// PhaseCreate creates the unique temp file in the destination directory.
	PhaseCreate Phase = "create"
	// PhaseWrite writes the payload into the temp file.
	PhaseWrite Phase = "write"
	// PhaseChmod applies the caller's perm to the temp file.
	PhaseChmod Phase = "chmod"
	// PhaseFileSync fsyncs the temp file's contents (checked).
	PhaseFileSync Phase = "file-sync"
	// PhaseClose closes the temp file (checked).
	PhaseClose Phase = "close"
	// PhaseRename renames the temp file over the destination: the publish
	// step. A failure here means the rename did NOT happen.
	PhaseRename Phase = "rename"
	// PhaseDirSync fsyncs the destination directory so a successful rename
	// survives a crash. This is the only phase that runs after publication.
	PhaseDirSync Phase = "dir-sync"
)

// ErrNotPublished marks an AtomicWriteFile failure raised BEFORE the rename:
// the new bytes were never published, the previous durable state at Path is
// intact (or Path did not exist) and the temp file was removed. Callers may
// keep rolling a mutation back on this class: nothing observable changed.
var ErrNotPublished = errors.New("fsutil: new state not published, previous state intact")

// ErrPublishedUncertain marks an AtomicWriteFile failure raised AFTER the
// rename (a failed parent-directory fsync): the new bytes are visible at
// Path, but their crash durability is not certified. A caller MUST NOT read
// this as "the previous state is intact" and MUST NOT roll a security-
// monotonic mutation back to its permissive pre-mutation value: memory would
// then be more permissive than the visible file. The correct handling is to
// retain the published (more restrictive) state and keep readiness degraded
// until a later successful persist reconciles it.
var ErrPublishedUncertain = errors.New("fsutil: new state published but its crash durability is not certified")

// AtomicWriteError is the typed failure of AtomicWriteFile. Phase names the
// durability step that failed; Renamed reports whether the rename had
// already succeeded when the failure was detected (true only for
// PhaseDirSync); Err is the underlying cause, also returned by Unwrap so
// errors.As/Is reach the wrapped error and Path is the destination path (the
// path whose meaning changed on a Renamed failure).
type AtomicWriteError struct {
	Path    string
	Phase   Phase
	Renamed bool
	Err     error
}

func (e *AtomicWriteError) Error() string {
	state := "not published, previous state intact"
	if e.Renamed {
		state = "published, crash durability uncertain"
	}
	return fmt.Sprintf("fsutil: atomic write %s failed in phase %s (%s): %v", e.Path, e.Phase, state, e.Err)
}

// Unwrap returns the underlying durability-step error.
func (e *AtomicWriteError) Unwrap() error { return e.Err }

// Is makes the phase sentinels usable with errors.Is: every pre-rename
// failure matches ErrNotPublished, every post-rename failure matches
// ErrPublishedUncertain. Any other target falls through to the ordinary
// unwrap chain, so errors.Is(err, os.ErrPermission) and friends keep working.
func (e *AtomicWriteError) Is(target error) bool {
	switch target {
	case ErrNotPublished:
		return !e.Renamed
	case ErrPublishedUncertain:
		return e.Renamed
	}
	return false
}

// Renamed reports whether err is an AtomicWriteError raised after the rename
// succeeded: the new bytes are visible at the destination path but the write
// is not certified crash-durable. Security-state callers use it to choose
// between rolling a mutation back (definitely not published) and retaining
// the published, more restrictive state while readiness stays degraded.
func Renamed(err error) bool {
	var awe *AtomicWriteError
	return errors.As(err, &awe) && awe.Renamed
}

// NotPublished reports whether err is an AtomicWriteError raised before the
// rename, i.e. the write is definitely not visible.
func NotPublished(err error) bool {
	var awe *AtomicWriteError
	return errors.As(err, &awe) && !awe.Renamed
}

// PhaseOf returns the failed durability phase of err.
func PhaseOf(err error) (Phase, bool) {
	var awe *AtomicWriteError
	if errors.As(err, &awe) {
		return awe.Phase, true
	}
	return "", false
}

// newAtomicWriteError builds the typed failure for one durability step. The
// rename itself is a pre-publication step: only the directory fsync after it
// reports Renamed=true.
func newAtomicWriteError(path string, phase Phase, err error) *AtomicWriteError {
	return &AtomicWriteError{
		Path:    path,
		Phase:   phase,
		Renamed: phase == PhaseDirSync,
		Err:     err,
	}
}

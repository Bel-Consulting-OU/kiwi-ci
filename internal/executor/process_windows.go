//go:build windows

package executor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	modkernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = modkernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = modkernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = modkernel32.NewProc("AssignProcessToJobObject")
)

// jobObjectExtendedLimitInformationClass is the JobObjectInformationClass
// value for JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
const jobObjectExtendedLimitInformationClass = 9

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// superviseChild creates a dedicated Windows Job Object for the command's
// process tree, configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, and
// synchronously assigns the child to it before returning.
//
// Ordering guarantee: superviseChild must be called in the caller goroutine
// immediately after cmd.Start() has materialized cmd.Process and before any
// supervision goroutine is spawned. It performs the whole sequence — create
// job, configure job, OpenProcess(cmd.Process.Pid), AssignProcessToJobObject —
// synchronously in that caller goroutine and returns only once the child is
// inside the job. No goroutine can therefore ever observe an unassigned child
// process; the previous implementation polled cmd.Process from a watcher
// goroutine and raced cmd.Start's assignment of it.
//
// The returned cleanup closes the job handle; with kill-on-close set, that
// terminates every process still assigned to the job, which is what makes
// cancellation kill the whole tree (the direct child kill alone would leave
// grandchildren running). It must be invoked after cmd.Wait(). A non-nil
// error means the child could not be placed under the Job Object; the caller
// must terminate the child rather than run it unsupervised.
func superviseChild(cmd *exec.Cmd) (func(), error) {
	job, _, err := procCreateJobObjectW.Call(0, 0)
	if job == 0 {
		if err == nil || err == syscall.Errno(0) {
			err = errors.New("CreateJobObjectW failed")
		}
		return nil, err
	}
	info := jobObjectExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if r, _, serr := procSetInformationJobObject.Call(job, jobObjectExtendedLimitInformationClass, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		_ = syscall.CloseHandle(syscall.Handle(job))
		if serr == nil || serr == syscall.Errno(0) {
			serr = errors.New("SetInformationJobObject failed")
		}
		return nil, serr
	}
	if cmd.Process == nil {
		_ = syscall.CloseHandle(syscall.Handle(job))
		return nil, errors.New("child process is nil after cmd.Start")
	}
	if err := assignToJobObjectNow(cmd.Process, syscall.Handle(job)); err != nil {
		_ = syscall.CloseHandle(syscall.Handle(job))
		return nil, err
	}
	return func() {
		_ = syscall.CloseHandle(syscall.Handle(job))
	}, nil
}

// assignToJobObjectNow synchronously opens the child process with the
// PROCESS_SET_QUOTA|PROCESS_TERMINATE rights AssignProcessToJobObject
// requires and assigns it to job, all in the caller goroutine. OpenProcess
// necessarily precedes AssignProcessToJobObject here (the returned handle is
// the argument to the assign call), which pins the open-then-assign ordering
// by construction.
func assignToJobObjectNow(proc *os.Process, job syscall.Handle) error {
	h, err := syscall.OpenProcess(processSetQuotaOrTerminate, false, uint32(proc.Pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	if r, _, err := procAssignProcessToJobObject.Call(uintptr(job), uintptr(h)); r == 0 {
		if err == nil || err == syscall.Errno(0) {
			return errors.New("AssignProcessToJobObject failed")
		}
		return err
	}
	return nil
}

func configureProcess(cmd *exec.Cmd) {}
func terminateProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
func killProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

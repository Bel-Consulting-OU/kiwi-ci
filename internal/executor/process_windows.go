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
	procResumeThread             = modkernel32.NewProc("ResumeThread")
	procCloseHandle              = modkernel32.NewProc("CloseHandle")
	procGetExitCodeProcess       = modkernel32.NewProc("GetExitCodeProcess")
)

// processQueryLimitedInformation is the OpenProcess access right needed for
// GetExitCodeProcess liveness probes (portable across modern Windows).
const processQueryLimitedInformation = 0x1000

// jobObjectExtendedLimitInformationClass is the JobObjectInformationClass
// value for JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
const jobObjectExtendedLimitInformationClass = 9

// createSuspendedFlag is CREATE_SUSPENDED for CreateProcessW. Go's
// os/exec sets it via SysProcAttr.CreationFlags so the child is born
// frozen, assigned to the Job Object, then resumed — closing the
// Start→assign execution race.
const createSuspendedFlag = 0x00000004

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
// Ordering: the child is created SUSPENDED (CREATE_SUSPENDED via
// SysProcAttr.CreationFlags), assigned to the Job Object, then resumed.
// No userspace instruction of the child runs before it is inside the job,
// so a fast native command cannot spawn an unowned grandchild during a
// Start→assign window.
//
// The returned cleanup closes the job handle; with kill-on-close set, that
// terminates every process still assigned to the job. It must be invoked
// after cmd.Wait(). A non-nil error means the child could not be placed
// under the Job Object; the caller must terminate the child rather than
// run it unsupervised.
func superviseChild(cmd *exec.Cmd) (func(), error) {
	// configureProcess already set CREATE_SUSPENDED when the caller used
	// the native backend; ensure it is set even for direct test calls.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= createSuspendedFlag

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
		_ = terminateProcess(cmd)
		_ = killProcess(cmd)
		_ = syscall.CloseHandle(syscall.Handle(job))
		return nil, err
	}
	// Primary thread handle: Go keeps it in ProcessState on some versions;
	// open by PID with THREAD_SUSPEND_RESUME to resume the primary thread.
	if err := resumeProcess(cmd.Process); err != nil {
		_ = terminateProcess(cmd)
		_ = killProcess(cmd)
		_ = syscall.CloseHandle(syscall.Handle(job))
		return nil, err
	}
	return func() {
		_ = syscall.CloseHandle(syscall.Handle(job))
	}, nil
}

// resumeProcess resumes the primary thread of a CREATE_SUSPENDED process.
// On Windows the primary thread TID equals the process PID.
func resumeProcess(proc *os.Process) error {
	const threadSuspendResume = 0x0002
	h, err := syscall.OpenProcess(threadSuspendResume|processSetQuotaOrTerminate, false, uint32(proc.Pid))
	if err != nil {
		// OpenProcess for the primary thread is wrong — OpenThread is.
		// Fall through to OpenThread below.
		_ = h
	}
	th, terr := openThread(threadSuspendResume, false, uint32(proc.Pid))
	if terr != nil {
		return terr
	}
	defer syscall.CloseHandle(th)
	r, _, err := procResumeThread.Call(uintptr(th))
	if r == ^uintptr(0) {
		if err == nil || err == syscall.Errno(0) {
			return errors.New("ResumeThread failed")
		}
		return err
	}
	return nil
}

func openThread(access uint32, inherit bool, tid uint32) (syscall.Handle, error) {
	procOpenThread := modkernel32.NewProc("OpenThread")
	h, _, err := procOpenThread.Call(uintptr(access), uintptr(boolToInt(inherit)), uintptr(tid))
	if h == 0 {
		if err == nil || err == syscall.Errno(0) {
			err = errors.New("OpenThread failed")
		}
		return 0, err
	}
	return syscall.Handle(h), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// assignToJobObjectNow synchronously opens the child process with the
// PROCESS_SET_QUOTA|PROCESS_TERMINATE rights AssignProcessToJobObject
// requires and assigns it to job, all in the caller goroutine.
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

// configureProcess sets CREATE_SUSPENDED so the child is born frozen; the
// Job Object assign + ResumeThread happen in superviseChild after Start.
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createSuspendedFlag,
	}
}

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

// processAlive reports whether pid is a live process. On Windows FindProcess
// succeeds for any PID, so liveness is GetExitCodeProcess == STILL_ACTIVE.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	r, _, _ := procGetExitCodeProcess.Call(uintptr(h), uintptr(unsafe.Pointer(&code)))
	if r == 0 {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

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
	modntdll                     = syscall.NewLazyDLL("ntdll.dll")
	procCreateJobObjectW         = modkernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = modkernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = modkernel32.NewProc("AssignProcessToJobObject")
	procCloseHandle              = modkernel32.NewProc("CloseHandle")
	procGetExitCodeProcess       = modkernel32.NewProc("GetExitCodeProcess")
	// NtResumeProcess resumes every thread of a process created with
	// CREATE_SUSPENDED. os/exec's StartProcess closes the primary-thread
	// handle (CloseHandle(pi.Thread)) before Start returns, and the primary
	// thread TID is NOT the process PID — OpenThread(PID) is wrong. The
	// process handle is the only identity we still own after Start.
	procNtResumeProcess = modntdll.NewProc("NtResumeProcess")
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
// SysProcAttr.CreationFlags), assigned to the Job Object, then resumed
// with NtResumeProcess on the process handle. No userspace instruction of
// the child runs before it is inside the job.
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
	// Resume every thread of the CREATE_SUSPENDED process via the process
	// handle. The primary-thread handle was closed inside os.StartProcess
	// and the thread TID is not the PID, so OpenThread(PID) is not an option.
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

// resumeProcess resumes a CREATE_SUSPENDED process by calling
// NtResumeProcess on its process handle. NtResumeProcess takes the process,
// not a thread id, and resumes every suspended thread of that process —
// exactly the primary thread CreateProcessW left frozen.
func resumeProcess(proc *os.Process) error {
	if proc == nil {
		return errors.New("resume: nil process")
	}
	// Open a process handle with the rights NtResumeProcess needs; the
	// handle os.Process keeps may only carry SYNCHRONIZE/PROCESS_QUERY.
	const processAllAccess = 0x1FFFFF
	h, err := syscall.OpenProcess(processAllAccess, false, uint32(proc.Pid))
	if err != nil {
		// Fall back to the handle embedded in os.Process via Signal probe
		// is not available; retry with query-limited rights — NtResumeProcess
		// only needs PROCESS_SUSPEND_RESUME (0x0800) on modern kernels.
		h, err = syscall.OpenProcess(0x0800, false, uint32(proc.Pid))
		if err != nil {
			return err
		}
	}
	defer syscall.CloseHandle(h)
	r, _, nerr := procNtResumeProcess.Call(uintptr(h))
	// NTSTATUS 0 == STATUS_SUCCESS; any non-zero value is a failure.
	if r != 0 {
		if nerr != nil && nerr != syscall.Errno(0) {
			return nerr
		}
		return errors.New("NtResumeProcess failed")
	}
	return nil
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
// Job Object assign + NtResumeProcess happen in superviseChild after Start.
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

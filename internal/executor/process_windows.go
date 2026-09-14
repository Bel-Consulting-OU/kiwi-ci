//go:build windows

package executor

import (
	"os/exec"
	"runtime"
	"sync"
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

// AssignProcessToJobObject needs PROCESS_SET_QUOTA|PROCESS_TERMINATE rights
// on the child process handle.
const processSetQuotaOrTerminate = 0x0100 | 0x0001

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

// setupChildJob creates a dedicated Windows Job Object for the command's
// process tree, configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, and
// assigns the child to it as soon as cmd.Start has materialized the process.
// The returned cleanup closes the job handle; with kill-on-close set, that
// terminates every process still assigned to the job, which is what makes
// cancellation kill the whole tree (the direct child kill alone would leave
// grandchildren running). It must be called before cmd.Start and invoked
// after cmd.Wait. The assignment goroutine is best-effort: if the job cannot
// be created or assigned, cleanup degrades to a no-op and existing
// single-process termination still applies.
func setupChildJob(cmd *exec.Cmd) func() {
	job, _, _ := procCreateJobObjectW.Call(0, 0)
	if job == 0 {
		return func() {}
	}
	info := jobObjectExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	procSetInformationJobObject.Call(job, jobObjectExtendedLimitInformationClass, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))

	stop := make(chan struct{})
	assigned := make(chan struct{})
	go func() {
		defer close(assigned)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if cmd.Process != nil {
				h, err := syscall.OpenProcess(processSetQuotaOrTerminate, false, uint32(cmd.Process.Pid))
				if err == nil {
					procAssignProcessToJobObject.Call(job, uintptr(h))
					_ = syscall.CloseHandle(h)
				}
				return
			}
			runtime.Gosched()
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			<-assigned
			_ = syscall.CloseHandle(syscall.Handle(job))
		})
	}
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

//go:build windows

package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestSuspendedLaunchLifecycleAssignResumeKill is the audit's Windows
// validation gap: actually launch a suspended child, PROVE it cannot
// execute before job assignment, resume it, observe it running (and its
// descendant spawning), then prove Job-Object teardown with
// KILL_ON_JOB_CLOSE kills the descendant too. The existing dead-PID test
// only proved resumeProcess does not panic; this exercises the real
// sequence:
//
//	CreateProcess(CREATE_SUSPENDED) → no execution
//	AssignProcessToJobObject        → ownership
//	NtResumeProcess                 → execution begins
//	close job handle                 → child AND descendant die
//
// Requires a real Windows host (this file is windows-only by build tag);
// cross-compilation from another GOOS proves it stays in the build.
func TestSuspendedLaunchLifecycleAssignResumeKill(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran.txt")
	grandPIDFile := filepath.Join(dir, "grand.pid")
	childScript := filepath.Join(dir, "child.cmd")
	grandScript := filepath.Join(dir, "grand.ps1")

	// Grandchild: publish its own PID, then linger long enough to outlive
	// any non-job kill window.
	ps1 := "Set-Content -LiteralPath '" + grandPIDFile + "' -Value $PID\nStart-Sleep -Seconds 300\n"
	if err := os.WriteFile(grandScript, []byte(ps1), 0o644); err != nil {
		t.Fatal(err)
	}
	// Child: publish the marker, spawn the grandchild, then linger.
	cmdBody := "@echo off\r\n" +
		"echo ran>\"" + marker + "\"\r\n" +
		"start /b powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"" + grandScript + "\"\r\n" +
		"ping -n 300 127.0.0.1 >nul\r\n"
	if err := os.WriteFile(childScript, []byte(cmdBody), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("cmd.exe", "/c", childScript)
	configureProcess(cmd) // CREATE_SUSPENDED: born frozen
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	childDied := false
	reapChild := func() {
		if childDied {
			return
		}
		childDied = true
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		reapChild()
	})

	// PHASE 1 — suspension: no userspace instruction may have run, so the
	// marker cannot exist yet. If CREATE_SUSPENDED were dropped anywhere,
	// cmd.exe would have written it well within this window.
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("suspended child executed BEFORE job assignment (marker exists) — CREATE_SUSPENDED window broken")
	} else if !os.IsNotExist(err) {
		t.Fatalf("marker stat: %v", err)
	}

	// PHASE 2 — assign to a kill-on-close Job Object, then resume.
	jobCleanup, err := superviseChild(cmd)
	if err != nil {
		t.Fatalf("superviseChild: %v", err)
	}
	// Closing the job handle must happen EXACTLY ONCE (phase 5 closes it;
	// an early failure must also close it without double-closing a recycled
	// handle value).
	var jobOnce sync.Once
	jobClose := func() { jobOnce.Do(jobCleanup) }
	t.Cleanup(jobClose)
	// PHASE 3 — execution observed: the marker appears.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resumed child never executed (marker missing)")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// PHASE 4 — the grandchild appeared INSIDE the job (spawned post-
	// resume) and reports a live PID.
	deadline = time.Now().Add(15 * time.Second)
	var grandPID int
	for {
		if b, err := os.ReadFile(grandPIDFile); err == nil {
			if p, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && p > 0 {
				grandPID = p
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("grandchild never published its PID")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !processHandleOpen(grandPID) {
		t.Fatal("grandchild PID is not a live process before teardown")
	}

	// PHASE 5 — job teardown: closing the job handle must kill the child
	// (KILL_ON_JOB_CLOSE) AND the descendant that inherited membership.
	jobClose()
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	select {
	case <-waitDone:
		childDied = true
	case <-time.After(15 * time.Second):
		t.Fatal("primary child survived job-handle close")
	}
	deadline = time.Now().Add(15 * time.Second)
	for processHandleOpen(grandPID) {
		if time.Now().After(deadline) {
			t.Fatalf("descendant pid %d survived Job Object teardown — grandchild escaped the job", grandPID)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// processHandleOpen reports whether pid still names a RUNNING process.
// Windows sets the process object's signal the moment termination begins,
// so: open failure → gone; open + signal already raised → exiting (treated
// as gone); open + no signal → alive. No goroutine or last-exit probe
// needed — the object signal IS the liveness edge the job kill flips.
func processHandleOpen(pid int) bool {
	const processQueryLimitedInformation = 0x1000
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	waitZero, err := windows.WaitForSingleObject(windows.Handle(h), 0)
	if err != nil {
		return false
	}
	const waitObject0 = 0x00000000
	return waitZero != waitObject0 // WAIT_TIMEOUT → still running
}

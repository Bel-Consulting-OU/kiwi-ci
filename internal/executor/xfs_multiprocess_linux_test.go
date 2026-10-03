//go:build linux

package executor

// True two-PROCESS regression for XFS project-ID allocation: two independent
// Kiwi processes sharing one filesystem must never publish the same project
// ID. The test re-executes the test binary as a helper process so the
// allocation locks, pools and Go memory are genuinely separate.

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("KIWI_XFS_ALLOC_HELPER") == "1" {
		os.Exit(runXFSAllocHelper())
	}
	os.Exit(m.Run())
}

// runXFSAllocHelper performs one real quota acquisition with the fake
// xfs_quota whose report is derived from a SHARED assignment log, then prints
// the assigned project ID. It runs in a separate process from the test.
func runXFSAllocHelper() int {
	ws, err := os.MkdirTemp("", "kiwi-run-helper-*")
	if err != nil {
		return 2
	}
	script := os.Getenv("KIWI_XFS_ALLOC_SCRIPT")
	status, _ := setupXFSProjectQuotaOnMount(ws, mountInfoEntry{mountPoint: "/mnt/xfs", device: "8:99", fsType: "xfs"}, 1<<20, script)
	if !status.Hard || status.Assignment == nil {
		return 3
	}
	os.Stdout.WriteString(strconv.FormatUint(uint64(status.Assignment.ProjectID), 10))
	return 0
}

func TestXFSConcurrentProcessesNeverAllocateSameProjectID(t *testing.T) {
	dir := t.TempDir()
	lockDir := filepath.Join(dir, "lock")
	if err := os.MkdirAll(lockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "assignments.log")
	script := filepath.Join(dir, "xfs_quota")
	body := `#!/bin/sh
echo "$@" >> "$KIWI_XFS_ALLOC_LOG"
case "$*" in
  *"report -p -n"*) awk '/project -s/ {for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) print "#" $i}' "$KIWI_XFS_ALLOC_LOG" 2>/dev/null;;
esac
exit 0
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	runHelper := func() (string, error) {
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(),
			"KIWI_XFS_ALLOC_HELPER=1",
			"KIWI_XFS_ALLOC_SCRIPT="+script,
			"KIWI_XFS_ALLOC_LOG="+logPath,
			"KIWI_XFS_LOCK_DIR="+lockDir,
			"KIWI_XFS_PROJECT_ID_BASE=100000",
			"KIWI_XFS_PROJECT_ID_COUNT=4",
		)
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	var wg sync.WaitGroup
	results := make([]string, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = runHelper()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("helper %d: %v (output %q)", i, err, results[i])
		}
		if results[i] == "" {
			t.Fatalf("helper %d produced no project ID", i)
		}
	}
	if results[0] == results[1] {
		t.Fatalf("two processes allocated the SAME project ID %s (log:\n%s)", results[0], readFileOrEmpty(logPath))
	}
	// The shared log must show two distinct published assignments.
	logged := readFileOrEmpty(logPath)
	var published []string
	for _, line := range strings.Split(logged, "\n") {
		if !strings.Contains(line, "project -s") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if _, err := strconv.Atoi(field); err == nil {
				published = append(published, field)
			}
		}
	}
	sort.Strings(published)
	if len(published) != 2 || published[0] == published[1] {
		t.Fatalf("published assignments = %v, want two distinct IDs (log:\n%s)", published, logged)
	}
}

func readFileOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

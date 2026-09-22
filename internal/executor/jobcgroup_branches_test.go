package executor

// Branch coverage for the portable job-cgroup core: the declared-envelope
// helpers, the failure paths of directory creation, controller/limit
// materialization and removal, and the name derivation. These are the
// operations a real cgroupfs and a plain test directory share, so every
// branch is asserted through observable filesystem state.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestJobCgroupDeclaredEnvelope pins "declared": a request with at least one
// enforceable axis is declared, an all-zero request is not (no limit file is
// ever written for it).
func TestJobCgroupDeclaredEnvelope(t *testing.T) {
	cases := []struct {
		name string
		req  jobCgroupRequest
		want bool
	}{
		{"nothing declared", jobCgroupRequest{}, false},
		{"cpu only", jobCgroupRequest{CPU: 0.5}, true},
		{"memory only", jobCgroupRequest{Memory: 1}, true},
		{"pids only", jobCgroupRequest{PIDs: 1}, true},
	}
	for _, tc := range cases {
		if got := tc.req.declared(); got != tc.want {
			t.Errorf("%s: declared() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestJobCgroupEnvelopeSummaryRendersDeclaredAxes pins the operator-visible
// summary line: only declared axes appear, in a stable order, with a
// fractional CPU rendered unchanged.
func TestJobCgroupEnvelopeSummaryRendersDeclaredAxes(t *testing.T) {
	cases := []struct {
		req  jobCgroupRequest
		want string
	}{
		{jobCgroupRequest{}, ""},
		{jobCgroupRequest{CPU: 2}, "cpu=2"},
		{jobCgroupRequest{Memory: 1 << 30}, "memory=1073741824"},
		{jobCgroupRequest{PIDs: 256}, "pids=256"},
		{jobCgroupRequest{CPU: 1.5, Memory: 256 << 20, PIDs: 64}, "cpu=1.5 memory=268435456 pids=64"},
		{jobCgroupRequest{Memory: 8, PIDs: 2}, "memory=8 pids=2"},
	}
	for _, tc := range cases {
		if got := jobCgroupEnvelopeSummary(tc.req); got != tc.want {
			t.Errorf("jobCgroupEnvelopeSummary(%+v) = %q, want %q", tc.req, got, tc.want)
		}
	}
}

// TestCreateJobCgroupUnderMkdirFailure: an occupied directory name is
// reported (and nothing is removed from the caller's tree).
func TestCreateJobCgroupUnderMkdirFailure(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "kiwi-job-busy"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir, cleanup, err := createJobCgroupUnder(base, "kiwi-job-busy", nil, nil)
	if err == nil || cleanup != nil || dir != "" {
		t.Fatalf("mkdir failure = (%q, %v, %v)", dir, cleanup != nil, err)
	}
	if !strings.Contains(err.Error(), "create job cgroup") {
		t.Fatalf("error %q does not name the creation step", err)
	}
	// The pre-existing directory is untouched.
	if _, statErr := os.Stat(filepath.Join(base, "kiwi-job-busy")); statErr != nil {
		t.Fatalf("pre-existing directory changed: %v", statErr)
	}
}

// TestCreateJobCgroupUnderMaterializeFailure: a platform that cannot
// materialize the controller files must not leave the just-created directory
// behind.
func TestCreateJobCgroupUnderMaterializeFailure(t *testing.T) {
	orig := materializeCgroupControls
	materializeCgroupControls = func(dir string) error {
		return os.ErrPermission
	}
	t.Cleanup(func() { materializeCgroupControls = orig })

	base := t.TempDir()
	dir, cleanup, err := createJobCgroupUnder(base, "kiwi-job-mat", []string{"cpu"}, jobCgroupLimits(jobCgroupRequest{CPU: 1}))
	if err == nil || cleanup != nil || dir != "" {
		t.Fatalf("materialize failure = (%q, %v, %v)", dir, cleanup != nil, err)
	}
	if !strings.Contains(err.Error(), "materialize job cgroup") {
		t.Fatalf("error %q does not name the materialize step", err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("half-created job cgroup left behind: %v", entries)
	}
}

// TestCreateJobCgroupUnderRequiredLimitFailureRemovesDir: an unwritable
// REQUIRED limit aborts the whole cgroup (the advertised bound would be a
// lie) and removes the directory.
func TestCreateJobCgroupUnderRequiredLimitFailureRemovesDir(t *testing.T) {
	orig := materializeCgroupControls
	// Materialize cpu.max as a DIRECTORY: opening it for writing fails on
	// every supported platform, which is exactly the "kernel refused the
	// control file" failure mode this branch handles.
	materializeCgroupControls = func(dir string) error {
		return os.Mkdir(filepath.Join(dir, "cpu.max"), 0o755)
	}
	t.Cleanup(func() { materializeCgroupControls = orig })

	base := t.TempDir()
	dir, cleanup, err := createJobCgroupUnder(base, "kiwi-job-lim", nil, []cgroupLimit{{File: "cpu.max", Value: "100000 100000"}})
	if err == nil || cleanup != nil || dir != "" {
		t.Fatalf("required limit failure = (%q, %v, %v)", dir, cleanup != nil, err)
	}
	if !strings.Contains(err.Error(), "write cpu.max=100000 100000") {
		t.Fatalf("error %q does not name the failing limit", err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("failed job cgroup left behind: %v", entries)
	}
}

// TestCreateJobCgroupUnderOptionalLimitFailureIsTolerated: an unsupported
// OPTIONAL control file (memory.swap.max on a kernel without swap accounting)
// must not fail the job cgroup; the required limits are still written.
func TestCreateJobCgroupUnderOptionalLimitFailureIsTolerated(t *testing.T) {
	orig := materializeCgroupControls
	materializeCgroupControls = func(dir string) error {
		if err := os.WriteFile(filepath.Join(dir, "memory.max"), nil, 0o644); err != nil {
			return err
		}
		return os.Mkdir(filepath.Join(dir, "memory.swap.max"), 0o755)
	}
	t.Cleanup(func() { materializeCgroupControls = orig })

	base := t.TempDir()
	dir, cleanup, err := createJobCgroupUnder(base, "kiwi-job-opt", nil, []cgroupLimit{
		{File: "memory.max", Value: "1024"},
		{File: "memory.swap.max", Value: "0", Optional: true},
	})
	if err != nil {
		t.Fatalf("optional limit failure aborted the job cgroup: %v", err)
	}
	if cleanup == nil {
		t.Fatal("successful job cgroup without cleanup")
	}
	if b, rerr := os.ReadFile(filepath.Join(dir, "memory.max")); rerr != nil || string(b) != "1024" {
		t.Fatalf("required memory.max = %q err=%v", b, rerr)
	}
	// The optional file was left as-is (the kernel's business, not ours).
	info, serr := os.Stat(filepath.Join(dir, "memory.swap.max"))
	if serr != nil || !info.IsDir() {
		t.Fatalf("optional control file was modified: %v", serr)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestRemoveJobCgroupDirReportsChildFailures: a child cgroup that still holds
// containers cannot be removed; the failure names the child and the parent
// directory survives so the caller retries instead of silently leaking.
func TestRemoveJobCgroupDirReportsChildFailures(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "kiwi-job-child")
	if err := os.MkdirAll(filepath.Join(dir, "docker-scope", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := removeJobCgroupDir(dir)
	if err == nil {
		t.Fatal("non-empty child cgroup removal reported success")
	}
	msg := err.Error()
	if !strings.Contains(msg, "remove child cgroup") || !strings.Contains(msg, "remove job cgroup") {
		t.Fatalf("error %q must name both the child and the parent removal failures", msg)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("directory vanished despite failures: %v", statErr)
	}
	// A missing directory is already removed: idempotent success.
	if err := removeJobCgroupDir(filepath.Join(root, "absent")); err != nil {
		t.Fatalf("missing directory = %v, want nil", err)
	}
	// A directory holding only control FILES is removed (the files are
	// unlinked first).
	flat := filepath.Join(root, "kiwi-job-flat")
	if err := os.Mkdir(flat, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(flat, "cpu.max"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeJobCgroupDir(flat); err != nil {
		t.Fatalf("flat removal = %v", err)
	}
}

// TestJobCgroupDirNameTruncatesHostileIDs: an attacker-influenced job ID is
// sanitized to a single path component and bounded in length, so it can never
// escape the delegated base directory or collide by construction with the
// suffix of another job.
func TestJobCgroupDirNameTruncatesHostileIDs(t *testing.T) {
	long := strings.Repeat("A", 200)
	name := jobCgroupDirName(long, "suffix")
	if len(name) > len(jobCgroupNamePrefix)+80+1+len("suffix") {
		t.Fatalf("name %d bytes: not truncated", len(name))
	}
	if !strings.HasPrefix(name, jobCgroupNamePrefix) || !strings.HasSuffix(name, "-suffix") {
		t.Fatalf("name = %q", name)
	}
	if strings.ContainsAny(name, "/\\\x00") {
		t.Fatalf("name %q is not a single safe component", name)
	}
	// A short ID is preserved verbatim (after sanitization).
	if got := jobCgroupDirName("job-1", "abc"); got != "kiwi-job-job-1-abc" {
		t.Fatalf("short name = %q", got)
	}
}

// TestEnsureDelegatedCgroupBaseEmptyNeedNeedsOnlyADirectory: a request with
// no declared controllers only requires an existing directory, so the
// delegation file is never read.
func TestEnsureDelegatedCgroupBaseEmptyNeedNeedsOnlyADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := ensureDelegatedCgroupBase(dir, nil); err != nil {
		t.Fatalf("plain directory with no required controllers = %v", err)
	}
}

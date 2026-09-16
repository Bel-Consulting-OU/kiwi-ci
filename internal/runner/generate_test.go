package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestExecuteUploadsGeneratedFragment runs a job whose effective compiled
// job declares generate.path. The fragment file written by the generator
// step must be POSTed to /api/v1/jobs/{id}/generated with the lease
// headers, and the job must still complete successfully.
func TestExecuteUploadsGeneratedFragment(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	frag := `{"jobs":{"child-a":{"runtime":"native","steps":[{"run":"echo child"}]},"child-b":{"runtime":"native","steps":[{"run":"echo b"}]}},"deps":{"child-b":["child-a"]}}`
	base := "version: 1\njobs:\n  build:\n    generate:\n      path: generated.json\n    steps:\n      - run: echo hi\n"
	task := basicTask(base)
	task.Job.CompiledJobPayload = buildPayload(t, base, "build")

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "generated.json"), []byte(frag), 0o644)
	}
	r.execute(context.Background(), task)

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusSuccess {
		t.Fatalf("status = %s (%s), want success", c.Status, c.Error)
	}

	h := fsrv.headerOf(http.MethodPost, "/api/v1/jobs/job-1/generated")
	if h == nil {
		t.Fatal("no /generated POST recorded")
	}
	if got := h.Get("X-Kiwi-Runner-ID"); got != "runner-1" {
		t.Fatalf("X-Kiwi-Runner-ID = %q, want runner-1", got)
	}
	if got := h.Get("X-Kiwi-Lease-Token"); got != "lease-token" {
		t.Fatalf("X-Kiwi-Lease-Token = %q, want lease-token", got)
	}
	if got := h.Get("X-Kiwi-Lease-Generation"); got != "3" {
		t.Fatalf("X-Kiwi-Lease-Generation = %q, want 3", got)
	}

	fsrv.mu.Lock()
	bodies := append([][]byte{}, fsrv.generatedBodies...)
	fsrv.mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("generated POSTs = %d, want 1", len(bodies))
	}
	var parsed struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `json:"run"`
			} `json:"steps"`
		} `json:"jobs"`
		Deps map[string][]string `json:"deps"`
	}
	if err := json.Unmarshal(bodies[0], &parsed); err != nil {
		t.Fatalf("generated body is not valid fragment JSON: %v: %s", err, bodies[0])
	}
	if _, ok := parsed.Jobs["child-a"]; !ok {
		t.Fatalf("fragment jobs missing child-a: %s", bodies[0])
	}
	if deps := parsed.Deps["child-b"]; len(deps) != 1 || deps[0] != "child-a" {
		t.Fatalf("fragment deps = %v, want child-b -> [child-a]", parsed.Deps)
	}
}

// TestExecuteGeneratedFragmentRejectedFailsJob drives a non-2xx response
// from the /generated endpoint on a job WITHOUT generate.optional: the job
// completion must fail with the "generated graph rejected" error, so a run
// can never silently lose its declared children.
func TestExecuteGeneratedFragmentRejectedFailsJob(t *testing.T) {
	fsrv := &fakeRunnerServer{generatedStatus: http.StatusUnprocessableEntity}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    generate:\n      path: generated.json\n    steps:\n      - run: echo hi\n"
	task := basicTask(base)
	task.Job.CompiledJobPayload = buildPayload(t, base, "build")

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "generated.json"), []byte(`{"jobs":{},"deps":{}}`), 0o644)
	}
	r.execute(context.Background(), task)

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusFailure {
		t.Fatalf("status = %s (%s), want failure for a rejected generated graph", c.Status, c.Error)
	}
	if !strings.Contains(c.Error, "generated graph rejected") {
		t.Fatalf("completion error = %q, want the generated-graph rejection", c.Error)
	}
	if h := fsrv.headerOf(http.MethodPost, "/api/v1/jobs/job-1/generated"); h == nil {
		t.Fatal("no /generated POST recorded")
	}
}

// TestExecuteGeneratedFragmentRejectedOptionalCompletes pins the opt-out:
// with generate.optional=true the same non-2xx response stays a warning and
// the job completes successfully.
func TestExecuteGeneratedFragmentRejectedOptionalCompletes(t *testing.T) {
	fsrv := &fakeRunnerServer{generatedStatus: http.StatusUnprocessableEntity}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    generate:\n      path: generated.json\n      optional: true\n    steps:\n      - run: echo hi\n"
	task := basicTask(base)
	task.Job.CompiledJobPayload = buildPayload(t, base, "build")

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "generated.json"), []byte(`{"jobs":{},"deps":{}}`), 0o644)
	}
	r.execute(context.Background(), task)

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusSuccess {
		t.Fatalf("status = %s (%s), want success (generate.optional downgrades the rejection)", c.Status, c.Error)
	}
	fsrv.mu.Lock()
	logs := strings.Join(fsrv.logLines, "\n")
	fsrv.mu.Unlock()
	if !strings.Contains(logs, "generate.optional=true") {
		t.Fatalf("optional rejection not reported as a warning: %q", logs)
	}
}

// TestExecuteGeneratePathOnlyOnSuccess verifies a failed job never uploads
// a fragment even when generate.path is declared.
func TestExecuteGeneratePathOnlyOnSuccess(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    generate:\n      path: generated.json\n    steps:\n      - run: exit 1\n"
	task := basicTask(base)
	task.Job.CompiledJobPayload = buildPayload(t, base, "build")

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "generated.json"), []byte(`{"jobs":{},"deps":{}}`), 0o644)
	}
	r.execute(context.Background(), task)

	if h := fsrv.headerOf(http.MethodPost, "/api/v1/jobs/job-1/generated"); h != nil {
		t.Fatal("failed job uploaded a generated fragment")
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusFailure {
		t.Fatalf("status = %s, want failure", c.Status)
	}
}

// TestExecuteGeneratePathSymlinkFailsJob declares generate.path and plants a
// symlink to a host file outside the workspace at that path. The fragment
// is read through the native backend's no-follow read, so the read fails and
// the JOB fails with a clear error — never a warning — and no fragment is
// POSTed.
func TestExecuteGeneratePathSymlinkFailsJob(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    generate:\n      path: generated.json\n    steps:\n      - run: echo hi\n"
	task := basicTask(base)
	task.Job.CompiledJobPayload = buildPayload(t, base, "build")

	secret := filepath.Join(t.TempDir(), "host-secret.txt")
	if err := os.WriteFile(secret, []byte(`{"jobs":{"evil":{"runtime":"native","steps":[{"run":"echo pwned"}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.Symlink(secret, filepath.Join(dir, "generated.json"))
	}
	r.execute(context.Background(), task)

	if h := fsrv.headerOf(http.MethodPost, "/api/v1/jobs/job-1/generated"); h != nil {
		t.Fatal("fragment POSTed despite unreadable generate.path")
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusFailure {
		t.Fatalf("status = %s (%s), want failure for unreadable generate.path", c.Status, c.Error)
	}
	if !strings.Contains(c.Error, "generate.path") {
		t.Fatalf("error = %q, want generate.path refusal", c.Error)
	}
}

func TestSnapshotRequested(t *testing.T) {
	cases := []struct {
		name string
		on   []string
		st   model.Status
		want bool
	}{
		{"empty on captures success", nil, model.StatusSuccess, true},
		{"empty on captures failure", nil, model.StatusFailure, true},
		{"empty on captures cancelled", nil, model.StatusCancelled, true},
		{"empty on captures skipped", nil, model.StatusSkipped, true},
		{"listed status matches", []string{"failure"}, model.StatusFailure, true},
		{"listed status with case/spacing", []string{" Success "}, model.StatusSuccess, true},
		{"unlisted status not captured", []string{"failure"}, model.StatusSuccess, false},
		{"cancelled not captured when unlisted", []string{"success", "failure"}, model.StatusCancelled, false},
		{"multi-list match", []string{"success", "failure", "cancelled"}, model.StatusCancelled, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := snapshotRequested(pipeline.SnapshotSpec{On: tc.on}, tc.st); got != tc.want {
				t.Fatalf("snapshotRequested(On=%v, %s) = %t, want %t", tc.on, tc.st, got, tc.want)
			}
		})
	}
}

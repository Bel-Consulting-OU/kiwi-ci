package executor

// External-create ambiguity contract: a command error from `docker run`,
// `docker network create`, a service launch or `tart clone` is NOT proof the
// resource was not created. Every such failure must attempt a bounded
// remove-by-name; only a proven absence (rm exit 0 or a positive not-found)
// may tear down the workspace/protections. Anything else reports CleanupDebt
// so the runner retains the ledger and stops leasing.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

// backendDebtCollector records the raw (kind, resource, err) reports the
// backends' ReportCleanupDebt hooks receive.
func backendDebtCollector(dst *[]CleanupDebt) func(CleanupKind, string, error) {
	return func(kind CleanupKind, resource string, err error) {
		*dst = append(*dst, CleanupDebt{Kind: kind, Resource: resource, Err: err})
	}
}

func TestDockerRunAmbiguousCreateRemovesThenSucceeds(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_STATE", t.TempDir())
	// The fake creates the container state, then errors: the executor must
	// remove it by name and, once rm succeeds, run the normal restore path.
	t.Setenv("FAKE_DOCKER_RUN_CREATE_THEN_FAIL", "1")

	origProvision := provisionWorkspace
	restores := 0
	provisionWorkspace = func(string, int, int, bool) (func() error, error) {
		return func() error { restores++; return nil }, nil
	}
	t.Cleanup(func() { provisionWorkspace = origProvision })

	var debts []CleanupDebt
	b := &ContainerBackend{
		Image: "alpine:3.19", RunID: "r", JobID: "j", ReadOnlyRootFS: true,
		ReportCleanupDebt: backendDebtCollector(&debts),
	}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "start job container") {
		t.Fatalf("ambiguous docker run = %v, want start job container failure", err)
	}
	if strings.Contains(err.Error(), "may exist") {
		t.Fatalf("proven-absent removal still reported an unproven state: %v", err)
	}
	if restores != 1 {
		t.Fatalf("workspace restore ran %d times, want 1 after proven absence", restores)
	}
	if len(debts) != 0 {
		t.Fatalf("proven-absent removal reported debt: %+v", debts)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if b.container == "" || !strings.Contains(log, "rm -f "+b.container) {
		t.Fatalf("bounded remove-by-name was not attempted for %q:\n%s", b.container, log)
	}
}

func TestDockerRunAmbiguousCreateCleanupFailureReportsDebt(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_STATE", t.TempDir())
	t.Setenv("FAKE_DOCKER_RUN_CREATE_THEN_FAIL", "1")
	// The removal fails for a reason other than absence: the container may be
	// live, so the workspace protections MUST stay in place.
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	t.Setenv("FAKE_DOCKER_RM_MSG", "operation not permitted")

	origProvision := provisionWorkspace
	restores := 0
	provisionWorkspace = func(string, int, int, bool) (func() error, error) {
		return func() error { restores++; return nil }, nil
	}
	t.Cleanup(func() { provisionWorkspace = origProvision })

	quotaCleanups := 0
	var debts []CleanupDebt
	b := &ContainerBackend{
		Image: "alpine:3.19", RunID: "r", JobID: "j", ReadOnlyRootFS: true,
		quotaCleanup:      func() error { quotaCleanups++; return nil },
		ReportCleanupDebt: backendDebtCollector(&debts),
	}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "container may exist; not removed") {
		t.Fatalf("ambiguous docker run with failed removal = %v", err)
	}
	if len(debts) != 1 || debts[0].Kind != CleanupMainRuntime || debts[0].Resource != b.container {
		t.Fatalf("debts = %+v, want one %s debt for %q", debts, CleanupMainRuntime, b.container)
	}
	if debts[0].Err == nil {
		t.Fatal("debt report carries no error")
	}
	if restores != 0 {
		t.Fatalf("workspace restore ran under a possibly-live container: %d", restores)
	}
	if quotaCleanups != 0 {
		t.Fatalf("quota cleanup ran under a possibly-live container: %d", quotaCleanups)
	}
	if b.restoreWorkspace == nil || b.quotaCleanup == nil {
		t.Fatal("workspace protections were discarded instead of retained")
	}
}

func TestServiceNetworkAmbiguousCreateReportsDebt(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_STATE", t.TempDir())
	t.Setenv("FAKE_DOCKER_NET_CREATE_THEN_FAIL", "1")
	t.Setenv("FAKE_DOCKER_NET_RM_EXIT", "1")
	t.Setenv("FAKE_DOCKER_NET_RM_MSG", "operation not permitted")

	var debts []CleanupDebt
	svc := []pipeline.Service{{Name: "db", Image: "postgres:16"}}
	_, _, err := startContainerServicesOwned(context.Background(), "r", "j", runtimeOwner{}, svc, pipeline.Resources{}, false, false, "", func(string) {}, func(d CleanupDebt) {
		debts = append(debts, d)
	})
	if err == nil || !strings.Contains(err.Error(), "create services network") {
		t.Fatalf("ambiguous network create = %v, want the create error", err)
	}
	want := serviceNetworkName("r", "j")
	if len(debts) != 1 || debts[0].Kind != CleanupNetwork || debts[0].Resource != want {
		t.Fatalf("debts = %+v, want one %s debt for %q", debts, CleanupNetwork, want)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if !strings.Contains(log, "network rm "+want) {
		t.Fatalf("bounded network removal was not attempted:\n%s", log)
	}
}

func TestServiceContainerAmbiguousCreateIsInOwnedSet(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_STATE", t.TempDir())
	t.Setenv("FAKE_DOCKER_RUN_CREATE_THEN_FAIL", "1")
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	t.Setenv("FAKE_DOCKER_RM_MSG", "operation not permitted")

	var debts []CleanupDebt
	svc := []pipeline.Service{{Name: "db", Image: "postgres:16"}}
	_, _, err := startContainerServicesOwned(context.Background(), "r", "j", runtimeOwner{}, svc, pipeline.Resources{}, false, false, "", func(string) {}, func(d CleanupDebt) {
		debts = append(debts, d)
	})
	if err == nil || !strings.Contains(err.Error(), "start service") {
		t.Fatalf("ambiguous service run = %v, want the start error", err)
	}
	want := serviceContainerName("r", "j", 0)
	found := false
	for _, d := range debts {
		if d.Kind == CleanupService && d.Err != nil && strings.Contains(d.Err.Error(), want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("debts = %+v, want a %s debt naming %q", debts, CleanupService, want)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if !strings.Contains(log, "rm -f "+want) {
		t.Fatalf("the prospective service container was not in the owned cleanup set:\n%s", log)
	}
	// The bounded network removal still runs even though the container rm
	// failed.
	if !strings.Contains(log, "network rm "+serviceNetworkName("r", "j")) {
		t.Fatalf("service network cleanup was not attempted:\n%s", log)
	}
}

// fakeLifecycleBackend is a Backend + JobLifecycle whose start and close both
// fail, used to exercise runJob's start-failure cleanup path without a
// runtime.
type fakeLifecycleBackend struct {
	startErr  error
	closeErr  error
	closeCall int
}

func (*fakeLifecycleBackend) Name() string { return "fake-lifecycle" }

func (*fakeLifecycleBackend) Run(context.Context, Command, func(string)) error { return nil }

func (*fakeLifecycleBackend) ReadFile(context.Context, string, int64) ([]byte, error) {
	return nil, os.ErrNotExist
}

func (f *fakeLifecycleBackend) StartJob(context.Context, string, func(string)) error {
	return f.startErr
}

func (f *fakeLifecycleBackend) CloseJob() error {
	f.closeCall++
	return f.closeErr
}

func TestStartJobFailureInvokesCloseJobAndReportsDebt(t *testing.T) {
	startErr := errors.New("start refused after partial setup")
	closeErr := errors.New("close could not prove removal")
	fake := &fakeLifecycleBackend{startErr: startErr, closeErr: closeErr}
	orig := backendForNetwork
	backendForNetwork = func(string, string, string, string) (Backend, error) { return fake, nil }
	t.Cleanup(func() { backendForNetwork = orig })

	var debts []CleanupDebt
	ws := t.TempDir()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: &covSink{}, OnCleanupDebt: collectDebt(&debts)}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID:  "j",
		Job: pipeline.Job{Runtime: "native", Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || res.Error != startErr.Error() {
		t.Fatalf("runJob result = %+v, want the StartJob failure", res)
	}
	if fake.closeCall != 1 {
		t.Fatalf("CloseJob calls = %d, want exactly 1 after a failed StartJob", fake.closeCall)
	}
	found := false
	for _, d := range debts {
		if d.Kind == CleanupMainRuntime && d.Resource == "j" && errors.Is(d.Err, closeErr) {
			found = true
		}
	}
	if !found {
		t.Fatalf("debts = %+v, want one %s debt for the failed close", debts, CleanupMainRuntime)
	}
}

func TestTartCloneFailureCleanupFailureReportsDebt(t *testing.T) {
	testutil.UnixShell(t)
	installFakeBins(t)
	t.Setenv("FAKE_TART_CLONE_EXIT", "1")
	// The bounded delete cannot prove absence (not a "does not exist"
	// outcome): the clone may be live and must be reported.
	t.Setenv("FAKE_TART_DELETE_EXIT", "1")
	t.Setenv("FAKE_TART_DELETE_MSG", "operation not permitted")

	var debts []CleanupDebt
	b := &TartBackend{VM: "vm", ReportCleanupDebt: backendDebtCollector(&debts)}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "tart clone") {
		t.Fatalf("clone failure = %v, want the tart clone error", err)
	}
	if len(debts) != 1 || debts[0].Kind != CleanupVM || debts[0].Resource != b.clone || debts[0].Err == nil {
		t.Fatalf("debts = %+v, want one %s debt for %q", debts, CleanupVM, b.clone)
	}
	if b.clone == "" {
		t.Fatal("clone identity was dropped although absence was not proven")
	}
}

func TestTartRunStartCleanupFailureReportsDebt(t *testing.T) {
	testutil.UnixShell(t)
	installFakeBins(t)
	// The fake tart deletes itself on `tart run --help`, so the subsequent
	// run process cannot start; the clone's bounded delete also fails because
	// the binary is gone, leaving absence unproven.
	t.Setenv("FAKE_TART_SELF_DESTRUCT", "1")

	var debts []CleanupDebt
	b := &TartBackend{VM: "vm", ReportCleanupDebt: backendDebtCollector(&debts)}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "clone cleanup") {
		t.Fatalf("run-start failure = %v, want the clone cleanup error", err)
	}
	if len(debts) != 1 || debts[0].Kind != CleanupVM || debts[0].Resource != b.clone || debts[0].Err == nil {
		t.Fatalf("debts = %+v, want one %s debt for %q", debts, CleanupVM, b.clone)
	}
}

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
	"path/filepath"
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
	if len(debts) != 1 || debts[0].Kind != CleanupNetwork || debts[0].Err == nil {
		t.Fatalf("debts = %+v, want one %s debt", debts, CleanupNetwork)
	}
	want := debts[0].Resource
	if !strings.HasPrefix(want, "kiwi-net-r-j-") {
		t.Fatalf("network debt resource = %q, want the kiwi-net-r-j- prefix", want)
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
	want := ""
	for _, d := range debts {
		if d.Kind == CleanupService && d.Err != nil && strings.HasPrefix(d.Resource, "kiwi-svc-r-j-1-") {
			want = d.Resource
		}
	}
	if want == "" {
		t.Fatalf("debts = %+v, want a %s debt for the kiwi-svc-r-j-1- container", debts, CleanupService)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if !strings.Contains(log, "rm -f "+want) {
		t.Fatalf("the prospective service container was not in the owned cleanup set:\n%s", log)
	}
	// The bounded network removal still runs even though the container rm
	// failed.
	if !strings.Contains(log, "network rm kiwi-net-r-j-") {
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

// TestServiceCleanupNeverTouchesAnotherOwnersResource is the ownership proof
// for the unique service names: a container/network seeded under the LEGACY
// deterministic name (kiwi-svc-<run>-<job>-1 / kiwi-net-<run>-<job>) by a
// different attempt/owner must never be addressed by this attempt's cleanup.
// Only the attempt's own per-attempt names may appear in rm/network rm lines,
// and the seeded resources must survive.
func TestServiceCleanupNeverTouchesAnotherOwnersResource(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	legacyContainer := "kiwi-svc-runa-joba-1"
	legacyNetwork := "kiwi-net-runa-joba"
	for _, legacy := range []string{legacyContainer, legacyNetwork} {
		if err := os.MkdirAll(filepath.Join(state, legacy), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(dir, "docker.log")
	script := `#!/bin/sh
echo "$@" >> "` + logPath + `"
sub="$1"; shift
case "$sub" in
  network)
    case "$1" in
      create)
        net=""
        for a in "$@"; do net="$a"; done
        mkdir -p "` + state + `/$net"
        echo netid; exit 0;;
      rm)
        rm -rf "` + state + `/$2"
        exit 0;;
    esac;;
  run)
    name=""
    prev=""
    for a in "$@"; do
      if [ "$prev" = "--name" ]; then name="$a"; fi
      prev="$a"
    done
    if [ -e "` + state + `/attempts" ]; then echo "second service refused" >&2; exit 1; fi
    : > "` + state + `/attempts"
    mkdir -p "` + state + `/$name"
    echo "fake-container-$$"; exit 0;;
  rm)
    name="$1"
    if [ "$name" = "-f" ] && [ -n "$2" ]; then name="$2"; fi
    rm -rf "` + state + `/$name"
    exit 0;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// The SECOND service fails, so cleanupAll must remove the first service's
	// container (and the newly created network) by their unique names.
	_, _, err := startContainerServices(context.Background(), "runa", "joba",
		[]pipeline.Service{{Name: "db", Image: "postgres:16"}, {Name: "cache", Image: "redis:7"}},
		pipeline.Resources{}, false, false, "", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "start service") {
		t.Fatalf("failing second service = %v, want the start error", err)
	}
	data, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	log := string(data)
	ownContainers := map[string]bool{}
	removedNetworks := []string{}
	for _, line := range strings.Split(log, "\n") {
		if name, ok := strings.CutPrefix(line, "rm -f "); ok {
			if !strings.HasPrefix(name, "kiwi-svc-runa-joba-") {
				t.Fatalf("cleanup removed a foreign container %q:\n%s", name, log)
			}
			ownContainers[name] = true
		}
		if name, ok := strings.CutPrefix(line, "network rm "); ok {
			removedNetworks = append(removedNetworks, name)
		}
	}
	if len(ownContainers) == 0 {
		t.Fatalf("the attempt's own unique containers were never removed:\n%s", log)
	}
	if len(removedNetworks) != 1 || !strings.HasPrefix(removedNetworks[0], "kiwi-net-runa-joba-") {
		t.Fatalf("network cleanup = %v, want the attempt's own unique network:\n%s", removedNetworks, log)
	}
	// The seeded foreign resources were never addressed and still exist.
	for _, legacy := range []string{legacyContainer, legacyNetwork} {
		if strings.Contains(log, "rm -f "+legacy+"\n") || strings.Contains(log, "network rm "+legacy+"\n") {
			t.Fatalf("cleanup addressed the seeded foreign resource %q:\n%s", legacy, log)
		}
		if _, statErr := os.Stat(filepath.Join(state, legacy)); statErr != nil {
			t.Fatalf("seeded foreign resource %q was removed: %v", legacy, statErr)
		}
	}
}

// TestServiceNamesUniqueAcrossAttempts proves two successive start/cleanup
// attempts for the SAME run/job use disjoint physical container and network
// names (each attempt removes exactly its own), while the user-facing service
// alias stays identical across attempts.
func TestServiceNamesUniqueAcrossAttempts(t *testing.T) {
	installFakeBins(t)
	ctx := context.Background()
	services := []pipeline.Service{{Name: "db", Image: "postgres:16"}}
	var networks []string
	for attempt := 0; attempt < 2; attempt++ {
		network, cleanup, err := startContainerServices(ctx, "runU", "jobU", services, pipeline.Resources{}, false, false, "", func(string) {})
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		networks = append(networks, network)
		cleanup()
	}
	if networks[0] == networks[1] {
		t.Fatalf("network name reused across attempts: %v", networks)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	runs := runLines(log)
	if len(runs) != 2 {
		t.Fatalf("docker run lines = %d, want 2:\n%s", len(runs), log)
	}
	var containers []string
	for _, line := range runs {
		name := flagValue(line, "--name")
		if name == "" {
			t.Fatalf("run line without --name: %s", line)
		}
		containers = append(containers, name)
	}
	if containers[0] == containers[1] {
		t.Fatalf("container name reused across attempts: %v", containers)
	}
	for i := 0; i < 2; i++ {
		if !strings.HasPrefix(containers[i], "kiwi-svc-runu-jobu-1-") {
			t.Fatalf("attempt %d container %q lost the identity prefix", i, containers[i])
		}
		if !strings.HasPrefix(networks[i], "kiwi-net-runu-jobu-") {
			t.Fatalf("attempt %d network %q lost the identity prefix", i, networks[i])
		}
		if !strings.Contains(log, "rm -f "+containers[i]) {
			t.Fatalf("attempt %d did not remove its own container %q:\n%s", i, containers[i], log)
		}
		if !strings.Contains(log, "network rm "+networks[i]) {
			t.Fatalf("attempt %d did not remove its own network %q:\n%s", i, networks[i], log)
		}
	}
	if got := strings.Count(log, "--network-alias db"); got != 2 {
		t.Fatalf("--network-alias db count = %d, want 2 (alias stable across attempts):\n%s", got, log)
	}
}

// TestServiceNetworkCreateCarriesOwnershipLabels pins the label contract on
// the services network: kiwi.run and kiwi.job always, plus kiwi.runner and
// kiwi.instance when the starting runner has an identity (crash
// reconciliation depends on them).
func TestServiceNetworkCreateCarriesOwnershipLabels(t *testing.T) {
	installFakeBins(t)
	_, cleanup, err := startContainerServicesOwned(context.Background(), "runL", "jobL",
		runtimeOwner{RunnerID: "runner-a", InstanceID: "inst-1"},
		[]pipeline.Service{{Name: "db", Image: "postgres:16"}},
		pipeline.Resources{}, false, false, "", func(string) {}, nil)
	if err != nil {
		t.Fatalf("startContainerServicesOwned: %v", err)
	}
	cleanup()
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	createLine := ""
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "network create ") {
			createLine = line
			break
		}
	}
	if createLine == "" {
		t.Fatalf("no network create line:\n%s", log)
	}
	for _, want := range []string{"kiwi.run=runL", "kiwi.job=jobL", "kiwi.runner=runner-a", "kiwi.instance=inst-1"} {
		if !strings.Contains(createLine, want) {
			t.Fatalf("network create %q missing label %s", createLine, want)
		}
	}
}

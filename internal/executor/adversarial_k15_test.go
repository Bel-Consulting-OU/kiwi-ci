package executor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Adversarial: failure()-gated downloads must NOT restore on a green run,
// and MUST be deferred until after the job fails.
func TestDownloadIfFailureOnly(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "out.txt"), []byte("log"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := artifact.Default()
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  producer:
    steps:
      - name: write
        run: "true"
    artifacts:
      - name: log
        paths: ["out.txt"]
  consumer:
    needs: [producer]
    downloads:
      - from: producer
        name: log
        path: diag
        if: failure()
    steps:
      - name: boom
        run: "exit 1"
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	// One Executor owns the artifact registry for the whole run (producer
	// records paths; consumer looks them up) — the same contract local kiwi
	// run and the distributed runner use.
	ex := &Executor{Opt: Options{
		Workspace: ws, RunID: "run-dl", Artifacts: store,
		Logs: logging.Func(func(string, string, string) {}),
	}}
	resP := ex.RunCompiledJob(context.Background(), g.Spec, g.Jobs["producer"])
	if resP.Status != model.StatusSuccess {
		t.Fatalf("producer = %+v", resP)
	}
	ws2 := t.TempDir()
	exC := &Executor{Opt: Options{
		Workspace: ws2, RunID: "run-dl", Artifacts: store,
		LocalDownloads: true, Logs: logging.Func(func(string, string, string) {}),
	}}
	// Share the registry so the consumer can see the producer's publication.
	exC.artifacts = ex.artifacts
	cons := exC.RunCompiledJob(context.Background(), g.Spec, g.Jobs["consumer"])
	// After the job failed, the failure()-gated restore may have landed
	// (that is the contract). Setup must not restore it on a GREEN run —
	// check that with a separate green consumer below.
	if cons.Status != model.StatusFailure {
		t.Fatalf("consumer status = %v err=%s", cons.Status, cons.Error)
	}

	// Green job, failure()-only download: artifact exists but must NOT be
	// restored while the job succeeds.
	specGreen, err := pipeline.Parse([]byte(`version: 1
jobs:
  producer:
    steps: [{run: "true"}]
    artifacts:
      - name: log
        paths: ["out.txt"]
  consumer:
    needs: [producer]
    downloads:
      - from: producer
        name: log
        path: diag-must-stay-absent
        if: failure()
    steps: [{run: "true"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	gGreen, err := pipeline.Compile(specGreen)
	if err != nil {
		t.Fatal(err)
	}
	wsG := t.TempDir()
	exG := &Executor{Opt: Options{
		Workspace: wsG, RunID: "run-dl", Artifacts: store,
		LocalDownloads: true, Logs: logging.Func(func(string, string, string) {}),
	}}
	exG.artifacts = ex.artifacts
	gRes := exG.RunCompiledJob(context.Background(), gGreen.Spec, gGreen.Jobs["consumer"])
	if gRes.Status != model.StatusSuccess {
		t.Fatalf("green failure()-only consumer = %+v", gRes)
	}
	if _, err := os.Stat(filepath.Join(wsG, "diag-must-stay-absent")); err == nil {
		t.Fatal("failure() download restored on a successful run")
	}

	// Green path: unconditioned download restores during setup.
	spec2, err := pipeline.Parse([]byte(`version: 1
jobs:
  producer:
    steps: [{run: "true"}]
    artifacts:
      - name: log
        paths: ["out.txt"]
  consumer:
    needs: [producer]
    downloads:
      - from: producer
        name: log
        path: diag-ok
    steps: [{run: "true"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	g2, err := pipeline.Compile(spec2)
	if err != nil {
		t.Fatal(err)
	}
	ws3 := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws3, "out.txt"), []byte("log"), 0o644); err != nil {
		t.Fatal(err)
	}
	store2 := artifact.Default()
	exP2 := &Executor{Opt: Options{Workspace: ws3, RunID: "run-dl2", Artifacts: store2, Logs: logging.Func(func(string, string, string) {})}}
	if pr := exP2.RunCompiledJob(context.Background(), g2.Spec, g2.Jobs["producer"]); pr.Status != model.StatusSuccess {
		t.Fatalf("producer2 = %+v", pr)
	}
	ws4 := t.TempDir()
	exC2 := &Executor{Opt: Options{Workspace: ws4, RunID: "run-dl2", Artifacts: store2, LocalDownloads: true, Logs: logging.Func(func(string, string, string) {})}}
	exC2.artifacts = exP2.artifacts
	res2 := exC2.RunCompiledJob(context.Background(), g2.Spec, g2.Jobs["consumer"])
	if res2.Status != model.StatusSuccess {
		t.Fatalf("green consumer = %+v", res2)
	}
	if _, err := os.Stat(filepath.Join(ws4, "diag-ok")); err != nil {
		t.Fatalf("setup download did not land: %v", err)
	}
}

// Adversarial: native service whose binary is missing fails the job loudly
// without running steps.
func TestNativeServiceMissingBinary(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  live:
    runtime: native
    services:
      - name: nope
        native: true
        ready: "tcp:6404"
        command: ["kiwi-definitely-missing-svc-bin-xyz"]
    steps:
      - name: must-not-run
        run: "echo RAN"
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: logging.Func(func(_, _, l string) { lines = append(lines, l) })}}
	r := ex.RunCompiledJob(context.Background(), g.Spec, g.Jobs["live"])
	if r.Status != model.StatusFailure {
		t.Fatalf("status = %v err=%s", r.Status, r.Error)
	}
	if !strings.Contains(r.Error, "nope") {
		t.Fatalf("error = %q", r.Error)
	}
	for _, l := range lines {
		if strings.Contains(l, "RAN") {
			t.Fatalf("step ran despite missing native service: %v", lines)
		}
	}
}

// Adversarial: toolchain version mismatch fails before steps run.
func TestToolchainVersionMismatchBeforeSteps(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.Parse([]byte(`version: 1
toolchains:
  go:
    version: "THIS_VERSION_NEVER_MATCHES"
    command: ["go", "version"]
jobs:
  b:
    toolchains: [go]
    steps:
      - name: must-not-run
        run: "echo RAN"
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: logging.Func(func(_, _, l string) { lines = append(lines, l) })}}
	res := ex.RunCompiledJob(context.Background(), g.Spec, g.Jobs["b"])
	if res.Status != model.StatusFailure {
		t.Fatalf("status = %v err=%s", res.Status, res.Error)
	}
	for _, l := range lines {
		if strings.Contains(l, "RAN") {
			t.Fatalf("step ran despite toolchain mismatch: %v", lines)
		}
	}
}

// Adversarial: empty ChangedFiles produces [] not null in the JSON envelope.
func TestChangedFilesEmptyJSON(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  probe:
    steps:
      - run: |
          set -eu
          echo "json=$KIWI_CHANGED_JSON"
          echo "count=$KIWI_CHANGED_COUNT"
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: logging.Func(func(_, _, l string) { buf.WriteString(l + "\n") })}}
	res := ex.RunCompiledJob(context.Background(), g.Spec, g.Jobs["probe"])
	if res.Status != model.StatusSuccess {
		t.Fatalf("status=%v err=%s", res.Status, res.Error)
	}
	out := buf.String()
	if !strings.Contains(out, `"count":0`) {
		t.Fatalf("empty changed JSON: %s", out)
	}
	if strings.Contains(out, `"paths":null`) {
		t.Fatalf("paths must be [] not null: %s", out)
	}
}

// Adversarial: native service teardown completes quickly and leaves env.
func TestNativeServiceTeardownReapsPID(t *testing.T) {
	svc := pipeline.Service{
		Name:    "sleeper",
		Native:  true,
		Ready:   "tcp:6403",
		Command: []string{"python3", "-c", "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',6403)); s.listen(1); time.sleep(120)"},
	}
	_, env, cleanup, err := startNativeServices(context.Background(), "j", t.TempDir(), nil, []pipeline.Service{svc}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cleanup() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cleanup: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup hung")
	}
	if env["KIWI_SERVICE_SLEEPER_HOST"] == "" {
		t.Fatal("missing host env")
	}
}

func TestReadyProbePortParsing(t *testing.T) {
	cases := []struct {
		probe string
		port  int
		ok    bool
	}{
		{"tcp:6399", 6399, true},
		{"http:8123/ping", 8123, true},
		{"tcp:0", 0, false},
		{"tcp:notaport", 0, false},
		{"", 0, false},
		{"pg_isready:5432", 0, false}, // kind not tcp/http
	}
	for _, c := range cases {
		p, ok := readyProbePort(c.probe)
		if p != c.port || ok != c.ok {
			t.Fatalf("readyProbePort(%q) = (%d,%v), want (%d,%v)", c.probe, p, ok, c.port, c.ok)
		}
	}
}

// Live: ready tcp:N must bind N (not an ephemeral PORT) so a hardcoded
// listener and the probe agree.
func TestNativeServiceHonorsDeclaredReadyPort(t *testing.T) {
	svc := pipeline.Service{
		Name:    "hard",
		Native:  true,
		Command: []string{"python3", "-c", "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',6399)); s.listen(1); time.sleep(60)"},
		Ready:   "tcp:6399",
	}
	_, env, cleanup, err := startNativeServices(context.Background(), "j", t.TempDir(), nil, []pipeline.Service{svc}, func(string) {})
	if err != nil {
		t.Fatalf("startNativeServices: %v", err)
	}
	defer cleanup()
	if env["KIWI_SERVICE_HARD_PORT"] != "6399" {
		t.Fatalf("PORT env = %q, want 6399", env["KIWI_SERVICE_HARD_PORT"])
	}
}

// Two native services cannot share a declared ready port: the second bind
// must fail the job loudly (not silently probe the first).
func TestNativeServicesSameReadyPortFailsLoudly(t *testing.T) {
	svcA := pipeline.Service{Name: "a", Native: true, Ready: "tcp:6401",
		Command: []string{"python3", "-c", "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',6401)); s.listen(5); time.sleep(30)"}}
	// Second claims the same port and exits if bind fails (no Ready: the
	// 200ms liveness window must catch the death).
	svcB := pipeline.Service{Name: "b", Native: true,
		Command: []string{"python3", "-c", "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',6401))"}}
	_, _, cleanup, err := startNativeServices(context.Background(), "j", t.TempDir(), nil, []pipeline.Service{svcA, svcB}, func(string) {})
	if cleanup != nil {
		defer cleanup()
	}
	if err == nil {
		t.Fatal("second service on occupied tcp:6401 must fail")
	}
}

// Unknown changed-file set must not silently skip a path-restricted job.
func TestUnknownChangedFilesRunsPathJob(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  gated:
    paths: [src/**]
    steps:
      - run: "echo RAN"
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	ex := &Executor{Opt: Options{
		Workspace: ws, RunID: "r",
		ChangedFiles: nil, ChangedFilesKnown: false,
		Logs: logging.Func(func(_, _, l string) { lines = append(lines, l) }),
	}}
	res := ex.RunCompiledJob(context.Background(), g.Spec, g.Jobs["gated"])
	if res.Status != model.StatusSuccess {
		t.Fatalf("unknown-diff path job = %+v", res)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "unknown") {
		t.Fatalf("expected unknown-diff log, got:\n%s", joined)
	}
	if !strings.Contains(joined, "RAN") {
		t.Fatalf("job did not run:\n%s", joined)
	}
	// Known empty: path job must skip.
	ex2 := &Executor{Opt: Options{
		Workspace: ws, RunID: "r",
		ChangedFiles: nil, ChangedFilesKnown: true,
		Logs: logging.Func(func(string, string, string) {}),
	}}
	res2 := ex2.RunCompiledJob(context.Background(), g.Spec, g.Jobs["gated"])
	if res2.Status != model.StatusSkipped {
		t.Fatalf("known-empty path job = %+v, want skipped", res2)
	}
}

// A service whose child dies while another process answers the port must
// NOT be certified ready (wrong-process / port stolen).
func TestNativeReadyFailsWhenChildExits(t *testing.T) {
	// Occupy 6410 with a real listener (the "old postgres").
	ln, err := net.Listen("tcp", "127.0.0.1:6410")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Our service fails to bind 6410 and exits immediately.
	svc := pipeline.Service{
		Name:    "ghost",
		Native:  true,
		Ready:   "tcp:6410",
		Command: []string{"python3", "-c", "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',6410)); s.listen(1)"},
	}
	// Without SO_REUSEADDR the bind fails... Python default SO_REUSEADDR
	// may still fail with in use depending on OS. Force exit on bind fail.
	svc.Command = []string{"python3", "-c", "import socket,sys; s=socket.socket();\ntry:\n s.bind(('127.0.0.1',6410))\nexcept OSError:\n sys.exit(1)\ns.listen(1)\nimport time; time.sleep(30)"}

	_, _, cleanup, err := startNativeServices(context.Background(), "j", t.TempDir(), nil, []pipeline.Service{svc}, func(string) {})
	if cleanup != nil {
		defer cleanup()
	}
	if err == nil {
		t.Fatal("readiness must fail when the owned child exits even if the port answers")
	}
	if !strings.Contains(err.Error(), "exited") && !strings.Contains(err.Error(), "already in use") && !strings.Contains(err.Error(), "ready") {
		t.Fatalf("error = %v, want exit or pre-start occupancy", err)
	}
}

// Two jobs cannot claim the same host port.
func TestNativePortClaimConflicts(t *testing.T) {
	const port = 6411
	if err := claimNativePort(port, "jobA/postgres"); err != nil {
		t.Fatal(err)
	}
	defer releaseNativePort(port)
	err := claimNativePort(port, "jobB/postgres")
	if err == nil || !strings.Contains(err.Error(), "already claimed") {
		t.Fatalf("second claim = %v", err)
	}
}

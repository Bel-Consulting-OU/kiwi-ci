package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestKIWIChangedFilesEnv(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.Parse([]byte(`version: 1
jobs:
  probe:
    runtime: native
    steps:
      - name: dump
        run: |
          set -eu
          echo "count=$KIWI_CHANGED_COUNT"
          echo "files<<EOF"
          echo "$KIWI_CHANGED_FILES"
          echo "EOF"
          echo "json=$KIWI_CHANGED_JSON"
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	ex := &Executor{Opt: Options{
		Workspace:    ws,
		RunID:        "run-changed",
		ChangedFiles: []string{"a/b.go", "site/index.html"},
		Logs: logging.Func(func(job, step, line string) {
			buf.WriteString(line + "\n")
		}),
	}}
	results, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	res := results["probe"]
	if res.Status != model.StatusSuccess {
		t.Fatalf("status=%v err=%s", res.Status, res.Error)
	}
	out := buf.String()
	if !strings.Contains(out, "count=2") {
		t.Fatalf("missing KIWI_CHANGED_COUNT in output:\n%s", out)
	}
	if !strings.Contains(out, "a/b.go") || !strings.Contains(out, "site/index.html") {
		t.Fatalf("missing paths in KIWI_CHANGED_FILES:\n%s", out)
	}
	if !strings.Contains(out, `"count":2`) {
		t.Fatalf("missing JSON envelope:\n%s", out)
	}
}

func TestCheckBoundToolchainsMissing(t *testing.T) {
	e := &Executor{Opt: Options{Logs: logging.Func(func(string, string, string) {})}}
	err := e.checkBoundToolchains(context.Background(), "j", []pipeline.Toolchain{{Path: "kiwi-definitely-missing-binary-xyz", Version: "1"}})
	if err == nil || !strings.Contains(err.Error(), "not on PATH") {
		t.Fatalf("checkBoundToolchains(missing) = %v", err)
	}
}

func TestNativeServicesStartAndTeardown(t *testing.T) {
	// Use a long-lived process: sleep.
	svc := pipeline.Service{
		Name:    "sleeper",
		Native:  true,
		Command: []string{"python3", "-c", "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',6402)); s.listen(1); time.sleep(60)"},
		Ready:   "tcp:6402",
	}
	envNet, env, cleanup, err := startNativeServices(context.Background(), "j", t.TempDir(), []pipeline.Service{svc}, func(string) {})
	if err != nil {
		t.Fatalf("startNativeServices: %v", err)
	}
	if envNet != "native-services" {
		t.Fatalf("network = %q", envNet)
	}
	if env["KIWI_SERVICE_SLEEPER_HOST"] != "127.0.0.1" {
		t.Fatalf("env = %v", env)
	}
	if env["KIWI_SERVICE_SLEEPER_PORT"] == "" {
		t.Fatalf("missing port env: %v", env)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

func TestRuntimeMayRunNativeServices(t *testing.T) {
	native := []pipeline.Service{{Name: "x", Native: true, Command: []string{"true"}}}
	mixed := []pipeline.Service{{Name: "x", Native: true}, {Name: "y", Image: "alpine:3.20"}}
	if !RuntimeMayRunNativeServices("native", native) {
		t.Fatal("native+native svc should be allowed")
	}
	if !RuntimeMayRunNativeServices("", native) {
		t.Fatal("empty runtime is native")
	}
	if RuntimeMayRunNativeServices("container", native) {
		t.Fatal("container+native svc must be refused")
	}
	if RuntimeMayRunNativeServices("native", mixed) {
		t.Fatal("native runtime with container service must be refused")
	}
	_ = filepath.Join
	_ = os.TempDir
}

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/app"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "run":
		err = app.RunLocal(ctx, os.Args[2:])
	case "validate":
		err = app.Validate(os.Args[2:])
	case "explain":
		err = app.Explain(os.Args[2:])
	case "doctor":
		err = app.Doctor(os.Args[2:])
	case "server":
		err = app.Server(ctx, os.Args[2:])
	case "runner":
		err = app.Runner(ctx, os.Args[2:])
	case "dispatch":
		err = app.Dispatch(ctx, os.Args[2:])
	case "import":
		err = app.Import(os.Args[2:])
	case "replay":
		err = app.Replay(ctx, os.Args[2:])
	case "init":
		err = app.Init(os.Args[2:])
	case "runs", "jobs", "logs", "cancel", "approve", "rerun", "artifacts", "schedules", "policy":
		err = app.Ops(ctx, os.Args[1], os.Args[2:])
	case "tui":
		err = app.TUI(ctx, os.Args[2:])
	case "database":
		err = databaseCommand(ctx, os.Args[2:])
	case "config":
		err = configCommand(ctx, os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("kiwi %s (%s/%s)\n", version.String(), runtime.GOOS, runtime.GOARCH)
		if v := version.Full(); v["commit"] != "" || v["build_date"] != "" {
			extra := ""
			if v["commit"] != "" {
				extra = "commit " + v["commit"]
			}
			if v["build_date"] != "" {
				if extra != "" {
					extra += " "
				}
				extra += "built " + v["build_date"]
			}
			fmt.Printf("  %s\n", extra)
		}
		return
	case "help", "--help", "-h":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kiwi:", err)
		os.Exit(1)
	}
}

func databaseCommand(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("database requires a subcommand: migrate or status")
	}
	switch args[0] {
	case "migrate":
		return app.DatabaseMigrate(ctx, args[1:])
	case "status":
		return app.DatabaseStatus(ctx, args[1:])
	default:
		return fmt.Errorf("unknown database subcommand %q (want migrate or status)", args[0])
	}
}

func configCommand(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("config requires a subcommand: check")
	}
	switch args[0] {
	case "check":
		return app.ConfigCheck(ctx, args[1:])
	default:
		return fmt.Errorf("unknown config subcommand %q (want check)", args[0])
	}
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintln(out, `Kiwi CI — local-first CI/CD for fast, reproducible builds.

Usage:
  kiwi init     [--force] [-f .kiwi/pipeline.yaml]
  kiwi run      [-f .kiwi/pipeline.yaml] [--job NAME] [--max-parallel N] [--input k=v]
  kiwi validate [-f .kiwi/pipeline.yaml]
  kiwi explain  [-f .kiwi/pipeline.yaml] [--input k=v] [--why JOB]
  kiwi doctor
  kiwi server   [--listen :8080] [--mode dev|production] [--database-url URL]
                [--config kiwi.toml]
  kiwi config check --config kiwi.toml
  kiwi database migrate|status --database-url URL
  kiwi runner   --server http://127.0.0.1:8080 --token TOKEN [--drain]
  kiwi runner list|drain|disable|enable --server URL --token ADMIN_TOKEN [RUNNER_ID]
  kiwi dispatch --repo owner/name --ref main --input k=v --pipeline FILE
  kiwi runs [--server URL] [--token ADMIN_TOKEN]
  kiwi jobs RUN [--server URL] [--token ADMIN_TOKEN]
  kiwi logs RUN [--job KEY] [--follow] [--interactive] [--server URL] [--token ADMIN_TOKEN]
  kiwi tui RUN [--job KEY] [--follow] [--search TEXT] [--server URL] [--token ADMIN_TOKEN]
  kiwi cancel RUN | kiwi rerun RUN | kiwi approve JOB | kiwi artifacts RUN
  kiwi schedules list|trigger
  kiwi policy check [-f .kiwi/pipeline.yaml] [--trusted]
  kiwi version

Design goals:
  • identical local and remote DAG execution
  • native/container/Tart backends
  • first-class cache, artifacts, retries, cancellation, secrets and provenance
  • explainable scheduling instead of opaque YAML behavior
  • no mandatory cloud service`)
}

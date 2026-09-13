package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/kiwici/kiwi/internal/app"
)

const version = "0.1.0-dev"

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
	case "database":
		err = databaseCommand(ctx, os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("kiwi %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
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

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintln(out, `Kiwi CI — local-first CI/CD for fast, reproducible builds.

Usage:
  kiwi run      [-f .kiwi/pipeline.yaml] [--job NAME] [--max-parallel N]
  kiwi validate [-f .kiwi/pipeline.yaml]
  kiwi explain  [-f .kiwi/pipeline.yaml]
  kiwi doctor
  kiwi server   [--listen :8080] [--mode dev|production] [--database-url URL]
  kiwi database migrate|status --database-url URL
  kiwi runner   --server http://127.0.0.1:8080 --token TOKEN
  kiwi version

Design goals:
  • identical local and remote DAG execution
  • native/container/Tart backends
  • first-class cache, artifacts, retries, cancellation, secrets and provenance
  • explainable scheduling instead of opaque YAML behavior
  • no mandatory cloud service`)
}

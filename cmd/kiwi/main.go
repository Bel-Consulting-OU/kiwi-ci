package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/app"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

func main() {
	os.Exit(runProgram(os.Args[1:], os.Stdout, os.Stderr))
}

// errUnknownCommand marks a usage error; the caller must exit with status 2
// and must not prefix the message with "kiwi:" (usage() already printed the
// command list).
var errUnknownCommand = errors.New("unknown command")

// runProgram dispatches one kiwi invocation and returns the process exit
// code: 0 on success, 1 when the command failed, 2 for usage errors.
func runProgram(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := dispatch(ctx, args, stdout, stderr)
	if errors.Is(err, errUnknownCommand) {
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "kiwi:", err)
		return 1
	}
	return 0
}

// dispatch runs the subcommand named by args[0]. Unknown commands print the
// usage text and return a nil error after reporting why on stderr.
func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	switch args[0] {
	case "run":
		return app.RunLocal(ctx, args[1:])
	case "validate":
		return app.Validate(args[1:])
	case "explain":
		return app.Explain(args[1:])
	case "doctor":
		return app.Doctor(args[1:])
	case "server":
		return app.Server(ctx, args[1:])
	case "runner":
		return app.Runner(ctx, args[1:])
	case "dispatch":
		return app.Dispatch(ctx, args[1:])
	case "import":
		return app.Import(args[1:])
	case "replay":
		return app.Replay(ctx, args[1:])
	case "verify":
		return app.VerifyArtifact(args[1:])
	case "init":
		return app.Init(args[1:])
	case "runs", "jobs", "logs", "cancel", "approve", "rerun", "artifacts", "schedules", "policy":
		return app.Ops(ctx, args[0], args[1:])
	case "tui":
		return app.TUI(ctx, args[1:])
	case "database":
		return databaseCommand(ctx, args[1:])
	case "storage":
		return storageCommand(ctx, args[1:], os.Stdin, stdout, stderr)
	case "repair-repo-identities":
		return repairRepoIdentitiesCommand(ctx, args[1:])
	case "outbox":
		return app.Outbox(ctx, args[1:])
	case "config":
		return configCommand(ctx, args[1:])
	case "version", "--version", "-v":
		printVersion(stdout)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage()
		return errUnknownCommand
	}
}

// printVersion renders the build identity on stdout.
func printVersion(stdout io.Writer) {
	fmt.Fprintf(stdout, "kiwi %s (%s/%s)\n", version.String(), runtime.GOOS, runtime.GOARCH)
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
		fmt.Fprintf(stdout, "  %s\n", extra)
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

// storageCommand routes the operator storage subcommands. The staging-layout
// migration is implemented here (it only needs internal/staging and the
// interactive confirmation); the remaining subcommands stay in internal/app.
func storageCommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) >= 1 && args[0] == "migrate-staging-layout" {
		return migrateStagingLayout(ctx, args[1:], stdin, stdout, stderr)
	}
	return app.Storage(ctx, args)
}

// migrateStagingLayout implements
// `kiwi storage migrate-staging-layout --dir DIR [--force]`.
//
// It reclaims the pre-per-replica "legacy" spool files that a process older
// than the per-replica contract left directly in the shared staging root.
// Those files were staged with NO ownership lock, so the lock the migration
// acquires cannot prove an old process is dead: the operator must confirm the
// old replicas have drained, either interactively or with --force. Without
// one of those confirmations the command refuses and removes nothing.
func migrateStagingLayout(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("storage migrate-staging-layout", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", os.Getenv("KIWI_STAGING_DIR"), "staging root directory (or KIWI_STAGING_DIR)")
	force := fs.Bool("force", false, "confirm every old-layout replica has drained/stopped; skips the interactive prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("storage migrate-staging-layout takes no arguments")
	}
	root := strings.TrimSpace(*dir)
	if root == "" {
		return fmt.Errorf("--dir is required (or set KIWI_STAGING_DIR)")
	}
	if !*force {
		confirmed, err := confirmStagingMigration(stdin, stderr, root)
		if err != nil {
			return err
		}
		if !confirmed {
			return fmt.Errorf("staging layout migration aborted: run with --force once every old-layout replica has drained")
		}
	}
	res, err := staging.MigrateLegacyStagingLayout(ctx, root)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "staging layout migrated: root=%s reclaimed=%d bytes=%d replica_dirs_skipped=%d foreign_files_kept=%d\n",
		res.Root, len(res.Reclaimed), res.ReclaimedBytes, res.ReplicaDirs, res.ForeignFiles)
	for _, name := range res.Reclaimed {
		fmt.Fprintf(stdout, "  reclaimed %s\n", name)
	}
	return nil
}

// confirmStagingMigration asks the operator to type "yes" before the
// destructive pass. An unreadable or non-interactive stdin (EOF) is treated as
// a refusal, so a cron/script invocation without --force removes nothing.
func confirmStagingMigration(stdin io.Reader, stderr io.Writer, root string) (bool, error) {
	fmt.Fprintf(stderr, "This removes legacy top-level kiwi-stage-* spool files from %s.\n", root)
	fmt.Fprintln(stderr, "It is only safe once EVERY old-layout replica has drained/stopped (the lock cannot prove a pre-contract process is dead).")
	fmt.Fprint(stderr, "Type 'yes' to continue: ")
	scanner := bufio.NewScanner(stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, fmt.Errorf("read confirmation: %w", err)
		}
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer == "yes" || answer == "y", nil
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
  kiwi storage  reconcile-reservations --database-url URL
  kiwi storage  migrate-staging-layout --dir DIR [--force]
  kiwi repair-repo-identities [--database-url URL] [--apply] [--cancel-active]
  kiwi outbox dead-letters list|requeue|delete [--database-url URL] [ID]
  kiwi runner   --server http://127.0.0.1:8080 --token TOKEN [--drain]
  kiwi runner list|drain|disable|enable --server URL --token ADMIN_TOKEN [RUNNER_ID]
  kiwi dispatch --repo owner/name --ref main --input k=v --pipeline FILE
  kiwi import   github-actions|gitlab|circleci|woodpecker [--file PATH] [--out PATH] [--list-unsupported]
  kiwi replay   RUN JOB [STEP] --server URL --token TOKEN --pipeline FILE
  kiwi verify   [--server URL] [--token TOKEN] [--trusted-key PATH] ARTIFACT_ID
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

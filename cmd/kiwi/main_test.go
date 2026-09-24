package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/app"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

// captureUsage redirects the global flag output (where usage() writes) into a
// buffer for the duration of fn.
func captureUsage(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := flag.CommandLine.Output()
	flag.CommandLine.SetOutput(&buf)
	t.Cleanup(func() { flag.CommandLine.SetOutput(old) })
	fn()
	return buf.String()
}

func TestRunProgramNoArgsIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var code int
	usageText := captureUsage(t, func() {
		code = runProgram(nil, &stdout, &stderr)
	})
	if code != 2 {
		t.Fatalf("runProgram(nil) = %d, want 2", code)
	}
	if !strings.Contains(usageText, "Usage:") || !strings.Contains(usageText, "kiwi init") {
		t.Fatalf("usage text missing from output: %q", usageText)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("no-arg run must not write to stdout/stderr: %q %q", stdout.String(), stderr.String())
	}
}

func TestRunProgramUnknownCommandExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var code int
	usageText := captureUsage(t, func() {
		code = runProgram([]string{"frobnicate"}, &stdout, &stderr)
	})
	if code != 2 {
		t.Fatalf("unknown command exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "frobnicate"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "kiwi:") {
		t.Fatalf("unknown command must not be prefixed with kiwi:: %q", stderr.String())
	}
	if !strings.Contains(usageText, "Usage:") {
		t.Fatalf("unknown command must print usage, got %q", usageText)
	}
}

func TestRunProgramHelpAndVersionSucceed(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}} {
		var stdout, stderr bytes.Buffer
		var code int
		usageText := captureUsage(t, func() {
			code = runProgram(args, &stdout, &stderr)
		})
		if code != 0 {
			t.Fatalf("runProgram(%v) = %d, want 0", args, code)
		}
		if !strings.Contains(usageText, "Design goals:") {
			t.Fatalf("runProgram(%v) usage missing: %q", args, usageText)
		}
	}

	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		var stdout, stderr bytes.Buffer
		if code := runProgram(args, &stdout, &stderr); code != 0 {
			t.Fatalf("runProgram(%v) = %d, want 0", args, code)
		}
		if !strings.Contains(stdout.String(), "kiwi "+version.String()) {
			t.Fatalf("runProgram(%v) stdout = %q", args, stdout.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("runProgram(%v) stderr = %q", args, stderr.String())
		}
	}
}

func TestRunProgramInitSucceeds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.27.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runProgram([]string{"init", "--dir", dir, "-f", ".kiwi/pipeline.yaml"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runProgram(init) = %d, stderr = %q", code, stderr.String())
	}
	out := filepath.Join(dir, ".kiwi", "pipeline.yaml")
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("init did not write %s: %v", out, err)
	}
}

func TestRunProgramFailureExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runProgram([]string{"validate", "-f", filepath.Join(t.TempDir(), "missing.yaml")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runProgram(validate missing) = %d, want 1", code)
	}
	if !strings.HasPrefix(stderr.String(), "kiwi: ") {
		t.Fatalf("stderr = %q, want kiwi: prefix", stderr.String())
	}
}

// TestDispatchRoutesEveryCommand exercises each switch arm with arguments
// that fail before doing any work, asserting the arm produced a command
// error (and never the unknown-command sentinel).
func TestDispatchRoutesEveryCommand(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		args []string
	}{
		{"run", []string{"run", "--no-such-flag"}},
		{"validate", []string{"validate", "--no-such-flag"}},
		{"explain", []string{"explain", "--no-such-flag"}},
		{"doctor", []string{"doctor", "--no-such-flag"}},
		{"server", []string{"server", "--no-such-flag"}},
		{"runner", []string{"runner", "--no-such-flag"}},
		{"dispatch", []string{"dispatch", "--no-such-flag"}},
		{"import-empty", []string{"import"}},
		{"import", []string{"import", "github-actions", "--no-such-flag"}},
		{"replay", []string{"replay", "--no-such-flag"}},
		{"init", []string{"init", "--no-such-flag"}},
		{"runs", []string{"runs", "--no-such-flag"}},
		{"jobs", []string{"jobs", "--no-such-flag"}},
		{"logs", []string{"logs", "--no-such-flag"}},
		{"cancel", []string{"cancel", "--no-such-flag"}},
		{"approve", []string{"approve", "--no-such-flag"}},
		{"rerun", []string{"rerun", "--no-such-flag"}},
		{"artifacts", []string{"artifacts", "--no-such-flag"}},
		{"schedules", []string{"schedules", "--no-such-flag"}},
		{"policy", []string{"policy", "--no-such-flag"}},
		{"tui", []string{"tui", "--no-such-flag"}},
		{"database-empty", []string{"database"}},
		{"database", []string{"database", "--no-such-flag"}},
		{"outbox-empty", []string{"outbox"}},
		{"outbox", []string{"outbox", "--no-such-flag"}},
		{"config-empty", []string{"config"}},
		{"config", []string{"config", "--no-such-flag"}},
		{"storage-empty", []string{"storage"}},
		{"storage", []string{"storage", "--no-such-flag"}},
		{"repair-repo-identities", []string{"repair-repo-identities", "--no-such-flag"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			var err error
			captureUsage(t, func() {
				err = dispatch(ctx, tc.args, &stdout, &stderr)
			})
			if err == nil {
				t.Fatalf("dispatch(%v) = nil error, want failure", tc.args)
			}
			if errors.Is(err, errUnknownCommand) {
				t.Fatalf("dispatch(%v) misrouted to unknown command", tc.args)
			}
		})
	}
}

func TestDispatchVersionWritesIdentity(t *testing.T) {
	oldCommit, oldDate := version.Commit, version.BuildDate
	t.Cleanup(func() { version.Commit, version.BuildDate = oldCommit, oldDate })

	for _, tc := range []struct {
		commit, date string
		want         string
	}{
		{"", "", ""},
		{"a1b2c3d", "", "commit a1b2c3d"},
		{"", "2026-01-02T03:04:05Z", "built 2026-01-02T03:04:05Z"},
		{"a1b2c3d", "2026-01-02T03:04:05Z", "commit a1b2c3d built 2026-01-02T03:04:05Z"},
	} {
		version.Commit, version.BuildDate = tc.commit, tc.date
		var stdout, stderr bytes.Buffer
		if err := dispatch(context.Background(), []string{"version"}, &stdout, &stderr); err != nil {
			t.Fatalf("dispatch(version) = %v", err)
		}
		if !strings.Contains(stdout.String(), "kiwi "+version.Version) {
			t.Fatalf("stdout = %q", stdout.String())
		}
		if tc.want == "" {
			if strings.Count(strings.TrimSpace(stdout.String()), "\n") != 0 {
				t.Fatalf("unexpected extra version line: %q", stdout.String())
			}
			continue
		}
		if !strings.Contains(stdout.String(), tc.want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), tc.want)
		}
	}
}

func TestDispatchHelpIsSilent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	usageText := captureUsage(t, func() {
		if err := dispatch(context.Background(), []string{"help"}, &stdout, &stderr); err != nil {
			t.Fatalf("dispatch(help) = %v", err)
		}
	})
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("help wrote stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(usageText, "kiwi database migrate|status") {
		t.Fatalf("usage missing database line: %q", usageText)
	}
}

func TestDatabaseCommand(t *testing.T) {
	ctx := context.Background()
	if err := databaseCommand(ctx, nil); err == nil || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("databaseCommand(nil) = %v", err)
	}
	if err := databaseCommand(ctx, []string{"drop"}); err == nil || !strings.Contains(err.Error(), "unknown database subcommand") {
		t.Fatalf("databaseCommand(drop) = %v", err)
	}
	for _, sub := range []string{"migrate", "status"} {
		err := databaseCommand(ctx, []string{sub, "--no-such-flag"})
		if err == nil {
			t.Fatalf("databaseCommand(%s bad flag) = nil, want flag error", sub)
		}
		if strings.Contains(err.Error(), "subcommand") {
			t.Fatalf("databaseCommand(%s) rejected a known subcommand: %v", sub, err)
		}
	}
}

func TestConfigCommand(t *testing.T) {
	ctx := context.Background()
	if err := configCommand(ctx, nil); err == nil || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("configCommand(nil) = %v", err)
	}
	if err := configCommand(ctx, []string{"apply"}); err == nil || !strings.Contains(err.Error(), "unknown config subcommand") {
		t.Fatalf("configCommand(apply) = %v", err)
	}
	err := configCommand(ctx, []string{"check", "--no-such-flag"})
	if err == nil || strings.Contains(err.Error(), "subcommand") {
		t.Fatalf("configCommand(check bad flag) = %v", err)
	}
}

// TestOutboxCommand mirrors TestDatabaseCommand for the operator
// dead-letter command group: missing/unknown subcommands are usage errors and
// known subcommands fail on flags (never on "subcommand").
func TestOutboxCommand(t *testing.T) {
	ctx := context.Background()
	if err := app.Outbox(ctx, nil); err == nil || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("Outbox(nil) = %v", err)
	}
	if err := app.Outbox(ctx, []string{"drop"}); err == nil || !strings.Contains(err.Error(), "unknown outbox subcommand") {
		t.Fatalf("Outbox(drop) = %v", err)
	}
	if err := app.Outbox(ctx, []string{"dead-letters"}); err == nil || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("Outbox(dead-letters) = %v", err)
	}
	if err := app.Outbox(ctx, []string{"dead-letters", "drop"}); err == nil || !strings.Contains(err.Error(), "unknown outbox dead-letters subcommand") {
		t.Fatalf("Outbox(dead-letters drop) = %v", err)
	}
	for _, sub := range []string{"list", "requeue", "delete"} {
		err := app.Outbox(ctx, []string{"dead-letters", sub, "--no-such-flag"})
		if err == nil {
			t.Fatalf("Outbox(dead-letters %s bad flag) = nil, want flag error", sub)
		}
		if strings.Contains(err.Error(), "subcommand") {
			t.Fatalf("Outbox(dead-letters %s) rejected a known subcommand: %v", sub, err)
		}
	}
}

// TestStorageCommand mirrors TestDatabaseCommand for the operator storage
// repair command group.
func TestStorageCommand(t *testing.T) {
	ctx := context.Background()
	if err := app.Storage(ctx, nil); err == nil || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("Storage(nil) = %v", err)
	}
	if err := app.Storage(ctx, []string{"compact"}); err == nil || !strings.Contains(err.Error(), "unknown storage subcommand") {
		t.Fatalf("Storage(compact) = %v", err)
	}
	err := app.Storage(ctx, []string{"reconcile-reservations", "--no-such-flag"})
	if err == nil {
		t.Fatal("Storage(reconcile-reservations bad flag) = nil, want flag error")
	}
	if strings.Contains(err.Error(), "subcommand") {
		t.Fatalf("Storage(reconcile-reservations) rejected a known subcommand: %v", err)
	}
	// A known subcommand without a database URL fails on the URL requirement,
	// never as a usage/subcommand error.
	t.Setenv("KIWI_DATABASE_URL", "")
	err = app.Storage(ctx, []string{"reconcile-reservations"})
	if err == nil || !strings.Contains(err.Error(), "--database-url is required") {
		t.Fatalf("Storage(reconcile-reservations) without a URL = %v", err)
	}
}

// TestStorageCommandRoutesMigrateStagingLayout: the staging-layout migration
// is routed by cmd/kiwi (it only needs internal/staging); every other storage
// subcommand still goes to internal/app.
func TestStorageCommandRoutesMigrateStagingLayout(t *testing.T) {
	ctx := context.Background()
	// A missing --dir is a usage error, not an app dispatch.
	t.Setenv("KIWI_STAGING_DIR", "")
	var out, errOut bytes.Buffer
	err := storageCommand(ctx, []string{"migrate-staging-layout"}, strings.NewReader(""), &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "--dir is required") {
		t.Fatalf("migrate-staging-layout without --dir = %v", err)
	}
	// The reconcile subcommand is unchanged and delegated to internal/app.
	if err := storageCommand(ctx, nil, strings.NewReader(""), &out, &errOut); err == nil || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("storageCommand(nil) = %v", err)
	}
	if err := storageCommand(ctx, []string{"reconcile-reservations", "--no-such-flag"}, strings.NewReader(""), &out, &errOut); err == nil {
		t.Fatal("storageCommand(reconcile-reservations bad flag) = nil, want a flag error")
	}
}

// TestRepairRepoIdentitiesCommandFlags pins the operator repair command's
// flag/URL contract: a missing database URL and stray positional arguments are
// usage errors, and an unknown flag never reaches the store.
func TestRepairRepoIdentitiesCommandFlags(t *testing.T) {
	ctx := context.Background()
	t.Setenv("KIWI_DATABASE_URL", "")
	var out bytes.Buffer
	if err := repairRepoIdentities(ctx, nil, &out); err == nil || !strings.Contains(err.Error(), "--database-url is required") {
		t.Fatalf("repairRepoIdentities without a URL = %v", err)
	}
	if err := repairRepoIdentities(ctx, []string{"--no-such-flag"}, &out); err == nil {
		t.Fatal("repairRepoIdentities(bad flag) = nil, want a flag error")
	}
	if err := repairRepoIdentities(ctx, []string{"--database-url", "postgres://example/db", "extra"}, &out); err == nil || !strings.Contains(err.Error(), "takes no arguments") {
		t.Fatalf("repairRepoIdentities(extra arg) = %v", err)
	}
}

// TestMigrateStagingLayoutCommandReclaimsWithForce: --force skips the prompt
// and reclaims the legacy top-level file; the report names the root and count.
func TestMigrateStagingLayoutCommandReclaimsWithForce(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, staging.FilePrefix+"old-layout")
	if err := os.WriteFile(legacy, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := migrateStagingLayout(context.Background(), []string{"--dir", root, "--force"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatalf("migrateStagingLayout: %v (stderr %q)", err, errOut.String())
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy file survived the forced migration: %v", err)
	}
	if !strings.Contains(out.String(), "reclaimed=1") || !strings.Contains(out.String(), root) {
		t.Fatalf("migration report = %q", out.String())
	}
}

// TestMigrateStagingLayoutCommandRequiresConfirmation: without --force the
// command removes nothing unless the operator types yes; EOF (non-interactive
// stdin) is a refusal, so a script cannot wipe the root by accident.
func TestMigrateStagingLayoutCommandRequiresConfirmation(t *testing.T) {
	newRoot := func(t *testing.T) (string, string) {
		t.Helper()
		root := t.TempDir()
		legacy := filepath.Join(root, staging.FilePrefix+"old-layout")
		if err := os.WriteFile(legacy, []byte("legacy"), 0o600); err != nil {
			t.Fatal(err)
		}
		return root, legacy
	}
	t.Setenv("KIWI_STAGING_DIR", "")
	for name, answer := range map[string]string{
		"no":   "no\n",
		"eof":  "",
		"n":    "n\n",
		"junk": "maybe\n",
	} {
		t.Run(name, func(t *testing.T) {
			root, legacy := newRoot(t)
			var out, errOut bytes.Buffer
			err := migrateStagingLayout(context.Background(), []string{"--dir", root}, strings.NewReader(answer), &out, &errOut)
			if err == nil || !strings.Contains(err.Error(), "aborted") {
				t.Fatalf("unconfirmed migration (%q) = %v, want an abort", answer, err)
			}
			if _, serr := os.Stat(legacy); serr != nil {
				t.Fatalf("unconfirmed migration removed the file: %v", serr)
			}
		})
	}
	t.Run("yes", func(t *testing.T) {
		root, legacy := newRoot(t)
		var out, errOut bytes.Buffer
		if err := migrateStagingLayout(context.Background(), []string{"--dir", root}, strings.NewReader("yes\n"), &out, &errOut); err != nil {
			t.Fatalf("confirmed migration: %v", err)
		}
		if _, serr := os.Stat(legacy); !os.IsNotExist(serr) {
			t.Fatalf("confirmed migration did not remove the file: %v", serr)
		}
	})
	// Extra positional arguments are refused.
	var out, errOut bytes.Buffer
	if err := migrateStagingLayout(context.Background(), []string{"--dir", t.TempDir(), "--force", "extra"}, strings.NewReader(""), &out, &errOut); err == nil || !strings.Contains(err.Error(), "takes no arguments") {
		t.Fatalf("migrateStagingLayout(extra arg) = %v", err)
	}
	// KIWI_STAGING_DIR is honored when --dir is omitted.
	root, legacy := newRoot(t)
	t.Setenv("KIWI_STAGING_DIR", root)
	if err := migrateStagingLayout(context.Background(), []string{"--force"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatalf("migration via KIWI_STAGING_DIR: %v", err)
	}
	if _, serr := os.Stat(legacy); !os.IsNotExist(serr) {
		t.Fatalf("migration via KIWI_STAGING_DIR did not reclaim: %v", serr)
	}
}

func TestUsageListsCommands(t *testing.T) {
	text := captureUsage(t, usage)
	for _, want := range []string{
		"kiwi run", "kiwi validate", "kiwi explain", "kiwi doctor",
		"kiwi server", "kiwi runner", "kiwi dispatch", "kiwi init",
		"kiwi import", "kiwi replay",
		"kiwi tui", "kiwi config check", "kiwi outbox dead-letters",
		"kiwi storage  reconcile-reservations",
		"kiwi storage  migrate-staging-layout",
		"kiwi repair-repo-identities",
		"kiwi version", "identical local and remote DAG execution",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("usage text missing %q", want)
		}
	}
}

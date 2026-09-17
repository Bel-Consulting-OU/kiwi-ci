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
		{"config-empty", []string{"config"}},
		{"config", []string{"config", "--no-such-flag"}},
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

func TestUsageListsCommands(t *testing.T) {
	text := captureUsage(t, usage)
	for _, want := range []string{
		"kiwi run", "kiwi validate", "kiwi explain", "kiwi doctor",
		"kiwi server", "kiwi runner", "kiwi dispatch", "kiwi init",
		"kiwi tui", "kiwi config check",
		"kiwi version", "identical local and remote DAG execution",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("usage text missing %q", want)
		}
	}
}

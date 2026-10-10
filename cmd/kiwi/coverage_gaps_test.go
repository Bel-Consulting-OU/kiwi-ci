package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

type failingStdin struct{ err error }

func (r failingStdin) Read([]byte) (int, error) { return 0, r.err }

// TestDispatchVerifyRoute covers the verify branch of the command switch.
func TestDispatchVerifyRoute(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := dispatch(context.Background(), []string{"verify", "--no-such-flag"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("dispatch(verify, bad flag) = nil, want a flag error")
	}
	if errors.Is(err, errUnknownCommand) {
		t.Fatal("verify routed to the unknown-command branch")
	}
}

// TestRepairRepoIdentitiesDatabaseFailure covers the connect failure arm: an
// unparsable/refused DSN fails before any repair plan is produced.
func TestRepairRepoIdentitiesDatabaseFailure(t *testing.T) {
	t.Setenv("KIWI_DATABASE_URL", "")
	var out bytes.Buffer
	err := repairRepoIdentities(context.Background(), []string{"--database-url", "postgres://%zz"}, &out)
	if err == nil {
		t.Fatal("repairRepoIdentities accepted an unparsable DSN")
	}
}

// TestMigrateStagingLayoutFailureArms covers the flag error, the unreadable
// confirmation stdin, and a root the migration cannot use.
func TestMigrateStagingLayoutFailureArms(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := migrateStagingLayout(context.Background(), []string{"--no-such-flag"}, strings.NewReader(""), &out, &errOut); err == nil {
		t.Fatal("bad flag accepted")
	}

	errOut.Reset()
	err := migrateStagingLayout(context.Background(), []string{"--dir", t.TempDir()}, failingStdin{err: errors.New("stdin broke")}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "read confirmation") {
		t.Fatalf("unreadable stdin = %v, want the confirmation read error", err)
	}

	rootFile := t.TempDir() + "/not-a-dir"
	if err := os.WriteFile(rootFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if err := migrateStagingLayout(context.Background(), []string{"--dir", rootFile, "--force"}, strings.NewReader(""), &out, &errOut); err == nil {
		t.Fatal("migration against a regular file succeeded")
	}
}

// TestMigrateRunnerCacheLayoutFailureArms covers the flag error, the extra
// argument refusal, the unreadable confirmation stdin (prompting with
// KIWI_CACHE_ROOT set), and a root the reclaim cannot use.
func TestMigrateRunnerCacheLayoutFailureArms(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := migrateRunnerCacheLayout(context.Background(), []string{"--no-such-flag"}, strings.NewReader(""), &out, &errOut); err == nil {
		t.Fatal("bad flag accepted")
	}
	errOut.Reset()
	err := migrateRunnerCacheLayout(context.Background(), []string{"stray"}, strings.NewReader(""), &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "takes no arguments") {
		t.Fatalf("extra args = %v", err)
	}

	t.Setenv("KIWI_CACHE_ROOT", "/configured/cache-root")
	errOut.Reset()
	err = migrateRunnerCacheLayout(context.Background(), []string{"--dir", t.TempDir()}, failingStdin{err: errors.New("stdin broke")}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "read confirmation") {
		t.Fatalf("unreadable stdin = %v", err)
	}
	if !strings.Contains(errOut.String(), "/configured/cache-root") {
		t.Fatalf("configured cache root not named: %q", errOut.String())
	}

	rootFile := t.TempDir() + "/not-a-dir"
	if err := os.WriteFile(rootFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if err := migrateRunnerCacheLayout(context.Background(), []string{"--dir", rootFile, "--force"}, strings.NewReader(""), &out, &errOut); err == nil {
		t.Fatal("reclaim against a regular file succeeded")
	}
}

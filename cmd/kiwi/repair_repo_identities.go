package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// repairRepoIdentitiesCommand is the dispatch entry for the operator repair
// command (see repair_repo_identities usage in usage()):
//
//	kiwi repair-repo-identities [--database-url URL] [--apply] [--cancel-active]
//
// It talks DIRECTLY to the PostgreSQL control-plane store, like the other
// operator repair commands: an identity that can no longer be proven must be
// surfaced and quarantined, not guessed, and that decision needs the whole
// run/job population rather than the admin HTTP API.
func repairRepoIdentitiesCommand(ctx context.Context, args []string) error {
	return repairRepoIdentities(ctx, args, os.Stdout)
}

// repairRepoIdentities is the testable core with the report writer injected.
func repairRepoIdentities(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("repair-repo-identities", flag.ContinueOnError)
	url := fs.String("database-url", os.Getenv("KIWI_DATABASE_URL"), "PostgreSQL connection URL")
	apply := fs.Bool("apply", false, "rewrite provable identities and quarantine unprovable rows (default: list only)")
	cancelActive := fs.Bool("cancel-active", false, "cancel a non-terminal run/job whose identity would change (through the canonical cancellation transaction) BEFORE rewriting it; without this flag such rows are reported as active_requires_drain and left untouched")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*url) == "" {
		return fmt.Errorf("--database-url is required (or set KIWI_DATABASE_URL)")
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("repair-repo-identities takes no arguments")
	}
	st, err := storage.NewPostgres(ctx, *url)
	if err != nil {
		return err
	}
	defer st.Close()

	mode := storage.RepoIdentityRepairReport
	if *apply {
		mode = storage.RepoIdentityRepairApply
	}
	res, err := st.RepairRepoIdentitiesWithOptions(ctx, mode, storage.RepoIdentityRepairOptions{CancelActive: *cancelActive})
	if err != nil {
		return err
	}
	writeRepoIdentityRepairReport(out, res)
	// Fail closed: a report-only run that found unprovable rows OR active rows
	// that would change identity exits non-zero so an operator/CI notices and
	// re-runs with --apply (and --cancel-active for the active rows).
	if mode == storage.RepoIdentityRepairReport {
		if res.Quarantined > 0 {
			return fmt.Errorf("%d repository identities cannot be proven and need quarantine: re-run with --apply", res.Quarantined)
		}
		if res.ActiveRequiresDrain > 0 {
			return fmt.Errorf("%d non-terminal runs/jobs would change identity and require --cancel-active to drain first", res.ActiveRequiresDrain)
		}
	}
	return nil
}

// writeRepoIdentityRepairReport renders the one-line-per-row plan plus the
// summary an operator reads.
func writeRepoIdentityRepairReport(out io.Writer, res storage.RepoIdentityRepairResult) {
	for _, e := range res.Entries {
		fmt.Fprintf(out, "%s %s %s: %q -> %q (%s)\n",
			strings.ToUpper(e.Action.String()), e.Kind, e.ID, e.Stored, e.Repaired, e.Reason)
	}
	verb := "planned"
	if res.Mode == storage.RepoIdentityRepairApply {
		verb = "applied"
	}
	fmt.Fprintf(out, "repository identities %s: scanned=%d rewritten=%d quarantined=%d unchanged=%d active_requires_drain=%d drained=%d\n",
		verb, res.Scanned, res.Rewritten, res.Quarantined, res.Unchanged, res.ActiveRequiresDrain, res.Drained)
}

package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Storage dispatches the operator storage-repair commands:
//
//	kiwi storage reconcile-reservations [--database-url URL]
//
// Like the outbox dead-letter commands these talk DIRECTLY to the
// PostgreSQL control-plane store instead of the admin HTTP API: the repair is
// a leader-fenced store transaction, and an operator needs it exactly when
// the running fleet cannot serve leases (a rolling upgrade that left the
// durable resource-reservation ledger stale or leaked).
func Storage(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("storage requires a subcommand: reconcile-reservations")
	}
	switch args[0] {
	case "reconcile-reservations":
		return StorageReconcileReservations(ctx, args[1:])
	default:
		return fmt.Errorf("unknown storage subcommand %q (want reconcile-reservations)", args[0])
	}
}

// StorageReconcileReservations implements the repair command: it rebuilds the
// durable runner resource-reservation ledger from the authoritative persisted
// lease state (running jobs + lease identity + payload requests) and sweeps
// every row that no longer describes a live lease.
//
// When to run it: after a rolling upgrade in which an OLD server binary
// created running jobs after migration 0030 (or served their
// completions/cancellations), the ledger can be missing rows (under-reserve:
// a new leader would admit work the runner cannot hold) or hold rows with no
// live lease (capacity shrink). A new leader rebuilds the ledger BEFORE its
// first lease automatically; this command is the operator's repair path for a
// ledger that is still mis-stated — for example when the promotion hook could
// not complete, or after old replicas have since drained. It is idempotent
// and safe to run at any time, including while the fleet serves traffic: the
// store serializes reconciliation with a transaction-scoped advisory lock and
// never downgrades a freshly claimed generation.
//
// Leadership: the store operation is fenced against the durable leadership
// epoch, and a CLI process holds no advisory-lock claim. The command
// therefore presents the CURRENT durable epoch (ReadLeaderEpoch) for the
// duration of the repair — an explicit operator override, serialized against
// leadership hand-over by the epoch's FOR SHARE row lock, so a concurrent
// promotion simply makes the pass fail with a stale-epoch error and the
// operator re-runs it. Nothing else is mutated: the pass only rewrites
// ledger rows to match the running jobs' persisted leases.
func StorageReconcileReservations(ctx context.Context, args []string) error {
	return storageReconcileReservations(ctx, args, os.Stdout)
}

// storageReconcileReservations is StorageReconcileReservations with the report
// writer injected, so tests can assert the operator-facing result line.
func storageReconcileReservations(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("storage reconcile-reservations", flag.ContinueOnError)
	url := fs.String("database-url", os.Getenv("KIWI_DATABASE_URL"), "PostgreSQL connection URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*url) == "" {
		return fmt.Errorf("--database-url is required (or set KIWI_DATABASE_URL)")
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("storage reconcile-reservations takes no arguments")
	}
	st, err := storage.NewPostgres(ctx, *url)
	if err != nil {
		return err
	}
	defer st.Close()

	epoch, err := st.ReadLeaderEpoch(ctx)
	if err != nil {
		return fmt.Errorf("read leadership epoch: %w", err)
	}
	st.SetLeaderEpoch(epoch)
	res, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "resource reservations reconciled: running=%d upserted=%d deleted=%d\n", res.Running, res.Upserted, res.Deleted)
	return nil
}

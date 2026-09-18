package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Outbox dispatches the operator dead-letter commands:
//
//	kiwi outbox dead-letters list [--database-url URL]
//	kiwi outbox dead-letters requeue ID [--database-url URL]
//	kiwi outbox dead-letters delete ID [--database-url URL]
//
// Unlike the HTTP ops commands these talk DIRECTLY to the PostgreSQL
// control-plane store: dead letters are durable operator state with no admin
// HTTP endpoint, and requeue/delete are scoped to retired rows only, so the
// CLI can never disturb a live intent.
func Outbox(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("outbox requires a subcommand: dead-letters")
	}
	switch args[0] {
	case "dead-letters":
		return OutboxDeadLetters(ctx, args[1:])
	default:
		return fmt.Errorf("unknown outbox subcommand %q (want dead-letters)", args[0])
	}
}

// OutboxDeadLetters implements the list/requeue/delete subcommands.
func OutboxDeadLetters(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("outbox dead-letters requires a subcommand: list, requeue or delete")
	}
	switch args[0] {
	case "list":
		url, rest, err := outboxDeadLetterFlags("outbox dead-letters list", args[1:])
		if err != nil {
			return err
		}
		if len(rest) != 0 {
			return fmt.Errorf("outbox dead-letters list takes no arguments")
		}
		st, err := openOutboxDeadLetterStore(ctx, url)
		if err != nil {
			return err
		}
		defer st.Close()
		dead, err := st.OutboxDeadLetters(ctx)
		if err != nil {
			return err
		}
		if len(dead) == 0 {
			fmt.Println("no dead letters")
			return nil
		}
		fmt.Printf("%-40s %-22s %-8s %-24s %s\n", "ID", "KIND", "ATTEMPTS", "DEAD-LETTERED AT", "LAST ERROR")
		for _, d := range dead {
			fmt.Printf("%-40s %-22s %-8d %-24s %s\n",
				truncate(d.ID, 40), truncate(d.Kind, 22), d.Attempts,
				d.DeadLetteredAt.UTC().Format(time.RFC3339), truncate(d.LastError, 72))
		}
		return nil
	case "requeue":
		return outboxDeadLetterMutation(ctx, "requeue", args[1:])
	case "delete":
		return outboxDeadLetterMutation(ctx, "delete", args[1:])
	default:
		return fmt.Errorf("unknown outbox dead-letters subcommand %q (want list, requeue or delete)", args[0])
	}
}

// outboxDeadLetterFlags parses the shared --database-url flag.
func outboxDeadLetterFlags(name string, args []string) (url string, rest []string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	u := fs.String("database-url", os.Getenv("KIWI_DATABASE_URL"), "PostgreSQL connection URL")
	if err := fs.Parse(args); err != nil {
		return "", nil, err
	}
	return *u, fs.Args(), nil
}

// outboxDeadLetterMutation implements requeue/delete ID. The ID may appear
// before or after the flags, so it is extracted first and the remaining
// arguments are parsed as flags (Go's flag package stops at the first
// positional argument).
func outboxDeadLetterMutation(ctx context.Context, sub string, args []string) error {
	id := ""
	flagArgs := make([]string, 0, len(args))
	for _, a := range args {
		if id == "" && !strings.HasPrefix(a, "-") {
			id = a
			continue
		}
		flagArgs = append(flagArgs, a)
	}
	url, rest, err := outboxDeadLetterFlags("outbox dead-letters "+sub, flagArgs)
	if err != nil {
		return err
	}
	if id == "" || len(rest) != 0 {
		return fmt.Errorf("outbox dead-letters %s requires a dead-letter ID", sub)
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("outbox dead-letters %s requires a dead-letter ID", sub)
	}
	st, err := openOutboxDeadLetterStore(ctx, url)
	if err != nil {
		return err
	}
	defer st.Close()
	switch sub {
	case "requeue":
		if err := st.OutboxRequeue(ctx, id); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return fmt.Errorf("dead letter %s not found", id)
			}
			return err
		}
		fmt.Printf("requeued dead letter %s\n", id)
	case "delete":
		if err := st.OutboxDelete(ctx, id); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return fmt.Errorf("dead letter %s not found", id)
			}
			return err
		}
		fmt.Printf("deleted dead letter %s\n", id)
	default:
		return fmt.Errorf("unknown dead-letter mutation %q", sub)
	}
	return nil
}

// openOutboxDeadLetterStore opens the PostgreSQL store that owns the
// operator dead-letter state.
func openOutboxDeadLetterStore(ctx context.Context, url string) (*storage.PostgresStore, error) {
	if strings.TrimSpace(url) == "" {
		return nil, fmt.Errorf("--database-url is required (or set KIWI_DATABASE_URL)")
	}
	st, err := storage.NewPostgres(ctx, url)
	if err != nil {
		return nil, err
	}
	return st, nil
}

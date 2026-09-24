package app

import (
	"context"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestOutboxDeadLettersUsageErrors pins the command-layer contract for the
// operator dead-letter group: unknown/missing subcommands are errors, help
// exits through flag.ErrHelp, and a missing DSN fails before any connection.
func TestOutboxDeadLettersUsageErrors(t *testing.T) {
	t.Setenv("KIWI_DATABASE_URL", "")
	ctx := context.Background()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no-subcommand", nil, "outbox requires a subcommand"},
		{"unknown-subcommand", []string{"bogus"}, "unknown outbox subcommand"},
		{"dead-letters-no-sub", []string{"dead-letters"}, "requires a subcommand"},
		{"dead-letters-unknown", []string{"dead-letters", "bogus"}, "unknown outbox dead-letters subcommand"},
		{"list-extra-args", []string{"dead-letters", "list", "surplus"}, "takes no arguments"},
		{"requeue-no-id", []string{"dead-letters", "requeue"}, "requires a dead-letter ID"},
		{"requeue-empty-id", []string{"dead-letters", "requeue", "  "}, "requires a dead-letter ID"},
		{"delete-no-id", []string{"dead-letters", "delete"}, "requires a dead-letter ID"},
		// F6-F: a flag's value must never be mistaken for the ID. With the
		// flag first, the trailing ID is a stray positional, so the command
		// is rejected before any connection is attempted.
		{"requeue-dsn-first-rejected", []string{"dead-letters", "requeue", "--database-url", "postgres://example/db", "abc"}, "requires a dead-letter ID"},
		{"delete-dsn-first-rejected", []string{"dead-letters", "delete", "--database-url", "postgres://example/db", "abc"}, "requires a dead-letter ID"},
		// ID-first with an explicit empty DSN: the ID parses, and the DSN
		// requirement is what fails.
		{"requeue-id-then-empty-dsn", []string{"dead-letters", "requeue", "abc", "--database-url", ""}, "--database-url is required"},
		{"list-no-dsn", []string{"dead-letters", "list"}, "--database-url is required"},
		{"requeue-no-dsn", []string{"dead-letters", "requeue", "abc"}, "--database-url is required"},
		{"delete-no-dsn", []string{"dead-letters", "delete", "abc"}, "--database-url is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Outbox(ctx, tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Outbox(%v) = %v, want %q", tc.args, err, tc.want)
			}
		})
	}
	// -h is a flag-help request, not a subcommand error.
	if err := Outbox(ctx, []string{"dead-letters", "list", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("list -h = %v, want flag.ErrHelp", err)
	}
	if err := Outbox(ctx, []string{"dead-letters", "requeue", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("requeue -h = %v, want flag.ErrHelp", err)
	}
}

// TestOutboxDeadLettersPostgresRoundTrip drives the CLI command layer against
// a real PostgreSQL store: a retired intent appears in the listing, requeue
// re-arms it for claiming, and delete removes it. Gated on
// KIWI_TEST_POSTGRES_URL.
func TestOutboxDeadLettersPostgresRoundTrip(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL CLI round trip")
	}
	ctx := context.Background()
	st, err := storage.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Seed one retired intent (unique ID so repeated runs never collide).
	id := "app-outbox-it-" + time.Now().UTC().Format("20060102150405.000000000")
	if err := st.OutboxAppend(ctx, storage.OutboxItem{ID: id, Kind: "cli_it", Payload: []byte(`{}`)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.OutboxRetry(ctx, id, errors.New("seeded failure"), 1); err != nil {
		t.Fatalf("retire: %v", err)
	}
	t.Cleanup(func() { _ = st.OutboxDelete(context.Background(), id) })

	// list must find the retired row.
	dead, err := st.OutboxDeadLetters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range dead {
		if d.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("seeded dead letter %s not listed", id)
	}
	// list through the command layer succeeds (output goes to stdout).
	if err := Outbox(ctx, []string{"dead-letters", "list", "--database-url", dsn}); err != nil {
		t.Fatalf("list command: %v", err)
	}
	// requeue through the command layer re-arms the row (assertions are
	// scoped to the seeded ID: the shared test schema may hold unrelated
	// dead letters from other runs).
	if err := Outbox(ctx, []string{"dead-letters", "requeue", id, "--database-url", dsn}); err != nil {
		t.Fatalf("requeue command: %v", err)
	}
	dead, err = st.OutboxDeadLetters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dead {
		if d.ID == id {
			t.Fatalf("seeded dead letter still listed after requeue: %+v", d)
		}
	}
	if err := st.OutboxDelete(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("delete of a live row = %v, want ErrNotFound", err)
	}
	// A live row cannot be deleted through the command layer either.
	if err := Outbox(ctx, []string{"dead-letters", "delete", id, "--database-url", dsn}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("delete of live row = %v, want not found", err)
	}
	// Retire again and delete through the command layer.
	if err := st.OutboxRetry(ctx, id, errors.New("seeded failure 2"), 1); err != nil {
		t.Fatal(err)
	}
	if err := Outbox(ctx, []string{"dead-letters", "delete", id, "--database-url", dsn}); err != nil {
		t.Fatalf("delete command: %v", err)
	}
	if err := st.OutboxDelete(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("row still present after CLI delete: %v", err)
	}
}

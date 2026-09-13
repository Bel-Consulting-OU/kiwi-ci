package app

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kiwici/kiwi/internal/storage"
)

// DatabaseMigrate applies pending schema migrations to the PostgreSQL
// control-plane store.
func DatabaseMigrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("database migrate", flag.ContinueOnError)
	url := fs.String("database-url", os.Getenv("KIWI_DATABASE_URL"), "PostgreSQL connection URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("--database-url is required")
	}
	db, err := storage.NewPostgres(ctx, *url)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	version, err := db.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("database migrated to schema version %d\n", version)
	return nil
}

// DatabaseStatus reports the current schema version of the PostgreSQL
// control-plane store.
func DatabaseStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("database status", flag.ContinueOnError)
	url := fs.String("database-url", os.Getenv("KIWI_DATABASE_URL"), "PostgreSQL connection URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("--database-url is required")
	}
	db, err := storage.NewPostgres(ctx, *url)
	if err != nil {
		return err
	}
	defer db.Close()
	version, err := db.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("schema version %d\n", version)
	return nil
}

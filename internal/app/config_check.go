package app

import (
	"context"
	"flag"
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
)

// ConfigCheck implements `kiwi config check`: it loads and validates a
// configuration file (including the environment overlay and the schema
// invariants) without starting the server.
func ConfigCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	path := fs.String("config", "kiwi.toml", "configuration file to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.ApplyEnv(); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	fmt.Printf("config %s is valid (mode=%s, listen=%s)\n", *path, cfg.Server.Mode, cfg.Server.Listen)
	return nil
}

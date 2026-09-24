package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/tui"
)

// TUI drives the interactive log viewer:
//
//	kiwi tui RUN [--job KEY] [--follow] [--search TEXT]
//
// When stdout is not a terminal the TUI degrades to a plain filtered tail.
func TUI(ctx context.Context, args []string) error {
	return tuiWithIO(ctx, args, os.Stdout, os.Stdin)
}

func tuiWithIO(ctx context.Context, args []string, out io.Writer, in io.Reader) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	token := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin bearer token")
	job := fs.String("job", "", "only render entries for this job key")
	follow := fs.Bool("follow", false, "follow the live log stream")
	search := fs.String("search", "", "filter rendered lines to matches")
	rest, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("kiwi tui requires a run ID")
	}
	return tui.Run(ctx, tui.Config{
		Server: *serverURL,
		Token:  *token,
		RunID:  rest[0],
		JobKey: *job,
		Follow: *follow,
		Search: *search,
	}, out, in)
}

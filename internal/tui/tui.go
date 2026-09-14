package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Config configures one TUI session.
type Config struct {
	Server string
	Token  string
	RunID  string
	JobKey string
	Follow bool
	Search string
}

// Run drives the interactive log viewer. When out is not a terminal it
// degrades to a plain filtered tail.
func Run(ctx context.Context, cfg Config, out io.Writer, in io.Reader) error {
	lines := NewRing[string](10_000)
	client := &Client{Server: cfg.Server, Token: cfg.Token}
	after := int64(0)
	for {
		page, err := client.ReadPage(ctx, cfg.RunID, after, 1000)
		if err != nil {
			return fmt.Errorf("tui: read logs: %w", err)
		}
		for _, e := range page {
			if cfg.JobKey != "" && e.JobKey != cfg.JobKey {
				continue
			}
			lines.Append(formatEntry(entryFromModel(e)))
			after = e.Seq
		}
		if len(page) < 1000 {
			break
		}
	}

	if !cfg.Follow {
		return renderPlain(lines.Slice(), cfg.Search, out)
	}

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Follow(streamCtx, cfg.RunID, after, func(e model.LogEntry) {
			if cfg.JobKey == "" || e.JobKey == cfg.JobKey {
				lines.Append(formatEntry(entryFromModel(e)))
			}
		})
	}()

	if !isTerminal(os.Stdout.Fd()) {
		return renderPlain(lines.Slice(), cfg.Search, out)
	}

	term, err := rawMode(int(os.Stdin.Fd()))
	if err != nil {
		term, err = rawMode(0)
	}
	if err != nil {
		return renderPlain(lines.Slice(), cfg.Search, out)
	}
	defer term.Restore()
	return runInteractive(ctx, lines, cfg, out, in, errCh)
}

// logEntry is the minimal internal log record the TUI renders.
type logEntry struct {
	Seq    int64  `json:"seq"`
	RunID  string `json:"run_id"`
	JobID  string `json:"job_id"`
	JobKey string `json:"job_key"`
	Step   string `json:"step"`
	Line   string `json:"line"`
}

func entryFromModel(e model.LogEntry) logEntry {
	return logEntry{Seq: e.Seq, RunID: e.RunID, JobID: e.JobID, JobKey: e.JobKey, Step: e.Step, Line: e.Line}
}

func formatEntry(e logEntry) string {
	return fmt.Sprintf("%s > %s | %s", e.JobKey, e.Step, e.Line)
}

func renderPlain(lines []string, search string, out io.Writer) error {
	for _, l := range lines {
		if search != "" && !strings.Contains(l, search) {
			continue
		}
		if _, err := fmt.Fprintln(out, l); err != nil {
			return err
		}
	}
	return nil
}

func runInteractive(ctx context.Context, lines *Ring[string], cfg Config, out io.Writer, in io.Reader, errCh <-chan error) error {
	cursor := 0
	pattern := cfg.Search
	matches := []int{}
	stepCollapsed := map[string]bool{}
	keys := make(chan string, 16)
	go readKeys(ctx, in, keys)

	frame := func() {
		slice := lines.Slice()
		matches = findMatches(slice, pattern)
		fmt.Fprint(out, "\x1b[2J\x1b[H")
		fmt.Fprintf(out, "run %s | job %s | %d lines | /search: %q | q quit\n", cfg.RunID, cfg.JobKey, len(slice), pattern)
		for _, l := range renderFrame(slice, cursor, stepCollapsed, matches, 30, 132) {
			fmt.Fprintln(out, l)
		}
	}
	frame()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err != nil {
				return err
			}
			return nil
		case <-ticker.C:
			frame()
		case k := <-keys:
			slice := lines.Slice()
			switch k {
			case "q":
				return nil
			case "up":
				if cursor > 0 {
					cursor--
				}
			case "down":
				if cursor < len(slice)-1 {
					cursor++
				}
			case "pgup":
				cursor -= 30
				if cursor < 0 {
					cursor = 0
				}
			case "pgdn":
				cursor += 30
				if cursor >= len(slice) {
					cursor = len(slice) - 1
				}
			case "home":
				cursor = 0
			case "end":
				cursor = len(slice) - 1
			case "tab":
				if group := stepName(slice[cursor]); group != "" {
					stepCollapsed[group] = !stepCollapsed[group]
				}
			case "j":
				// cycle job filter: the full job list is fetched lazily; the
				// interactive session refines the filter from the stream.
				// (jobs endpoint integration lives in the CLI wiring phase.)
			case "f":
				for i, l := range slice {
					if strings.Contains(strings.ToLower(l), "fail") || strings.Contains(l, "error:") {
						cursor = i
						break
					}
				}
			case "y":
				link := cfg.Server + "/?run=" + cfg.RunID
				if copyPermalink(link) {
					fmt.Fprintf(out, "\npermalink copied: %s\n", link)
				} else {
					fmt.Fprintf(out, "\npermalink: %s\n", link)
				}
			case "n":
				for _, m := range matches {
					if m > cursor {
						cursor = m
						break
					}
				}
			case "N":
				for i := len(matches) - 1; i >= 0; i-- {
					if matches[i] < cursor {
						cursor = matches[i]
						break
					}
				}
			}
			if strings.HasPrefix(k, "/") {
				pattern = strings.TrimPrefix(k, "/")
			}
			frame()
		}
	}
}

// readKeys reads single keystrokes (with escape sequences for arrows) and
// sends normalized key names over ch until ctx ends.
func readKeys(ctx context.Context, in io.Reader, ch chan<- string) {
	buf := make([]byte, 8)
	pending := []byte{}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := in.Read(buf)
		if err != nil {
			return
		}
		pending = append(pending, buf[:n]...)
		for len(pending) > 0 {
			switch {
			case len(pending) >= 3 && pending[0] == 0x1b && pending[1] == '[':
				switch pending[2] {
				case 'A':
					ch <- "up"
				case 'B':
					ch <- "down"
				case '5', '6':
					if len(pending) >= 4 && pending[3] == '~' {
						if pending[2] == '5' {
							ch <- "pgup"
						} else {
							ch <- "pgdn"
						}
						pending = pending[4:]
						continue
					}
				case 'H':
					ch <- "home"
				case 'F':
					ch <- "end"
				}
				pending = pending[3:]
				continue
			case len(pending) >= 2 && pending[0] == 0x1b:
				pending = pending[1:]
				continue
			default:
				c := pending[0]
				pending = pending[1:]
				switch c {
				case 'q', 'Q':
					ch <- "q"
				case '\t':
					ch <- "tab"
				case 'j', 'J':
					ch <- "j"
				case 'f', 'F':
					ch <- "f"
				case 'y', 'Y':
					ch <- "y"
				case 'n':
					ch <- "n"
				case 'N':
					ch <- "N"
				case '/':
					line := []byte{'/'}
					for len(pending) > 0 && pending[0] != '\n' && pending[0] != '\r' {
						line = append(line, pending[0])
						pending = pending[1:]
					}
					if len(pending) > 0 {
						pending = pending[1:]
					}
					ch <- string(line)
				case '\n', '\r':
					// ignore
				}
			}
		}
	}
}

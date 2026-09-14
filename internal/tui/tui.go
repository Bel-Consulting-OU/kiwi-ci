package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
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
	filter := newJobFilter(client, cfg.RunID, cfg.JobKey)
	state := &logState{}
	after := int64(0)
	for {
		page, err := client.ReadPage(ctx, cfg.RunID, after, 1000)
		if err != nil {
			return fmt.Errorf("tui: read logs: %w", err)
		}
		for _, e := range page {
			state.set(e.Seq)
			if !filter.matches(e.JobKey) {
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
			if e.Seq <= state.get() {
				return
			}
			state.set(e.Seq)
			if filter.matches(e.JobKey) {
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
	return runInteractive(ctx, lines, &cfg, out, in, errCh, filter, state)
}

// logState tracks the highest log sequence consumed across the initial
// read, job-filter refetches and the follow stream so entries are never
// rendered twice when a refetch re-reads the backlog.
type logState struct {
	mu    sync.Mutex
	after int64
}

func (s *logState) get() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.after
}

func (s *logState) set(v int64) {
	s.mu.Lock()
	if v > s.after {
		s.after = v
	}
	s.mu.Unlock()
}

// jobFilter is the interactive job-key filter: the full job list is fetched
// from GET /api/v1/runs/{id}/jobs once (lazily, on the first "j" press) and
// each "j" press cycles the active key. An empty key means "all jobs".
type jobFilter struct {
	mu     sync.Mutex
	client *Client
	runID  string
	key    string
	jobs   []string
	loaded bool
}

func newJobFilter(client *Client, runID, key string) *jobFilter {
	return &jobFilter{client: client, runID: runID, key: key}
}

func (f *jobFilter) matches(jobKey string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.key == "" || jobKey == f.key
}

// cycle fetches the job list once, cycles the active filter key and
// returns the new key. A fetch failure leaves the filter unchanged.
func (f *jobFilter) cycle(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.loaded {
		jobs, err := f.client.ListJobs(ctx, f.runID)
		if err != nil {
			return f.key, err
		}
		f.jobs = jobs
		f.loaded = true
	}
	if len(f.jobs) == 0 {
		return f.key, nil
	}
	f.key = cycleJobFilter(f.jobs, f.key)
	return f.key, nil
}

// cycleJobFilter returns the next job filter after current. The cycle is
// "" (all jobs) -> first job -> ... -> last job -> "" (all jobs). A current
// key that is not in the list moves to the first job.
func cycleJobFilter(jobs []string, current string) string {
	if len(jobs) == 0 {
		return current
	}
	if current == "" {
		return jobs[0]
	}
	for i, j := range jobs {
		if j == current {
			if i+1 < len(jobs) {
				return jobs[i+1]
			}
			return ""
		}
	}
	return jobs[0]
}

// refetchLogs re-reads the full backlog under the given job filter and
// replaces the ring contents, advancing the shared sequence cursor so the
// follow stream does not re-deliver entries already consumed here.
func refetchLogs(ctx context.Context, client *Client, runID, jobKey string, lines *Ring[string], state *logState) error {
	after := int64(0)
	var collected []string
	for {
		page, err := client.ReadPage(ctx, runID, after, 1000)
		if err != nil {
			return err
		}
		for _, e := range page {
			state.set(e.Seq)
			if jobKey != "" && e.JobKey != jobKey {
				continue
			}
			collected = append(collected, formatEntry(entryFromModel(e)))
		}
		if len(page) < 1000 {
			break
		}
		for _, e := range page {
			after = e.Seq
		}
	}
	lines.Reset()
	for _, l := range collected {
		lines.Append(l)
	}
	return nil
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

func runInteractive(ctx context.Context, lines *Ring[string], cfg *Config, out io.Writer, in io.Reader, errCh <-chan error, filter *jobFilter, state *logState) error {
	cursor := 0
	pattern := cfg.Search
	matches := []int{}
	stepCollapsed := map[string]bool{}
	keys := make(chan string, 16)
	go readKeys(ctx, in, keys)

	frame := func() {
		slice := lines.Slice()
		matches = findMatches(slice, pattern)
		jobLabel := cfg.JobKey
		if jobLabel == "" {
			jobLabel = "all"
		}
		fmt.Fprint(out, "\x1b[2J\x1b[H")
		fmt.Fprintf(out, "run %s | job %s | %d lines | j cycle job | /search: %q | q quit\n", cfg.RunID, jobLabel, len(slice), pattern)
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
				if len(slice) > 0 && cursor < len(slice) {
					if group := stepName(slice[cursor]); group != "" {
						stepCollapsed[group] = !stepCollapsed[group]
					}
				}
			case "j":
				// Cycle the active job-key filter: the job list is fetched
				// once from GET /api/v1/runs/{id}/jobs, the filter advances
				// to the next job key (wrapping back to "all"), the log
				// backlog is refetched under the new filter, and the header
				// reflects the new active job.
				key, err := filter.cycle(ctx)
				if err != nil {
					fmt.Fprintf(out, "\njob list fetch failed: %v\n", err)
					break
				}
				cfg.JobKey = key
				if err := refetchLogs(ctx, filter.client, cfg.RunID, key, lines, state); err != nil {
					fmt.Fprintf(out, "\nlog refetch failed: %v\n", err)
				}
				cursor = 0
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

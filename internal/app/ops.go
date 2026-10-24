package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Ops dispatches the operator CLI commands that talk to a Kiwi server over
// HTTP: runs, jobs, logs, cancel, approve, rerun, artifacts, schedules and
// the local policy check. All server commands take --server/--token.
func Ops(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "runs":
		return opsRuns(ctx, args)
	case "jobs":
		return opsJobs(ctx, args)
	case "logs":
		return opsLogs(ctx, args)
	case "cancel":
		return opsMutateRun(ctx, "cancel", args)
	case "rerun":
		return opsMutateRun(ctx, "rerun", args)
	case "approve":
		return opsApprove(ctx, args)
	case "artifacts":
		return opsArtifacts(ctx, args)
	case "schedules":
		return opsSchedules(ctx, args)
	case "flake":
		return opsFlake(ctx, args)
	case "policy":
		return opsPolicy(ctx, args)
	default:
		return fmt.Errorf("unknown ops subcommand %q", sub)
	}
}

// opsClient is the HTTP client used by every server command. It never
// follows redirects so the bearer token cannot leak to another origin.
type opsClient struct {
	base   string
	token  string
	client *http.Client
}

func newOpsClient(serverURL, token string) *opsClient {
	// JSON ops calls stay short-timeout. Log follow uses a separate client
	// without a total response-body deadline (see streamClient).
	return &opsClient{
		base:   strings.TrimRight(serverURL, "/"),
		token:  token,
		client: server.NoRedirectClient(&http.Client{Timeout: 30 * time.Second}),
	}
}

// streamClient is the SSE client for log follow: connect/TLS may still be
// bounded by Transport, but there is no total http.Client.Timeout that
// would kill a healthy long stream at 30s.
func (c *opsClient) streamClient() *http.Client {
	return server.NoRedirectClient(&http.Client{})
}

// do performs one JSON request against the server.
func (c *opsClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response from %s %s: %w", method, path, err)
		}
	}
	return nil
}

// doIdempotent is do plus the retry contract every run-CREATING command
// needs: ONE Idempotency-Key per invocation, reused unchanged by every
// bounded retry, so a commit whose response was lost replays to the original
// run. Transport failures and 429/5xx responses are retried; a 409
// (IDEMPOTENCY_KEY_REUSED) is final because retrying cannot change it.
func (c *opsClient) doIdempotent(ctx context.Context, method, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	opKey, err := newLocalRunID()
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(b))
		if err != nil {
			return err
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", opKey)
		resp, err := c.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusConflict {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(body)))
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(body)))
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(body)))
		}
		if out != nil {
			err := json.NewDecoder(resp.Body).Decode(out)
			_ = resp.Body.Close()
			if err != nil {
				return fmt.Errorf("decode response from %s %s: %w", method, path, err)
			}
		} else {
			_ = resp.Body.Close()
		}
		return nil
	}
	return fmt.Errorf("%s %s: %w", method, path, lastErr)
}

func opsFlags(name string, args []string) (serverURL, token string, rest []string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	srv := fs.String("server", "", "Kiwi server URL (defaults to the active context / KIWI_SERVER)")
	tok := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin bearer token")
	rest, err = parseFlagsAndPositionals(fs, args)
	if err != nil {
		return "", "", nil, err
	}
	ep, epErr := ResolveEndpoint(*srv, *tok)
	if epErr != nil {
		return "", "", nil, epErr
	}
	return ep.Server, ep.Token, rest, nil
}

// parseFlagsAndPositionals parses fs over args in any order: Go's flag
// package stops at the first positional argument, so the documented
// `COMMAND RUN [--flags]` form (flags after the run ID) would otherwise drop
// every flag. Positionals and flags are separated first — a value-taking flag
// consumes the following argument unless it is written as --flag=value, and a
// bare "--" ends flag parsing — then only the flag tokens are handed to
// fs.Parse. The positionals are returned in order. Unknown flags still fail
// in fs.Parse.
func parseFlagsAndPositionals(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		if strings.Contains(a, "=") {
			continue
		}
		if flagTakesValue(fs, strings.TrimLeft(a, "-")) && i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	// fs.Parse cannot see positionals when flagArgs is non-empty; when it is
	// empty it returns none either, so the collected list is authoritative.
	return positional, nil
}

// flagTakesValue reports whether the named flag requires a following value.
// Boolean flags (such as --follow) never consume the next argument.
func flagTakesValue(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
		return false
	}
	return true
}

func opsRuns(ctx context.Context, args []string) error {
	// --test filters the listing to runs whose test reports contain a
	// failing/known test name (evidence query, not a log grep).
	fs := flag.NewFlagSet("runs", flag.ContinueOnError)
	srv := fs.String("server", "", "Kiwi server URL (defaults to the active context / KIWI_SERVER)")
	tok := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin bearer token")
	testName := fs.String("test", "", "only runs whose test records include this test name")
	rest, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("kiwi runs takes no arguments")
	}
	ep, epErr := ResolveEndpoint(*srv, *tok)
	if epErr != nil {
		return epErr
	}
	serverURL, token := ep.Server, ep.Token
	var out []model.Run
	c := newOpsClient(serverURL, token)
	cursor := ""
	seenCursor := map[string]bool{}
	// Follow X-Kiwi-Next-Cursor so the listing is not silently capped at
	// one page. The walk is bounded and fail-closed: a stuck cursor or a
	// runaway server must not produce a truncated list that looks complete.
	const maxRunPages = 64
	for page := 0; page < maxRunPages; page++ {
		var batch []model.Run
		path := "/api/v1/runs"
		if cursor != "" {
			path = "/api/v1/runs?cursor=" + url.QueryEscape(cursor)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
		if err != nil {
			return err
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
		}
		if err := json.Unmarshal(body, &batch); err != nil {
			return err
		}
		out = append(out, batch...)
		next := resp.Header.Get("X-Kiwi-Next-Cursor")
		if next == "" || len(batch) == 0 {
			break
		}
		if seenCursor[next] {
			return fmt.Errorf("kiwi runs: server pagination returned a repeated cursor %q; refusing to claim a complete listing", next)
		}
		seenCursor[next] = true
		cursor = next
		if page == maxRunPages-1 && cursor != "" {
			return fmt.Errorf("kiwi runs: server pagination did not terminate after %d pages (%d runs so far); refusing to claim a complete listing", maxRunPages, len(out))
		}
	}
	if *testName != "" {
		out = filterRunsByTest(ctx, c, out, *testName)
	}
	if len(out) == 0 {
		fmt.Println("no runs")
		return nil
	}
	// Full IDs: a truncated 10-char prefix cannot be passed back to
	// cancel/jobs/schedules trigger (32-hex ids collide on display).
	fmt.Printf("%-32s %-16s %-12s %-28s %-8s %s\n", "ID", "STATUS", "EVENT", "REPO", "TRUSTED", "AGE")
	for _, r := range out {
		fmt.Printf("%-32s %-16s %-12s %-28s %-8t %s\n", r.ID, r.Status, r.Event, truncate(r.Repo, 28), r.Trusted, time.Since(r.CreatedAt).Round(time.Second))
	}
	return nil
}

// filterRunsByTest keeps runs whose JUnit-derived test records include
// testName (case-sensitive class-qualified name). Evidence, not log text.
func filterRunsByTest(ctx context.Context, c *opsClient, runs []model.Run, testName string) []model.Run {
	var out []model.Run
	for _, r := range runs {
		var reports []model.TestReport
		if err := c.do(ctx, http.MethodGet, "/api/v1/runs/"+r.ID+"/tests", nil, &reports); err != nil {
			continue
		}
		for _, rep := range reports {
			for _, tc := range rep.Cases {
				name := tc.Name
				if tc.Class != "" {
					name = tc.Class + "." + tc.Name
				}
				if name == testName || tc.Name == testName {
					out = append(out, r)
					break
				}
			}
		}
	}
	return out
}

func opsJobs(ctx context.Context, args []string) error {
	serverURL, token, rest, err := opsFlags("jobs", args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("kiwi jobs requires a run ID")
	}
	var out []model.Job
	if err := newOpsClient(serverURL, token).do(ctx, http.MethodGet, "/api/v1/runs/"+rest[0]+"/jobs", nil, &out); err != nil {
		return err
	}
	if len(out) == 0 {
		fmt.Println("no jobs")
		return nil
	}
	fmt.Printf("%-32s %-20s %-16s %-10s %-20s %s\n", "ID", "KEY", "STATUS", "ATTEMPTS", "RUNNER", "ERROR")
	for _, j := range out {
		// Scheduling failures (lease, policy, capability) live only in
		// Error. Surface them here so a bare "failure" is never silent.
		errCol := j.Error
		if errCol == "" && j.Status != model.StatusSuccess && j.Status != model.StatusQueued && j.Status != model.StatusRunning {
			errCol = "(no error recorded)"
		}
		fmt.Printf("%-32s %-20s %-16s %-10d %-20s %s\n", j.ID, truncate(j.Key, 20), j.Status, j.Attempts, truncate(j.LeaseRunnerID, 20), errCol)
	}
	return nil
}

func opsLogs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	srv := fs.String("server", "", "Kiwi server URL (defaults to the active context / KIWI_SERVER)")
	tok := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin bearer token")
	job := fs.String("job", "", "only print entries for this job key")
	step := fs.String("step", "", "only print entries for this step name (e.g. security)")
	follow := fs.Bool("follow", false, "follow the SSE log stream after the backlog")
	interactive := fs.Bool("interactive", false, "open the interactive TUI log viewer (same as kiwi tui)")
	rest, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("kiwi logs requires a run ID")
	}
	ep, epErr := ResolveEndpoint(*srv, *tok)
	if epErr != nil {
		return epErr
	}
	runID := rest[0]
	if *interactive {
		tuiArgs := []string{"--server", ep.Server, "--token", ep.Token, "--job", *job}
		if *follow {
			tuiArgs = append(tuiArgs, "--follow")
		}
		tuiArgs = append(tuiArgs, runID)
		return tuiWithIO(ctx, tuiArgs, os.Stdout, os.Stdin)
	}
	c := newOpsClient(ep.Server, ep.Token)

	var entries []model.LogEntry
	if err := c.do(ctx, http.MethodGet, "/api/v1/runs/"+runID+"/logs?after=0&limit=100000", nil, &entries); err != nil {
		return err
	}
	var lastSeq int64
	for _, e := range entries {
		if *job != "" && e.JobKey != *job {
			continue
		}
		if *step != "" && e.Step != *step {
			continue
		}
		fmt.Printf("[%s/%s] %s\n", e.JobKey, e.Step, e.Line)
		if e.Seq > lastSeq {
			lastSeq = e.Seq
		}
	}
	if !*follow {
		return nil
	}
	return followLogsFiltered(ctx, c, runID, lastSeq, *job, *step)
}

// followLogs consumes the SSE endpoint, printing entries as they arrive
// until the stream ends (idle timeout) or ctx is cancelled.
func followLogs(ctx context.Context, c *opsClient, runID string, after int64, job string) error {
	return followLogsFiltered(ctx, c, runID, after, job, "")
}

// followLogsFiltered is followLogs with optional job and step-name filters.
func followLogsFiltered(ctx context.Context, c *opsClient, runID string, after int64, job, step string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/runs/%s/logs/stream?after=%d", c.base, runID, after), nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.streamClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("logs stream: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var e model.LogEntry
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err != nil {
			continue
		}
		if job != "" && e.JobKey != job {
			continue
		}
		if step != "" && e.Step != step {
			continue
		}
		fmt.Printf("[%s/%s] %s\n", e.JobKey, e.Step, e.Line)
	}
	return sc.Err()
}

// opsFlake prints flaky tests for a repository from the test-intelligence
// store (tests that flip across runs). This is the CLI half of the JUnit
// evidence contract: status descriptions and release gates must read this
// store, never grep logs (audit SM14 F14).
func opsFlake(ctx context.Context, args []string) error {
	serverURL, token, rest, err := opsFlags("flake", args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("kiwi flake requires a repository (owner/name or canonical host/owner/name)")
	}
	repo := rest[0]
	var out struct {
		Repo       string   `json:"repo"`
		Reports    int      `json:"reports"`
		TotalTests int      `json:"total_tests"`
		Failures   int      `json:"failures"`
		FlakyTests []string `json:"flaky_tests"`
	}
	c := newOpsClient(serverURL, token)
	path := "/api/v1/test-intelligence?repo=" + url.QueryEscape(repo)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return err
	}
	fmt.Printf("repo        %s\n", out.Repo)
	fmt.Printf("reports     %d\n", out.Reports)
	fmt.Printf("tests       %d\n", out.TotalTests)
	fmt.Printf("failures    %d\n", out.Failures)
	if len(out.FlakyTests) == 0 {
		fmt.Println("flaky       (none)")
		return nil
	}
	fmt.Printf("flaky       %d\n", len(out.FlakyTests))
	for _, name := range out.FlakyTests {
		fmt.Printf("  %s\n", name)
	}
	return nil
}

func opsMutateRun(ctx context.Context, sub string, args []string) error {
	serverURL, token, rest, err := opsFlags(sub, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("kiwi %s requires a run ID", sub)
	}
	var run model.Run
	client := newOpsClient(serverURL, token)
	path := "/api/v1/runs/" + rest[0] + "/" + sub
	if sub == "rerun" {
		// A rerun creates a new run: one operation key per invocation is
		// reused by the bounded retries, so a lost 202 replays to the same
		// rerun instead of launching it twice. Cancel is naturally
		// idempotent and keeps the single-shot path.
		err = client.doIdempotent(ctx, http.MethodPost, path, struct{}{}, &run)
	} else {
		err = client.do(ctx, http.MethodPost, path, struct{}{}, &run)
	}
	if err != nil {
		return err
	}
	fmt.Printf("run %s: %s\n", run.ID, run.Status)
	return nil
}

func opsApprove(ctx context.Context, args []string) error {
	serverURL, token, rest, err := opsFlags("approve", args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("kiwi approve requires a job ID")
	}
	var job model.Job
	if err := newOpsClient(serverURL, token).do(ctx, http.MethodPost, "/api/v1/jobs/"+rest[0]+"/approve", struct{}{}, &job); err != nil {
		return err
	}
	fmt.Printf("job %s (%s): approved by %s\n", job.ID, job.Key, job.ApprovedBy)
	return nil
}

func opsArtifacts(ctx context.Context, args []string) error {
	serverURL, token, rest, err := opsFlags("artifacts", args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("kiwi artifacts requires a run ID")
	}
	var out []model.ArtifactRecord
	if err := newOpsClient(serverURL, token).do(ctx, http.MethodGet, "/api/v1/runs/"+rest[0]+"/artifacts", nil, &out); err != nil {
		return err
	}
	if len(out) == 0 {
		fmt.Println("no artifacts")
		return nil
	}
	fmt.Printf("%-28s %-20s %-10s %-16s %s\n", "NAME", "JOB", "SIZE", "SHA256", "ID")
	for _, a := range out {
		fmt.Printf("%-28s %-20s %-10d %-16s %s\n", truncate(a.Name, 28), truncate(a.JobKey, 20), a.Size, truncate(a.SHA256, 16), a.ID)
	}
	return nil
}

// opsSchedules implements kiwi schedules list|trigger:
//
//	kiwi schedules list            — GET /api/v1/schedules
//	kiwi schedules trigger ID      — POST /api/v1/schedules/{id}/trigger
func opsSchedules(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("kiwi schedules requires a subcommand: list or trigger")
	}
	switch args[0] {
	case "list":
		serverURL, token, rest, err := opsFlags("schedules list", args[1:])
		if err != nil {
			return err
		}
		if len(rest) != 0 {
			return fmt.Errorf("kiwi schedules list takes no arguments")
		}
		var out []storage.Schedule
		if err := newOpsClient(serverURL, token).do(ctx, http.MethodGet, "/api/v1/schedules", nil, &out); err != nil {
			return err
		}
		if len(out) == 0 {
			fmt.Println("no schedules")
			return nil
		}
		fmt.Printf("%-32s %-28s %-24s %-8s %s\n", "ID", "REPOSITORY", "SPEC", "ENABLED", "LAST RUN")
		for _, sc := range out {
			last := "-"
			if sc.LastRun != nil {
				last = sc.LastRun.Format(time.RFC3339)
			}
			fmt.Printf("%-32s %-28s %-24s %-8t %s\n", sc.ID, truncate(sc.Repository, 28), truncate(sc.Spec, 24), sc.Enabled, last)
		}
		return nil
	case "trigger":
		serverURL, token, rest, err := opsFlags("schedules trigger", args[1:])
		if err != nil {
			return err
		}
		if len(rest) != 1 {
			return fmt.Errorf("kiwi schedules trigger requires a schedule ID")
		}
		var run model.Run
		if err := newOpsClient(serverURL, token).do(ctx, http.MethodPost, "/api/v1/schedules/"+rest[0]+"/trigger", struct{}{}, &run); err != nil {
			return err
		}
		fmt.Printf("triggered schedule %s: run %s (%s)\n", rest[0], run.ID, run.Status)
		return nil
	default:
		return fmt.Errorf("unknown schedules subcommand %q (want list or trigger)", args[0])
	}
}

// opsPolicy implements `kiwi policy check`: it parses the pipeline file and
// previews admission against the trusted or untrusted DEFAULT capability
// set. It is a local capability preview for operators, not the server's
// full enqueue admission (org policy file, principal grants, and
// structural admitCompiledSpec checks run server-side only). A green result
// here does not guarantee the server will admit the same pipeline.
func opsPolicy(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("kiwi policy requires a subcommand: check")
	}
	if args[0] != "check" {
		return fmt.Errorf("unknown policy subcommand %q (want check)", args[0])
	}
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	file := fs.String("f", ".kiwi/pipeline.yaml", "pipeline file")
	trusted := fs.Bool("trusted", false, "evaluate with trusted default capabilities instead of untrusted")
	policyFile := fs.String("config", "", "policy file to intersect (default .kiwi/policy.toml when present)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	spec, err := pipeline.Load(*file)
	if err != nil {
		return err
	}
	caps := policy.DefaultUntrustedCapabilities()
	if *trusted {
		caps = policy.DefaultTrustedCapabilities()
	}
	// Honor the policy file so a trusted preview matches the server:
	// secret_allowlist and other restrictions narrow the capability set.
	polPath := *policyFile
	if polPath == "" {
		for _, cand := range []string{".kiwi/policy.toml", ".kiwi/policy.yaml"} {
			if _, serr := os.Stat(cand); serr == nil {
				polPath = cand
				break
			}
		}
	}
	if polPath != "" {
		if pol, perr := policy.Load(polPath); perr == nil {
			caps = policy.Intersect(caps, pol.CapabilitiesFor(""))
			fmt.Printf("  policy file:    %s\n", polPath)
		} else {
			return fmt.Errorf("policy: %w", perr)
		}
	}
	effective := caps.Effective(*trusted)
	trust := "untrusted"
	if *trusted {
		trust = "trusted"
	}
	fmt.Printf("pipeline %s: %d jobs, evaluating as %s\n", *file, len(spec.Jobs), trust)
	fmt.Printf("  native_execution: %t  container: %t  tart: %t\n", effective.NativeExecution, effective.Container, effective.Tart)
	fmt.Printf("  network egress:   %s\n", networkName(effective.Network))
	fmt.Printf("  deployments:      %t  cache: read=%t write=%t\n", effective.Deployments, effective.CacheRead, effective.CacheWrite)
	secretRule := "unrestricted"
	if effective.Secrets != nil {
		secretRule = fmt.Sprintf("allowlist (%d names)", len(effective.Secrets))
	}
	fmt.Printf("  secrets:          %s  oidc audiences: %v\n", secretRule, effective.OIDC)
	if err := policy.ValidateAdmissionWithCapabilities(spec, effective); err != nil {
		fmt.Printf("  admission: FAILED\n")
		return fmt.Errorf("policy admission failed: %w", err)
	}
	fmt.Println("  admission: OK")
	return nil
}

func networkName(n pipeline.NetworkPolicy) string {
	switch n {
	case pipeline.NetworkPolicyNone:
		return "none"
	case pipeline.NetworkPolicyServicesOnly:
		return "services-only"
	case pipeline.NetworkPolicyInternet:
		return "internet"
	default:
		return "default"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

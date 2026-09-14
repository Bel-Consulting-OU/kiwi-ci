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
	"os"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
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
	return &opsClient{
		base:   strings.TrimRight(serverURL, "/"),
		token:  token,
		client: server.NoRedirectClient(&http.Client{Timeout: 30 * time.Second}),
	}
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

func opsFlags(name string, args []string) (serverURL, token string, rest []string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	srv := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	tok := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin bearer token")
	if err := fs.Parse(args); err != nil {
		return "", "", nil, err
	}
	return *srv, *tok, fs.Args(), nil
}

func opsRuns(ctx context.Context, args []string) error {
	serverURL, token, rest, err := opsFlags("runs", args)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("kiwi runs takes no arguments")
	}
	var out []model.Run
	if err := newOpsClient(serverURL, token).do(ctx, http.MethodGet, "/api/v1/runs", nil, &out); err != nil {
		return err
	}
	if len(out) == 0 {
		fmt.Println("no runs")
		return nil
	}
	fmt.Printf("%-10s %-16s %-12s %-28s %-8s %s\n", "ID", "STATUS", "EVENT", "REPO", "TRUSTED", "AGE")
	for _, r := range out {
		fmt.Printf("%-10s %-16s %-12s %-28s %-8t %s\n", truncate(r.ID, 10), r.Status, r.Event, truncate(r.Repo, 28), r.Trusted, time.Since(r.CreatedAt).Round(time.Second))
	}
	return nil
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
	fmt.Printf("%-10s %-20s %-16s %-10s %s\n", "ID", "KEY", "STATUS", "ATTEMPTS", "RUNNER")
	for _, j := range out {
		fmt.Printf("%-10s %-20s %-16s %-10d %s\n", truncate(j.ID, 10), truncate(j.Key, 20), j.Status, j.Attempts, truncate(j.LeaseRunnerID, 10))
	}
	return nil
}

func opsLogs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	srv := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	tok := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin bearer token")
	job := fs.String("job", "", "only print entries for this job key")
	follow := fs.Bool("follow", false, "follow the SSE log stream after the backlog")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("kiwi logs requires a run ID")
	}
	runID := fs.Arg(0)
	c := newOpsClient(*srv, *tok)

	var entries []model.LogEntry
	if err := c.do(ctx, http.MethodGet, "/api/v1/runs/"+runID+"/logs?after=0&limit=100000", nil, &entries); err != nil {
		return err
	}
	var lastSeq int64
	for _, e := range entries {
		if *job != "" && e.JobKey != *job {
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
	return followLogs(ctx, c, runID, lastSeq, *job)
}

// followLogs consumes the SSE endpoint, printing entries as they arrive
// until the stream ends (idle timeout) or ctx is cancelled.
func followLogs(ctx context.Context, c *opsClient, runID string, after int64, job string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/runs/%s/logs/stream?after=%d", c.base, runID, after), nil)
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
		fmt.Printf("[%s/%s] %s\n", e.JobKey, e.Step, e.Line)
	}
	return sc.Err()
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
	if err := newOpsClient(serverURL, token).do(ctx, http.MethodPost, "/api/v1/runs/"+rest[0]+"/"+sub, struct{}{}, &run); err != nil {
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

// opsSchedules implements kiwi schedules list|trigger. Server-side
// schedules are deferred, so both forms report that clearly.
func opsSchedules(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("kiwi schedules requires a subcommand: list or trigger")
	}
	switch args[0] {
	case "list", "trigger":
		fmt.Println("schedules are not yet implemented (server-side schedules are deferred)")
		return nil
	default:
		return fmt.Errorf("unknown schedules subcommand %q (want list or trigger)", args[0])
	}
}

// opsPolicy implements `kiwi policy check`: it parses the pipeline file and
// evaluates admission against the trusted or untrusted default capability
// set, mirroring the server's enqueue-time policy pass.
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

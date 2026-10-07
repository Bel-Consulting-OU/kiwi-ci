package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// recordedJobPipeline mirrors the control plane's exact-replay export
// (GET /api/v1/runs/{run}/jobs/{job}/pipeline): the persisted canonical
// pipeline text and the enqueue-time compiled job payload the runner
// verified, plus the job's attempt identity.
type recordedJobPipeline struct {
	RunID              string                    `json:"run_id"`
	JobID              string                    `json:"id"`
	Key                string                    `json:"key"`
	BaseKey            string                    `json:"base_key,omitempty"`
	LeaseGeneration    int64                     `json:"lease_generation,omitempty"`
	Attempts           int                       `json:"attempts,omitempty"`
	Pipeline           string                    `json:"pipeline"`
	CompiledJobPayload *model.CompiledJobPayload `json:"compiled_job_payload,omitempty"`
}

// Replay reconstructs the workspace state a run's job executed in and
// re-runs that job locally.
//
// The default mode is EXACT: the persisted pipeline text and the recorded
// compiled job payload are fetched from the control plane, re-verified with
// the same binding verifier the distributed runner uses
// (pipeline.VerifyCompiledJobBinding), and the recorded effective job is
// executed against the restored workspace snapshot. The operator's local
// pipeline file is never read — a record that no longer re-verifies is
// refused instead of silently running something else.
//
// --debug-rerun restores the previous debugging behavior: the workspace
// snapshot is restored and the CURRENT local pipeline file is compiled and
// executed. Execution semantics therefore come from the local checkout and
// may differ from the recorded run.
//
// Secrets are freshly authorized from the local provider — never captured.
//
// Usage: kiwi replay RUN JOB [STEP] --server URL --token TOKEN [--attempt N] [--debug-rerun] [--pipeline FILE]
func Replay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	server := fs.String("server", os.Getenv("KIWI_SERVER"), "control plane URL")
	token := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin token")
	pipelineFile := fs.String("pipeline", ".kiwi/pipeline.yaml", "pipeline file for --debug-rerun")
	attempt := fs.Int64("attempt", 0, "lease generation (attempt) of the snapshot to replay; default: newest generation for the job")
	debugRerun := fs.Bool("debug-rerun", false, "run against the CURRENT local pipeline file instead of the recorded pipeline (execution semantics may differ)")
	rest, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 2 && len(rest) != 3 {
		return fmt.Errorf("usage: kiwi replay RUN JOB [STEP] --server URL --token TOKEN [--attempt N] [--debug-rerun] [--pipeline FILE]")
	}
	if *server == "" {
		return fmt.Errorf("--server (or KIWI_SERVER) is required")
	}
	if *attempt < 0 {
		return fmt.Errorf("--attempt must be a positive lease generation")
	}
	runID, jobKey := rest[0], rest[1]
	var stepID string
	if len(rest) == 3 {
		stepID = rest[2]
	}
	client := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	auth := func(req *http.Request) {
		if *token != "" {
			req.Header.Set("Authorization", "Bearer "+*token)
		}
	}

	getJSON := func(path string, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, *server+path, nil)
		if err != nil {
			return err
		}
		auth(req)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("%s: %s", resp.Status, string(b))
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}

	// Resolve the pipeline and the job to execute. Exact mode trusts only the
	// control plane's recorded pipeline/payload pair; debug-rerun keeps the
	// local-file behavior and warns about it.
	var spec *pipeline.Spec
	var matchJob pipeline.CompiledJob
	snapshotKey := jobKey
	if *debugRerun {
		fmt.Fprintf(os.Stderr, "warning: --debug-rerun executes %s from your CURRENT pipeline file; execution semantics may differ from the recorded run\n", *pipelineFile)
		spec, err = pipeline.Load(*pipelineFile)
		if err != nil {
			return fmt.Errorf("load pipeline: %w", err)
		}
		g, cerr := pipeline.Compile(spec)
		if cerr != nil {
			return cerr
		}
		found := false
		for _, cj := range g.Jobs {
			if cj.ID == jobKey || cj.BaseID == jobKey {
				matchJob = cj
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("job %q not found in %s", jobKey, *pipelineFile)
		}
	} else {
		var rec recordedJobPipeline
		if err := getJSON("/api/v1/runs/"+url.PathEscape(runID)+"/jobs/"+url.PathEscape(jobKey)+"/pipeline", &rec); err != nil {
			return fmt.Errorf("fetch recorded pipeline: %w", err)
		}
		if rec.Pipeline == "" {
			return fmt.Errorf("run %s job %q has no recorded pipeline", runID, jobKey)
		}
		spec, err = pipeline.Parse([]byte(rec.Pipeline))
		if err != nil {
			return fmt.Errorf("parse recorded pipeline: %w", err)
		}
		// Verify the recorded payload against the HISTORICAL pipeline with
		// the shared runner verifier. A record that does not re-verify is
		// refused: exact replay must never execute something else.
		verified, verr := pipeline.VerifyCompiledJobBinding(spec, rec.Key, rec.CompiledJobPayload)
		if verr != nil {
			return fmt.Errorf("recorded pipeline/payload mismatch for job %q in run %s: %w; use --debug-rerun to run against your current pipeline", rec.Key, runID, verr)
		}
		g, cerr := pipeline.Compile(spec)
		if cerr != nil {
			return fmt.Errorf("compile recorded pipeline: %w", cerr)
		}
		found := false
		for _, cj := range g.Jobs {
			if cj.ID == rec.Key || cj.BaseID == rec.Key {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("job %q not found in the recorded pipeline", rec.Key)
		}
		matchJob = verified
		snapshotKey = rec.Key
	}

	recs, err := listReplaySnapshots(ctx, client, auth, *server, runID)
	if err != nil {
		return fmt.Errorf("list snapshots: %w", err)
	}
	match, err := selectReplaySnapshot(recs, snapshotKey, *attempt, runID)
	if err != nil {
		return err
	}
	fmt.Printf("using snapshot %s (lease generation %d)\n", match.ID, match.LeaseGeneration)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *server+"/api/v1/runs/"+url.PathEscape(runID)+"/snapshots/"+url.PathEscape(match.ID), nil)
	if err != nil {
		return err
	}
	auth(req)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("download snapshot: %s: %s", resp.Status, string(b))
	}
	ws, err := os.MkdirTemp("", "kiwi-replay-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(ws)
	if _, err := snapshot.Restore(resp.Body, ws); err != nil {
		return fmt.Errorf("restore snapshot: %w", err)
	}
	runIDLocal, err := newLocalRunID()
	if err != nil {
		return err
	}
	masker := &secrets.Masker{}
	logs := &logging.Console{Writer: os.Stdout, Masker: masker}
	provider := secrets.Chain{secrets.EnvProvider{Prefix: "KIWI_SECRET_"}, secrets.MacKeychainProvider{Service: "kiwi-ci"}}
	opts := executor.Options{
		Workspace:              ws,
		RunID:                  runIDLocal,
		OnlyStep:               stepID,
		RequireImmutableImages: true,
		InheritEnv:             false,
		SecretProvider:         provider,
		Logs:                   logs,
	}
	e := &executor.Executor{Opt: opts, Masker: masker}
	result := e.RunCompiledJob(ctx, spec, matchJob)
	fmt.Printf("replayed %-36s %-10s %s\n", matchJob.ID, result.Status, result.Duration.Round(1e6))
	if result.Status != model.StatusSuccess && result.Status != model.StatusSkipped {
		return errors.New("replay finished with failures")
	}
	return nil
}

// listReplaySnapshots walks the run's snapshot collection to completion. The
// listing endpoint is keyset-paginated (X-Kiwi-Next-Cursor); assuming one
// page would silently miss the requested attempt on a busy job, so every page
// is followed until the header is absent.
func listReplaySnapshots(ctx context.Context, client *http.Client, auth func(*http.Request), server, runID string) ([]model.SnapshotRecord, error) {
	var all []model.SnapshotRecord
	cursor := ""
	for {
		path := server + "/api/v1/runs/" + url.PathEscape(runID) + "/snapshots"
		if cursor != "" {
			path += "?cursor=" + url.QueryEscape(cursor)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		auth(req)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return nil, fmt.Errorf("%s: %s", resp.Status, string(b))
		}
		var page []model.SnapshotRecord
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		next := resp.Header.Get("X-Kiwi-Next-Cursor")
		resp.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}
		all = append(all, page...)
		if next == "" {
			return all, nil
		}
		if next == cursor {
			return nil, errors.New("snapshot pagination cursor did not advance")
		}
		cursor = next
	}
}

// selectReplaySnapshot picks the snapshot record to restore for jobKey. With
// attempt > 0 only records uploaded under that lease generation match — a
// missing attempt is an error, never a silent fallback to another attempt.
// Without an attempt the newest generation wins (legacy records without a
// generation compare by upload time).
func selectReplaySnapshot(recs []model.SnapshotRecord, jobKey string, attempt int64, runID string) (model.SnapshotRecord, error) {
	var match model.SnapshotRecord
	for _, rec := range recs {
		if rec.JobKey != jobKey {
			continue
		}
		if attempt > 0 {
			if rec.LeaseGeneration != attempt {
				continue
			}
			if match.ID == "" || rec.CreatedAt.After(match.CreatedAt) {
				match = rec
			}
			continue
		}
		if match.ID == "" || rec.LeaseGeneration > match.LeaseGeneration ||
			(rec.LeaseGeneration == match.LeaseGeneration && rec.CreatedAt.After(match.CreatedAt)) {
			match = rec
		}
	}
	if match.ID == "" {
		if attempt > 0 {
			return match, fmt.Errorf("no workspace snapshot for job %q at lease generation %d in run %s", jobKey, attempt, runID)
		}
		return match, fmt.Errorf("no workspace snapshot for job %q in run %s", jobKey, runID)
	}
	return match, nil
}

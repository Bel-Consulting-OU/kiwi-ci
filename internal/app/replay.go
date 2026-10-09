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

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/execution"
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
// verified, plus the job's attempt identity and the persisted execution state
// (trust, resource requests, service envelope) the shared materializer needs.
type recordedJobPipeline struct {
	RunID              string                    `json:"run_id"`
	JobID              string                    `json:"id"`
	Key                string                    `json:"key"`
	BaseKey            string                    `json:"base_key,omitempty"`
	LeaseGeneration    int64                     `json:"lease_generation,omitempty"`
	Attempts           int                       `json:"attempts,omitempty"`
	Pipeline           string                    `json:"pipeline"`
	CompiledJobPayload *model.CompiledJobPayload `json:"compiled_job_payload,omitempty"`
	PersistedJob       *recordedPersistedJob     `json:"persisted_job,omitempty"`
}

// recordedPersistedJob is the persisted execution state the materializer
// consumes; it mirrors the control plane's exportedPersistedJob DTO.
type recordedPersistedJob struct {
	Trusted                bool                   `json:"trusted"`
	Network                string                 `json:"network,omitempty"`
	CPURequest             float64                `json:"cpu_request,omitempty"`
	MemoryRequest          int64                  `json:"memory_request,omitempty"`
	DiskRequest            int64                  `json:"disk_request,omitempty"`
	PIDsRequest            int                    `json:"pids_request,omitempty"`
	ServiceEnvelopeRequest model.ResourceCapacity `json:"service_envelope_request,omitempty"`
}

// persistedJob converts the exported state to the model.Job shape the
// materializer consumes.
func (r recordedPersistedJob) persistedJob() model.Job {
	return model.Job{
		Trusted:                r.Trusted,
		Network:                r.Network,
		CPURequest:             r.CPURequest,
		MemoryRequest:          r.MemoryRequest,
		DiskRequest:            r.DiskRequest,
		PIDsRequest:            r.PIDsRequest,
		ServiceEnvelopeRequest: r.ServiceEnvelopeRequest,
	}
}

// replayOptionsSeam observes the effective executor.Options a replay derived
// (test-only; production leaves it nil).
var replayOptionsSeam func(executor.Options)

// replayWorkspaceDiskQuotaSetup is the OS-level hard workspace-bound probe
// exact replay uses for an untrusted recorded job. It defaults to the
// executor's capability probe — the same mechanism the distributed runner
// installs before checkout (WorkspaceDiskQuotaSetup, an XFS project quota) —
// and is a variable so tests can drive the supported/unsupported outcomes
// deterministically.
var replayWorkspaceDiskQuotaSetup = executor.WorkspaceDiskQuotaSetup

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
// An untrusted recorded job (exact mode) additionally requires the same
// OS-level hard workspace quota the distributed runner installs: the quota is
// applied to the replay workspace BEFORE the snapshot is restored, and when
// the host cannot establish one the replay refuses to run untrusted code
// unless --allow-unbounded-workspace is passed explicitly (with a loud
// warning). Trusted jobs and --debug-rerun keep their previous behavior.
//
// Secrets are freshly authorized from the local provider — never captured.
//
// Usage: kiwi replay RUN JOB [STEP] --server URL --token TOKEN [--attempt N] [--debug-rerun] [--allow-unbounded-workspace] [--allow-post-job-snapshot] [--pipeline FILE]
func Replay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	server := fs.String("server", os.Getenv("KIWI_SERVER"), "control plane URL")
	token := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin token")
	pipelineFile := fs.String("pipeline", ".kiwi/pipeline.yaml", "pipeline file for --debug-rerun")
	attempt := fs.Int64("attempt", 0, "lease generation (attempt) of the snapshot to replay; default: newest generation for the job")
	debugRerun := fs.Bool("debug-rerun", false, "run against the CURRENT local pipeline file instead of the recorded pipeline (execution semantics may differ)")
	allowUnbounded := fs.Bool("allow-unbounded-workspace", false, "replay an untrusted recorded job even when no OS-level hard workspace quota can be established (hostile recorded code can then fill the operator filesystem; prints a warning)")
	allowPostJob := fs.Bool("allow-post-job-snapshot", false, "replay from the post-execution (post_job) snapshot when the attempt has no pre-execution checkpoint (execution starts from post-execution workspace state)")
	rest, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 2 && len(rest) != 3 {
		return fmt.Errorf("usage: kiwi replay RUN JOB [STEP] --server URL --token TOKEN [--attempt N] [--debug-rerun] [--allow-unbounded-workspace] [--allow-post-job-snapshot] [--pipeline FILE]")
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
	// materialized is the effective execution of the recorded job (exact mode
	// only): the trust/resource/network/sandbox overlays the distributed
	// runner executed under. Replay maps it onto executor.Options so a hostile
	// record can never be replayed under weaker restrictions.
	var materialized *execution.EffectiveExecution
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
		// Materialize the effective execution from the recorded verified job
		// plus the persisted job fields: the same pure derivation the
		// distributed runner ran, so the replay enforces the recorded
		// network/sandbox/resource restrictions even if a hostile record
		// tries to present more permissive persisted fields.
		if rec.PersistedJob == nil {
			return fmt.Errorf("recorded job %q in run %s has no persisted execution state (trust/resources); the control plane is too old for exact replay: use --debug-rerun to run against your current pipeline", rec.Key, runID)
		}
		persisted := rec.PersistedJob.persistedJob()
		caps, _, cerr := execution.EffectivePolicyCapabilities(rec.CompiledJobPayload, persisted.Trusted)
		if cerr != nil {
			return fmt.Errorf("recorded effective policy for job %q in run %s is invalid: %w; use --debug-rerun to run against your current pipeline", rec.Key, runID, cerr)
		}
		eff, merr := execution.MaterializeEffectiveExecution(verified, rec.CompiledJobPayload, persisted, caps)
		if merr != nil {
			return fmt.Errorf("recorded effective execution for job %q in run %s is invalid: %w; use --debug-rerun to run against your current pipeline", rec.Key, runID, merr)
		}
		materialized = &eff
		matchJob = eff.CompiledJob
		snapshotKey = rec.Key
	}

	recs, err := listReplaySnapshots(ctx, client, auth, *server, runID)
	if err != nil {
		return fmt.Errorf("list snapshots: %w", err)
	}
	match, err := selectReplaySnapshot(recs, snapshotKey, *attempt, runID, *allowPostJob)
	if err != nil {
		return err
	}
	if snapshotPhaseOf(match) == model.SnapshotPhasePostJob {
		fmt.Fprintf(os.Stderr, "warning: --allow-post-job-snapshot selected the POST-execution snapshot %s; execution starts from the state the recorded attempt left behind, not from a pre-execution checkpoint\n", match.ID)
	}
	fmt.Printf("using %s snapshot %s (lease generation %d)\n", snapshotPhaseOf(match), match.ID, match.LeaseGeneration)

	// The replay workspace is created NOW, before the snapshot is downloaded
	// and restored, so the hard quota for an untrusted recorded job can be
	// installed on the empty directory exactly like the distributed runner
	// installs it before checkout. Without it a hostile historical job could
	// fill the operator filesystem during execution (the step-boundary
	// resources.disk check is not a security boundary).
	ws, err := os.MkdirTemp("", "kiwi-replay-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(ws)
	var replayQuota *executor.DiskQuotaStatus
	if materialized != nil && materialized.Untrusted {
		if *allowUnbounded {
			fmt.Fprintf(os.Stderr, "warning: --allow-unbounded-workspace: replaying UNTRUSTED recorded code without an OS-level hard workspace quota; workspace writes are only checked at step boundaries and hostile code can fill the operator filesystem\n")
		} else {
			// The same capability probe (and XFS project-quota install) the
			// distributed runner runs before checkout. Replay has no
			// crash-recovery ledger, so a hard crash mid-replay can leave the
			// project quota assigned; normal return always cleans it up.
			status, cleanup := replayWorkspaceDiskQuotaSetup(ws, materialized.WorkspaceQuotaLimit)
			if !status.Hard {
				if cleanup != nil {
					_ = cleanup()
				}
				return fmt.Errorf("refusing to replay untrusted job %q without an OS-level hard workspace quota: %s; the replay workspace would be bounded only at step boundaries, so hostile recorded code could fill the operator filesystem — re-run with --allow-unbounded-workspace to accept that risk", jobKey, status.Detail)
			}
			if cleanup != nil {
				defer cleanup()
			}
			replayQuota = &status
		}
	}

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
		Workspace:      ws,
		RunID:          runIDLocal,
		OnlyStep:       stepID,
		InheritEnv:     false,
		SecretProvider: provider,
		Logs:           logs,
	}
	if materialized != nil {
		// Exact replay: enforce the recorded effective execution (untrusted
		// floor, workspace bound, immutable images) through the ONE shared
		// mapping the distributed runner uses. Deliberate local-only
		// differences: the ephemeral local workspace, no artifact/cache
		// upload, and the step selector. For an untrusted record the hard
		// OS-level workspace quota was installed on the empty workspace
		// before the snapshot was restored (replayQuota); its outcome is
		// passed through so the container backend accepts it as already
		// bounded instead of re-probing (or running unbounded).
		opts = executor.OptionsFromExecution(opts, *materialized)
		if replayQuota != nil {
			opts.WorkspaceQuota = replayQuota
			opts.RequireUntrustedDiskQuota = true
		}
	} else {
		// --debug-rerun executes the local file with historical local
		// semantics; no recorded effective execution exists to derive from.
		opts.RequireImmutableImages = true
	}
	// Test seam: observe the final options (production leaves it nil).
	if replayOptionsSeam != nil {
		replayOptionsSeam(opts)
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

// snapshotPhaseOf returns the effective phase of a snapshot record. Legacy
// records (persisted before the phase field existed) carry an empty phase and
// were outcome captures, so they mean post_job.
func snapshotPhaseOf(rec model.SnapshotRecord) string {
	if rec.Phase == "" {
		return model.SnapshotPhasePostJob
	}
	return rec.Phase
}

// selectReplaySnapshot picks the snapshot record to restore for jobKey.
//
// Replay MUST start from the pre-execution checkpoint (phase pre_job): the
// post-execution snapshot already contains the attempt's mutations, so
// executing from it would silently run against post-execution state. With
// attempt > 0 only records uploaded under that lease generation match — a
// missing attempt is an error, never a silent fallback to another attempt.
// Without an attempt the newest generation wins (legacy records without a
// generation compare by upload time).
//
// When the requested attempt has no pre_job record, the caller may opt into
// the post_job record with allowPostJob (the --allow-post-job-snapshot escape
// hatch); the record is returned so the caller can warn that execution starts
// from post-execution state. Without the escape hatch the refusal names the
// problem and the flag.
func selectReplaySnapshot(recs []model.SnapshotRecord, jobKey string, attempt int64, runID string, allowPostJob bool) (model.SnapshotRecord, error) {
	if match := pickReplaySnapshot(recs, jobKey, attempt, model.SnapshotPhasePreJob); match.ID != "" {
		return match, nil
	}
	post := pickReplaySnapshot(recs, jobKey, attempt, model.SnapshotPhasePostJob)
	if post.ID != "" {
		if allowPostJob {
			return post, nil
		}
		where := "for job " + fmt.Sprintf("%q", jobKey)
		if attempt > 0 {
			where = fmt.Sprintf("for job %q at lease generation %d", jobKey, attempt)
		}
		return model.SnapshotRecord{}, fmt.Errorf("no pre-execution (pre_job) workspace snapshot %s in run %s: the recorded attempt has only a post-execution snapshot, and replaying it would start from the state the attempt already mutated; re-run with --allow-post-job-snapshot to accept post-execution state, or re-run the job with a runner that captures pre_job snapshots", where, runID)
	}
	if attempt > 0 {
		return model.SnapshotRecord{}, fmt.Errorf("no workspace snapshot for job %q at lease generation %d in run %s", jobKey, attempt, runID)
	}
	return model.SnapshotRecord{}, fmt.Errorf("no workspace snapshot for job %q in run %s", jobKey, runID)
}

// pickReplaySnapshot returns the newest record for jobKey whose effective
// phase equals phase (legacy empty phases are post_job), honoring the attempt
// selection rules: a positive attempt matches exactly that lease generation;
// zero selects across generations (newest generation, then newest upload).
func pickReplaySnapshot(recs []model.SnapshotRecord, jobKey string, attempt int64, phase string) model.SnapshotRecord {
	var match model.SnapshotRecord
	for _, rec := range recs {
		if rec.JobKey != jobKey || snapshotPhaseOf(rec) != phase {
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
	return match
}

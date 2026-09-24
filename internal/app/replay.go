package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// Replay reconstructs the exact workspace state a run's job executed in and
// re-runs that job locally. The snapshot restores the content-addressed
// workspace; the pipeline file recompiles to the same resolved job. Secrets
// are freshly authorized from the local provider — never captured.
//
// Usage: kiwi replay RUN JOB [STEP] --server URL --token TOKEN --pipeline FILE
func Replay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	server := fs.String("server", os.Getenv("KIWI_SERVER"), "control plane URL")
	token := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin token")
	pipelineFile := fs.String("pipeline", ".kiwi/pipeline.yaml", "pipeline file for the run being replayed")
	rest, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 2 && len(rest) != 3 {
		return fmt.Errorf("usage: kiwi replay RUN JOB [STEP] --server URL --token TOKEN --pipeline FILE")
	}
	if *server == "" {
		return fmt.Errorf("--server (or KIWI_SERVER) is required")
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

	var recs []model.SnapshotRecord
	if err := getJSON("/api/v1/runs/"+runID+"/snapshots", &recs); err != nil {
		return fmt.Errorf("list snapshots: %w", err)
	}
	var match model.SnapshotRecord
	for _, rec := range recs {
		if rec.JobKey == jobKey {
			if rec.CreatedAt.After(match.CreatedAt) {
				match = rec
			}
		}
	}
	if match.ID == "" {
		return fmt.Errorf("no workspace snapshot for job %q in run %s", jobKey, runID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *server+"/api/v1/runs/"+runID+"/snapshots/"+match.ID, nil)
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
	spec, err := pipeline.Load(*pipelineFile)
	if err != nil {
		return fmt.Errorf("load pipeline: %w", err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		return err
	}
	var matchJob *pipeline.CompiledJob
	for _, cj := range g.Jobs {
		if cj.ID == jobKey || cj.BaseID == jobKey {
			cj := cj
			matchJob = &cj
			break
		}
	}
	if matchJob == nil {
		return fmt.Errorf("job %q not found in %s", jobKey, *pipelineFile)
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
	result := e.RunCompiledJob(ctx, g.Spec, *matchJob)
	fmt.Printf("replayed %-36s %-10s %s\n", matchJob.ID, result.Status, result.Duration.Round(1e6))
	if result.Status != model.StatusSuccess && result.Status != model.StatusSkipped {
		return errors.New("replay finished with failures")
	}
	return nil
}

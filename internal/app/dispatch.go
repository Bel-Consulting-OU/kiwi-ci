package app

import (
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
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// kvFlags collects repeatable --input k=v flags.
type kvFlags struct {
	pairs map[string]string
}

func (k *kvFlags) String() string { return "k=v" }

func (k *kvFlags) Set(v string) error {
	name, val, ok := strings.Cut(v, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return fmt.Errorf("input must be k=v, got %q", v)
	}
	if k.pairs == nil {
		k.pairs = map[string]string{}
	}
	k.pairs[name] = val
	return nil
}

// Dispatch submits a manual run to a Kiwi control plane:
//
//	kiwi dispatch --repo org/app --ref main --input environment=staging \
//	    --pipeline .kiwi/pipeline.yaml
//
// The pipeline is required in v1 (a forge-backed pipeline fetch is a
// deferred integration); inputs travel as Metadata keys "input.<name>" and
// are validated and injected server-side at enqueue.
func Dispatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dispatch", flag.ContinueOnError)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	token := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin/API bearer token")
	repo := fs.String("repo", "", "repository: owner/name (GitHub default) or a full clone URL")
	ref := fs.String("ref", "main", "git ref to dispatch")
	event := fs.String("event", "manual", "event name recorded on the run")
	pipeline := fs.String("pipeline", "", "pipeline YAML file (required)")
	var inputs kvFlags
	fs.Var(&inputs, "input", "pipeline input k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*repo) == "" {
		return fmt.Errorf("--repo is required (owner/name or clone URL)")
	}
	if *pipeline == "" {
		return fmt.Errorf("--pipeline is required in v1 (forge-backed pipeline fetch is deferred)")
	}
	b, err := os.ReadFile(*pipeline)
	if err != nil {
		return err
	}
	repoURL, repoFullName := repoCoords(*repo)
	meta := map[string]string{}
	for k, v := range inputs.pairs {
		meta["input."+k] = v
	}
	in := server.SubmitRun{
		RepoURL:      repoURL,
		RepoFullName: repoFullName,
		Ref:          *ref,
		Event:        *event,
		Pipeline:     string(b),
		Metadata:     meta,
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(*serverURL, "/")+"/api/v1/runs", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("dispatch: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var run model.Run
	if err := json.Unmarshal(body, &run); err != nil {
		return err
	}
	fmt.Printf("dispatched run %s (%s) %s %s\n", run.ID, run.Event, run.RepoFullName, run.Ref)
	return nil
}

// repoCoords derives the clone URL and canonical full name from a --repo
// value: a URL is used as-is (full name from the last two path segments);
// an owner/name pair defaults to GitHub.
func repoCoords(repo string) (repoURL, fullName string) {
	repo = strings.TrimSpace(repo)
	if strings.Contains(repo, "://") {
		repoURL = repo
		fullName = repo
		if i := strings.Index(fullName, "://"); i >= 0 {
			fullName = fullName[i+3:]
		}
		fullName = strings.TrimSuffix(fullName, "/")
		if i := strings.Index(fullName, "/"); i >= 0 {
			fullName = fullName[i+1:]
		}
		fullName = strings.TrimSuffix(fullName, ".git")
		return repoURL, fullName
	}
	fullName = repo
	repoURL = "https://github.com/" + fullName + ".git"
	return repoURL, fullName
}

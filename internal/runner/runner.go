package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kiwici/kiwi/internal/artifact"
	"github.com/kiwici/kiwi/internal/cache"
	"github.com/kiwici/kiwi/internal/executor"
	"github.com/kiwici/kiwi/internal/logging"
	"github.com/kiwici/kiwi/internal/model"
	"github.com/kiwici/kiwi/internal/pipeline"
	"github.com/kiwici/kiwi/internal/policy"
	"github.com/kiwici/kiwi/internal/secrets"
	"github.com/kiwici/kiwi/internal/server"
	"github.com/kiwici/kiwi/internal/testintel"
)

type Config struct {
	Server, Token, Name string
	Labels              []string
	Poll                time.Duration
	Heartbeat           time.Duration
	Concurrency         int
}
type Runner struct {
	Cfg    Config
	ID     string
	Client *http.Client
}

func (r *Runner) Run(ctx context.Context) error {
	if r.Client == nil {
		r.Client = &http.Client{Timeout: 65 * time.Second}
	}
	if r.Cfg.Poll == 0 {
		r.Cfg.Poll = 2 * time.Second
	}
	if r.Cfg.Heartbeat == 0 {
		r.Cfg.Heartbeat = 10 * time.Second
	}
	if r.Cfg.Concurrency <= 0 {
		r.Cfg.Concurrency = 1
	}
	if err := r.register(ctx); err != nil {
		return err
	}
	done := make(chan struct{}, r.Cfg.Concurrency)
	active := 0
	for {
		// Fill every free local execution slot before sleeping. The control plane
		// independently capacity-checks this runner, so a race cannot over-lease it.
		for active < r.Cfg.Concurrency {
			task, err := r.next(ctx)
			if err != nil || task == nil {
				break
			}
			active++
			go func(t server.Task) {
				r.execute(ctx, t)
				done <- struct{}{}
			}(*task)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			active--
		case <-time.After(r.Cfg.Poll):
		}
	}
}
func (r *Runner) register(ctx context.Context) error {
	labels := append([]string{}, r.Cfg.Labels...)
	labels = append(labels, "os:"+runtime.GOOS, "arch:"+runtime.GOARCH, "native")
	if _, err := exec.LookPath("docker"); err == nil {
		labels = append(labels, "container")
	}
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("tart"); err == nil {
			labels = append(labels, "tart")
		}
	}
	in := model.Runner{ID: r.ID, Name: r.Cfg.Name, Labels: unique(labels), Metadata: map[string]string{"go": runtime.Version()}, Capacity: r.Cfg.Concurrency}
	var out model.Runner
	if err := r.post(ctx, "/api/v1/runners/register", in, &out); err != nil {
		return err
	}
	r.ID = out.ID
	fmt.Printf("kiwi runner %s registered (%s/%s) labels=%s\n", r.ID, runtime.GOOS, runtime.GOARCH, strings.Join(out.Labels, ","))
	return nil
}
func (r *Runner) next(ctx context.Context) (*server.Task, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Cfg.Server+"/api/v1/runners/"+r.ID+"/next", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	r.auth(req)
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("next: %s: %s", resp.Status, b)
	}
	var t server.Task
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *Runner) execute(parent context.Context, t server.Task) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	go r.heartbeatLoop(ctx, cancel, t, done)
	defer close(done)

	tmp, err := os.MkdirTemp("", "kiwi-run-*")
	if err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	defer os.RemoveAll(tmp)
	if err = r.checkout(ctx, t.Job, tmp); err != nil {
		r.complete(parent, t, statusForErr(ctx, err), err, nil)
		return
	}
	spec, err := pipeline.Parse([]byte(t.Job.Pipeline))
	if err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	if err := policy.ValidateAdmission(spec, t.Job.Trusted); err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	cj, ok := g.Jobs[t.Job.Key]
	if !ok {
		r.complete(parent, t, model.StatusFailure, fmt.Errorf("compiled job %q not found", t.Job.Key), nil)
		return
	}
	cj.Job.Network = t.Job.Network
	masker := &secrets.Masker{}
	if cj.Job.Permissions.IDToken {
		if cj.Job.Env == nil {
			cj.Job.Env = map[string]string{}
		}
		cj.Job.Env["KIWI_OIDC_REQUEST_URL"] = r.Cfg.Server + "/api/v1/jobs/" + t.Job.ID + "/oidc"
		cj.Job.Env["KIWI_OIDC_REQUEST_TOKEN"] = t.LeaseToken
		masker.Add(t.LeaseToken)
	}
	if err := r.restoreDownloads(ctx, t, cj.Job.Downloads, tmp); err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	sink := logging.Func(func(job, step, line string) {
		msg := masker.Mask(line)
		fmt.Printf("[%s/%s] %s\n", job, step, msg)
		_ = r.post(parent, "/api/v1/jobs/"+t.Job.ID+"/log", server.LogLine{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration, JobKey: job, Step: step, Line: msg}, nil)
	})
	provider := secrets.Chain{secrets.EnvProvider{Prefix: "KIWI_SECRET_"}, secrets.MacKeychainProvider{Service: "kiwi-ci"}}
	cacheStore := cache.Default()
	cacheStore.RemoteURL, cacheStore.Token, cacheStore.Client = r.Cfg.Server, r.Cfg.Token, r.Client
	reporter := func(_ string, name, path string) error { return r.uploadArtifact(parent, t, name, path) }
	ex := executor.Executor{Opt: executor.Options{Workspace: tmp, RunID: t.Job.RunID, Event: t.Job.Event, Branch: branchFromRef(t.Job.Ref), ChangedFiles: effectiveChangedFiles(t.Job.ChangedFiles, tmp), SecretProvider: provider, Logs: sink, Cache: cacheStore, ArtifactReporter: reporter, DependencyStatus: t.Job.DependencyStatus, NeedsOutputs: t.Job.NeedsOutputs, CacheNamespace: cacheNamespace(t.Job)}, Masker: masker}
	res := ex.RunCompiledJob(ctx, spec, cj)
	if len(cj.Job.TestReports) > 0 {
		report, er := testintel.Aggregate(tmp, cj.Job.TestReports)
		if er != nil {
			sink.WriteLine(cj.ID, "tests", "report warning: "+er.Error())
		} else if report.Tests > 0 {
			er = r.post(parent, "/api/v1/jobs/"+t.Job.ID+"/tests", map[string]any{"runner_id": r.ID, "lease_token": t.LeaseToken, "lease_generation": t.LeaseGeneration, "report": report}, nil)
			if er != nil {
				sink.WriteLine(cj.ID, "tests", "upload warning: "+er.Error())
			}
		}
	}
	var runErr error
	if res.Error != "" {
		runErr = fmt.Errorf("%s", res.Error)
	}
	r.complete(parent, t, res.Status, runErr, res.Outputs)
}

func (r *Runner) heartbeatLoop(ctx context.Context, cancel context.CancelFunc, t server.Task, done <-chan struct{}) {
	ticker := time.NewTicker(r.Cfg.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			var out server.HeartbeatResponse
			err := r.post(ctx, "/api/v1/jobs/"+t.Job.ID+"/heartbeat", server.Heartbeat{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration}, &out)
			if err != nil {
				continue
			}
			if out.Cancel {
				cancel()
				return
			}
		}
	}
}

func statusForErr(ctx context.Context, err error) model.Status {
	if ctx.Err() != nil {
		return model.StatusCancelled
	}
	_ = err
	return model.StatusFailure
}
func cacheNamespace(j model.Job) string {
	trust := "untrusted"
	if j.Trusted {
		trust = "trusted"
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(j.RepoURL))))
	return "repo:" + hex.EncodeToString(sum[:12]) + ":" + trust
}

func branchFromRef(ref string) string {
	return strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/")
}
func effectiveChangedFiles(serverFiles []string, dir string) []string {
	if len(serverFiles) > 0 {
		return append([]string{}, serverFiles...)
	}
	return changedFiles(dir)
}
func changedFiles(dir string) []string {
	b, err := exec.Command("git", "-C", dir, "diff", "--name-only", "HEAD~1", "HEAD").Output()
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range strings.Split(string(b), "\n") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (r *Runner) checkout(ctx context.Context, j model.Job, dir string) error {
	args := []string{"clone", "--filter=blob:none", "--no-checkout", j.RepoURL, dir}
	cmdClone := exec.CommandContext(ctx, "git", args...)
	cmdClone.Env = os.Environ()
	if token := os.Getenv("KIWI_GITHUB_TOKEN"); token != "" {
		cmdClone.Env = append(cmdClone.Env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Bearer "+token)
	}
	if out, err := cmdClone.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone: %v: %s", err, out)
	}
	ref := j.Ref
	if j.SHA != "" {
		ref = j.SHA
	}
	if ref == "" {
		ref = "HEAD"
	}
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "checkout", "--force", ref)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git checkout: %v: %s", err, out)
	}
	return nil
}
func (r *Runner) restoreDownloads(ctx context.Context, t server.Task, inputs []pipeline.ArtifactInput, workspace string) error {
	if len(inputs) == 0 {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Cfg.Server+"/api/v1/runs/"+t.Job.RunID+"/artifacts", nil)
	if err != nil {
		return err
	}
	r.auth(req)
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("list artifacts %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var records []model.ArtifactRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return err
	}
	for _, in := range inputs {
		dest := workspace
		if in.Path != "" {
			clean := filepath.Clean(in.Path)
			if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return fmt.Errorf("unsafe download path %q", in.Path)
			}
			dest = filepath.Join(workspace, clean)
		}
		matches := 0
		for _, a := range records {
			base := a.JobKey
			if i := strings.IndexByte(base, '['); i >= 0 {
				base = base[:i]
			}
			if a.Name != in.Name || (a.JobKey != in.From && base != in.From) {
				continue
			}
			matches++
			tmp, err := os.CreateTemp("", "kiwi-artifact-*.tar.gz")
			if err != nil {
				return err
			}
			tmpPath := tmp.Name()
			h := sha256.New()
			url := r.Cfg.Server + "/api/v1/artifacts/" + a.ID
			dreq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err == nil {
				r.auth(dreq)
			}
			if err != nil {
				tmp.Close()
				os.Remove(tmpPath)
				return err
			}
			dresp, err := r.Client.Do(dreq)
			if err != nil {
				tmp.Close()
				os.Remove(tmpPath)
				return err
			}
			if dresp.StatusCode != 200 {
				b, _ := io.ReadAll(io.LimitReader(dresp.Body, 4096))
				dresp.Body.Close()
				tmp.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("download artifact %s: %s: %s", a.Name, dresp.Status, strings.TrimSpace(string(b)))
			}
			_, cp := io.Copy(io.MultiWriter(tmp, h), dresp.Body)
			dresp.Body.Close()
			cl := tmp.Close()
			if cp != nil {
				os.Remove(tmpPath)
				return cp
			}
			if cl != nil {
				os.Remove(tmpPath)
				return cl
			}
			got := hex.EncodeToString(h.Sum(nil))
			if a.SHA256 != "" && got != a.SHA256 {
				os.Remove(tmpPath)
				return fmt.Errorf("artifact %s integrity mismatch", a.Name)
			}
			if err := artifact.Extract(tmpPath, dest); err != nil {
				os.Remove(tmpPath)
				return err
			}
			os.Remove(tmpPath)
		}
		if matches == 0 {
			return fmt.Errorf("required artifact %s from %s not found", in.Name, in.From)
		}
	}
	return nil
}

func (r *Runner) uploadArtifact(ctx context.Context, t server.Task, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	url := r.Cfg.Server + "/api/v1/jobs/" + t.Job.ID + "/artifacts/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, f)
	if err != nil {
		return err
	}
	r.auth(req)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Kiwi-Runner-ID", r.ID)
	req.Header.Set("X-Kiwi-Lease-Token", t.LeaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", fmt.Sprint(t.LeaseGeneration))
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("artifact upload %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (r *Runner) complete(ctx context.Context, t server.Task, st model.Status, err error, outputs map[string]string) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	_ = r.post(ctx, "/api/v1/jobs/"+t.Job.ID+"/complete", server.Complete{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration, Status: st, Error: msg, Outputs: outputs}, nil)
}
func (r *Runner) post(ctx context.Context, path string, in, out any) error {
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Cfg.Server+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r.auth(req)
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, bb)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
func unique(in []string) []string {
	m := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, x := range in {
		if x != "" && !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}
func (r *Runner) auth(req *http.Request) {
	if r.Cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Cfg.Token)
	}
}

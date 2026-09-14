package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"go.opentelemetry.io/otel/attribute"
)

// publishGitHubStatus mirrors run state to the forge via the durable
// outbox: one "Kiwi / Pipeline" check plus one per-job check for every
// finished job. It only queues intents and returns immediately, so it is
// safe to call while holding the server lock. Dispatch happens in
// Maintain's flushOutbox tick and is best-effort by design.
func (s *Server) publishGitHubStatus(run model.Run) {
	_, span := s.startSpan(context.Background(), "forge.status.publish")
	defer span.End()
	if run.RepoFullName == "" || run.SHA == "" {
		return
	}
	if s.GitHubToken == "" && s.GitHubAppID == 0 && s.gitHubAPIBase == "" {
		// No publishing credential or endpoint configured: nothing can be
		// published, so the intent would never dispatch. Skip enqueueing.
		return
	}
	status, conclusion := checkStateForRun(run.Status)
	summary := "pipeline " + string(run.Status)
	items := []forge.OutboxItem{s.checkIntent(run, "Pipeline", status, conclusion, summary, nil)}
	span.SetAttributes(attribute.String("kiwi.run_status", string(run.Status)))

	s.mu.Lock()
	var jobIntents []forge.OutboxItem
	for _, j := range s.jobs {
		if j.RunID != run.ID || !j.Status.Terminal() {
			continue
		}
		jstatus, jconclusion := checkStateForRun(j.Status)
		jsummary := "job " + j.Key + " " + string(j.Status)
		if j.Error != "" {
			jsummary += ": " + j.Error
		}
		jobIntents = append(jobIntents, s.checkIntent(run, j.Key, jstatus, jconclusion, jsummary, nil))
	}
	s.mu.Unlock()
	// Deterministic order: pipeline first, then jobs sorted by key.
	sort.Slice(jobIntents, func(i, j int) bool {
		var a, b forge.CheckPayload
		_ = json.Unmarshal(jobIntents[i].Payload, &a)
		_ = json.Unmarshal(jobIntents[j].Payload, &b)
		return a.Name < b.Name
	})
	items = append(items, jobIntents...)
	for _, it := range items {
		if err := s.outbox.Enqueue(it); err != nil {
			log.Printf("outbox: enqueue %s: %v", it.Kind, err)
		}
	}
}

func (s *Server) checkIntent(run model.Run, name, status, conclusion, summary string, annotations []forge.CheckAnnotation) forge.OutboxItem {
	detailsURL := ""
	if s.ExternalURL != "" {
		detailsURL = s.ExternalURL + "/?run=" + run.ID
	}
	payload, err := json.Marshal(forge.CheckPayload{
		RepoFullName: run.RepoFullName,
		SHA:          run.SHA,
		Name:         name,
		Status:       status,
		Conclusion:   conclusion,
		DetailsURL:   detailsURL,
		Summary:      summary,
		Annotations:  annotations,
	})
	if err != nil {
		payload = []byte("{}")
	}
	return forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: payload}
}

// checkStateForRun maps Kiwi run/job statuses onto GitHub check-run
// status/conclusion pairs.
func checkStateForRun(status model.Status) (checkStatus, conclusion string) {
	switch status {
	case model.StatusQueued:
		return "queued", ""
	case model.StatusRunning, model.StatusWaitingApproval, model.StatusPending:
		return "in_progress", ""
	case model.StatusSuccess:
		return "completed", "success"
	case model.StatusSkipped:
		return "completed", "skipped"
	case model.StatusCancelled:
		return "completed", "cancelled"
	case model.StatusFailure, model.StatusBlocked:
		return "completed", "failure"
	default:
		return "in_progress", ""
	}
}

// publishGitHubStatusFromPayload is the legacy commit-status dispatch for
// github_status outbox intents. It posts directly to the GitHub statuses
// API and is kept for intents enqueued by older state or external callers.
func (s *Server) publishGitHubStatusFromPayload(ctx context.Context, p forge.StatusPayload) error {
	if p.RepoFullName == "" || p.SHA == "" {
		return nil
	}
	body, err := json.Marshal(map[string]any{
		"state":       p.State,
		"description": p.Description,
		"context":     p.Context,
		"target_url":  p.TargetURL,
	})
	if err != nil {
		return err
	}
	url := "https://api.github.com/repos/" + p.RepoFullName + "/statuses/" + p.SHA
	if s.gitHubAPIBase != "" {
		url = s.gitHubAPIBase + "/repos/" + p.RepoFullName + "/statuses/" + p.SHA
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	g := s.gitHubForge()
	if tok, err := g.TokenFor(ctx, p.RepoFullName); err != nil {
		return err
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	client := NoRedirectClient(&http.Client{Timeout: 15 * time.Second})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GitHub statuses API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

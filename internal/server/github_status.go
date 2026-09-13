package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kiwici/kiwi/internal/model"
)

// publishGitHubStatus mirrors run state to the GitHub commit status API.
// It is best-effort: without a token or forge coordinates it is a no-op.
func (s *Server) publishGitHubStatus(run model.Run) {
	if s.GitHubToken == "" || run.RepoFullName == "" || run.SHA == "" {
		return
	}
	state := "pending"
	desc := string(run.Status)
	switch {
	case run.Status == model.StatusSuccess:
		state = "success"
		desc = "pipeline succeeded"
	case run.Status == model.StatusSkipped:
		state = "success"
		desc = "pipeline skipped"
	case run.Status == model.StatusCancelled:
		state = "error"
		desc = "pipeline cancelled"
	case run.Status == model.StatusFailure || run.Status == model.StatusBlocked:
		state = "failure"
		desc = "pipeline failed"
	case run.Status == model.StatusRunning:
		desc = "pipeline running"
	case run.Status == model.StatusWaitingApproval:
		desc = "waiting for approval"
	}
	target := ""
	if s.ExternalURL != "" {
		target = s.ExternalURL + "/?run=" + run.ID
	}
	body, err := json.Marshal(map[string]any{
		"state":       state,
		"description": "kiwi: " + desc,
		"context":     "kiwi",
		"target_url":  target,
	})
	if err != nil {
		return
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/statuses/%s", run.RepoFullName, run.SHA)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+s.GitHubToken)
	req.Header.Set("Content-Type", "application/json")
	client := NoRedirectClient(&http.Client{Timeout: 15 * time.Second})
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

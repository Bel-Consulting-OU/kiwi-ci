package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kiwici/kiwi/internal/policy"
)

type githubRepo struct {
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
}

type githubPush struct {
	Ref        string     `json:"ref"`
	After      string     `json:"after"`
	Deleted    bool       `json:"deleted"`
	Repository githubRepo `json:"repository"`
}

type githubPullRequest struct {
	Action      string     `json:"action"`
	Number      int        `json:"number"`
	Repository  githubRepo `json:"repository"`
	PullRequest struct {
		Head struct {
			SHA  string     `json:"sha"`
			Ref  string     `json:"ref"`
			Repo githubRepo `json:"repo"`
		} `json:"head"`
		Base struct {
			SHA  string     `json:"sha"`
			Ref  string     `json:"ref"`
			Repo githubRepo `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
}

func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if s.GitHubWebhookSecret == "" {
		http.Error(w, "GitHub webhook secret is not configured", http.StatusServiceUnavailable)
		return
	}
	if !verifyGitHubSignature(s.GitHubWebhookSecret, r.Header.Get("X-Hub-Signature-256"), body) {
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	switch event {
	case "ping":
		w.WriteHeader(http.StatusNoContent)
		return
	case "push":
		var p githubPush
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, "bad push payload", 400)
			return
		}
		if p.Deleted {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		content, err := s.fetchGitHubFile(r.Context(), p.Repository.FullName, s.pipelinePath(), p.After)
		if err != nil {
			http.Error(w, "fetch pipeline: "+err.Error(), 502)
			return
		}
		run, err := s.enqueue(SubmitRun{RepoURL: p.Repository.CloneURL, Ref: p.Ref, SHA: p.After, Event: "push", Pipeline: content, Trusted: true})
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, http.StatusAccepted, run)
		return
	case "pull_request":
		var p githubPullRequest
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, "bad pull_request payload", 400)
			return
		}
		if !map[string]bool{"opened": true, "reopened": true, "synchronize": true, "ready_for_review": true}[p.Action] {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		trusted := p.PullRequest.Head.Repo.FullName == p.PullRequest.Base.Repo.FullName
		pipelineSHA := p.PullRequest.Head.SHA
		if !trusted {
			pipelineSHA = p.PullRequest.Base.SHA
		}
		content, err := s.fetchGitHubFile(r.Context(), p.PullRequest.Base.Repo.FullName, s.pipelinePath(), pipelineSHA)
		if err != nil {
			http.Error(w, "fetch pipeline: "+err.Error(), 502)
			return
		}
		in := SubmitRun{RepoURL: p.PullRequest.Head.Repo.CloneURL, Ref: p.PullRequest.Head.Ref, SHA: p.PullRequest.Head.SHA, Event: "pull_request", Pipeline: content, Trusted: trusted}
		run, err := s.enqueue(in)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, http.StatusAccepted, run)
		return
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func verifyGitHubSignature(secret, header string, body []byte) bool {
	if !strings.HasPrefix(header, "sha256=") {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

func (s *Server) pipelinePath() string {
	if s.PipelinePath == "" {
		return ".kiwi/pipeline.yaml"
	}
	return s.PipelinePath
}

func (s *Server) fetchGitHubFile(ctx context.Context, repo, path, ref string) (string, error) {
	u := "https://api.github.com/repos/" + repo + "/contents/" + strings.TrimPrefix(path, "/") + "?ref=" + url.QueryEscape(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.GitHubToken)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("GitHub API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var v struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	if v.Encoding != "base64" {
		return "", fmt.Errorf("unsupported GitHub content encoding %q", v.Encoding)
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(v.Content, "\n", ""))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

var _ = policy.ValidateAdmission

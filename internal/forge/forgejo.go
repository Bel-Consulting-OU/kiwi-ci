package forge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultForgejoBase = "https://codeberg.org"

// Forgejo implements Forge for Forgejo/Gitea instances. Webhook payloads
// and signatures mirror GitHub (HMAC X-Hub-Signature-256); the REST API
// lives under /api/v1 and is structurally GitHub-like.
type Forgejo struct {
	// Secret is the webhook HMAC secret.
	Secret string
	// Token is the API token (fallback: KIWI_FORGEJO_TOKEN).
	Token string
	// BaseURL is the instance root (default https://codeberg.org).
	BaseURL string
	Client  *http.Client
}

func (f *Forgejo) apiBase() string {
	if f.BaseURL != "" {
		return strings.TrimRight(f.BaseURL, "/") + "/api/v1"
	}
	return defaultForgejoBase + "/api/v1"
}

func (f *Forgejo) httpClient() *http.Client {
	if f.Client != nil {
		return NoRedirectClient(f.Client)
	}
	return NoRedirectClient(&http.Client{Timeout: 20 * time.Second})
}

func (f *Forgejo) apiToken() string {
	if f.Token != "" {
		return f.Token
	}
	return os.Getenv("KIWI_FORGEJO_TOKEN")
}

func (f *Forgejo) VerifyWebhook(body []byte, signatureOrToken string, headers http.Header) error {
	if !VerifyHMACSignature(signatureOrToken, headers.Get("X-Hub-Signature-256"), body) {
		return fmt.Errorf("invalid webhook signature")
	}
	return nil
}

// Forgejo webhook payloads are GitHub-shaped, so parsing reuses the GitHub
// payload structs with the forge field overridden.
func (f *Forgejo) ParseEvent(body []byte) (EventContext, error) {
	var probe struct {
		PullRequest json.RawMessage `json:"pull_request"`
		Ref         string          `json:"ref"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return EventContext{}, err
	}
	var ec EventContext
	if len(probe.PullRequest) > 0 && string(probe.PullRequest) != "null" {
		var p githubPullRequestPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return EventContext{}, err
		}
		if p.Action == "" {
			return EventContext{}, nil
		}
		base := repoFromGitHub(p.Repository, "forgejo")
		head := repoFromGitHub(p.PullRequest.Head.Repo, "forgejo")
		if head.FullName == "" {
			head = base
		}
		ec = EventContext{
			Forge:          "forgejo",
			Event:          "pull_request",
			Action:         p.Action,
			Ref:            p.PullRequest.Head.Ref,
			BaseRef:        p.PullRequest.Base.Ref,
			HeadSHA:        p.PullRequest.Head.SHA,
			BaseSHA:        p.PullRequest.Base.SHA,
			Repository:     base,
			HeadRepository: head,
			Trusted:        head.FullName == base.FullName,
			Draft:          p.PullRequest.Draft,
		}
		return ec, nil
	}
	if probe.Ref == "" {
		return EventContext{}, nil
	}
	var p githubPushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return EventContext{}, err
	}
	ec = EventContext{
		Forge:      "forgejo",
		Event:      "push",
		Ref:        p.Ref,
		HeadSHA:    p.After,
		BaseSHA:    p.Before,
		Trusted:    true,
		Repository: repoFromGitHub(p.Repository, "forgejo"),
	}
	ec.HeadRepository = ec.Repository
	if p.Deleted || allZerosSHA(p.After) {
		ec.HeadSHA = ""
	}
	if strings.HasPrefix(p.Ref, "refs/tags/") {
		ec.Tag = strings.TrimPrefix(p.Ref, "refs/tags/")
	}
	return ec, nil
}

func (f *Forgejo) FetchFile(ctx context.Context, repoFullName, path, ref string) (string, error) {
	u := f.apiBase() + "/repos/" + repoFullName + "/contents/" + strings.TrimPrefix(path, "/") + "?ref=" + url.QueryEscape(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if tok := f.apiToken(); tok != "" {
		req.Header.Set("Authorization", "token "+tok)
	}
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBodyBytes))
		return "", fmt.Errorf("Forgejo API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var v struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPipelineJSONBytes)).Decode(&v); err != nil {
		return "", err
	}
	if v.Encoding != "base64" {
		return "", fmt.Errorf("unsupported Forgejo content encoding %q", v.Encoding)
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(v.Content, "\n", ""))
	if err != nil {
		return "", err
	}
	if len(b) > maxFetchFileBytes {
		return "", fmt.Errorf("Forgejo file exceeds %d byte limit", maxFetchFileBytes)
	}
	return string(b), nil
}

// Forgejo compare mirrors GitHub: pages of 100, hard cap at 300 files. A
// complete list is only claimed when pagination terminated on a short
// page.
func (f *Forgejo) ChangedFiles(ctx context.Context, ec EventContext) (ChangedFilesResult, error) {
	if ec.HeadSHA == "" || ec.BaseSHA == "" || ec.Repository.FullName == "" {
		return ChangedFilesResult{}, nil
	}
	files := make([]string, 0, githubComparePerPage)
	for page := 1; page <= githubCompareMaxPages; page++ {
		u := fmt.Sprintf("%s/repos/%s/compare/%s...%s?per_page=%d&page=%d",
			f.apiBase(), ec.Repository.FullName, url.PathEscape(ec.BaseSHA), url.PathEscape(ec.HeadSHA), githubComparePerPage, page)
		pageFiles, pageFull, err := f.changedFilesPage(ctx, ec.Repository.FullName, u)
		if err != nil {
			return ChangedFilesResult{}, err
		}
		files = append(files, pageFiles...)
		if !pageFull {
			return ChangedFilesResult{Files: files, Complete: true}, nil
		}
	}
	return ChangedFilesResult{Files: files, Complete: false}, nil
}

func (f *Forgejo) changedFilesPage(ctx context.Context, repoFullName, u string) ([]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	if tok := f.apiToken(); tok != "" {
		req.Header.Set("Authorization", "token "+tok)
	}
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBodyBytes))
		return nil, false, fmt.Errorf("Forgejo compare API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var v struct {
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiffResponseBytes)).Decode(&v); err != nil {
		return nil, false, err
	}
	files := make([]string, 0, len(v.Files))
	for _, file := range v.Files {
		files = append(files, file.Filename)
	}
	return files, len(files) == githubComparePerPage, nil
}

// PublishCheck falls back to a commit status (Forgejo's check-run support
// is partial); annotations are dropped.
func (f *Forgejo) PublishCheck(ctx context.Context, repoFullName, sha, name, status, conclusion, detailsURL, summary string, _ []CheckAnnotation) error {
	if repoFullName == "" || sha == "" {
		return fmt.Errorf("missing repo or sha for status publish")
	}
	state := "pending"
	switch {
	case status == "in_progress":
		state = "pending"
	case status == "completed":
		switch conclusion {
		case "success", "skipped", "neutral":
			state = "success"
		case "failure":
			state = "failure"
		case "cancelled":
			state = "error"
		}
	}
	body, err := json.Marshal(map[string]any{
		"state":       state,
		"context":     "Kiwi / " + name,
		"description": summary,
		"target_url":  detailsURL,
	})
	if err != nil {
		return err
	}
	u := f.apiBase() + "/repos/" + repoFullName + "/statuses/" + url.PathEscape(sha)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := f.apiToken(); tok != "" {
		req.Header.Set("Authorization", "token "+tok)
	}
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Forgejo statuses API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (f *Forgejo) CloneCredentialFor(_ string) (string, bool) {
	if t := f.apiToken(); t != "" {
		return t, true
	}
	return "", false
}

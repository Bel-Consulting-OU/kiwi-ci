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

const defaultGitHubAPI = "https://api.github.com"

// GitHub implements Forge for github.com (and GitHub Enterprise with a
// custom BaseURL).
type GitHub struct {
	// Secret is the webhook HMAC secret (X-Hub-Signature-256).
	Secret string
	// Token is a PAT or installation token override for API calls. When
	// empty, App (if set) and then KIWI_GITHUB_TOKEN are used.
	Token string
	// App, when set, provides installation tokens for API calls.
	App *App
	// BaseURL is the API base (default https://api.github.com).
	BaseURL string
	// Client is the HTTP client (default: 20s timeout, no redirects).
	Client *http.Client
}

func (g *GitHub) apiBase() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/")
	}
	return defaultGitHubAPI
}

func (g *GitHub) httpClient() *http.Client {
	if g.Client != nil {
		return NoRedirectClient(g.Client)
	}
	return NoRedirectClient(&http.Client{Timeout: 20 * time.Second})
}

// authToken resolves the API token: explicit token, App installation token
// for the repository, or the KIWI_GITHUB_TOKEN environment variable.
func (g *GitHub) authToken(ctx context.Context, repoFullName string) (string, error) {
	if g.Token != "" {
		return g.Token, nil
	}
	if g.App != nil && repoFullName != "" {
		return g.App.TokenFor(ctx, repoFullName)
	}
	if t := os.Getenv("KIWI_GITHUB_TOKEN"); t != "" {
		return t, nil
	}
	return "", nil
}

func (g *GitHub) VerifyWebhook(body []byte, signatureOrToken string, headers http.Header) error {
	if !VerifyHMACSignature(signatureOrToken, headers.Get("X-Hub-Signature-256"), body) {
		return fmt.Errorf("invalid webhook signature")
	}
	return nil
}

// TokenFor resolves an API token for the repository (explicit token, App
// installation token, or environment fallback). Empty string means no
// token is available.
func (g *GitHub) TokenFor(ctx context.Context, repoFullName string) (string, error) {
	return g.authToken(ctx, repoFullName)
}

type githubRepoPayload struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
}

type githubPushPayload struct {
	Ref        string            `json:"ref"`
	Before     string            `json:"before"`
	After      string            `json:"after"`
	Deleted    bool              `json:"deleted"`
	Repository githubRepoPayload `json:"repository"`
}

type githubPullRequestPayload struct {
	Action      string            `json:"action"`
	Number      int               `json:"number"`
	Repository  githubRepoPayload `json:"repository"`
	PullRequest struct {
		Draft bool `json:"draft"`
		Head  struct {
			SHA  string            `json:"sha"`
			Ref  string            `json:"ref"`
			Repo githubRepoPayload `json:"repo"`
		} `json:"head"`
		Base struct {
			SHA  string            `json:"sha"`
			Ref  string            `json:"ref"`
			Repo githubRepoPayload `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
}

func (g *GitHub) ParseEvent(body []byte) (EventContext, error) {
	var probe struct {
		PullRequest json.RawMessage `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return EventContext{}, err
	}
	if len(probe.PullRequest) > 0 && string(probe.PullRequest) != "null" {
		return g.parsePullRequest(body)
	}
	return g.parsePush(body)
}

func (g *GitHub) parsePush(body []byte) (EventContext, error) {
	var p githubPushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return EventContext{}, err
	}
	if p.Ref == "" {
		return EventContext{}, nil
	}
	ec := EventContext{
		Forge:      "github",
		Event:      "push",
		Ref:        p.Ref,
		HeadSHA:    p.After,
		BaseSHA:    p.Before,
		Trusted:    true,
		Repository: repoFromGitHub(p.Repository, "github"),
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

func (g *GitHub) parsePullRequest(body []byte) (EventContext, error) {
	var p githubPullRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return EventContext{}, err
	}
	if p.Action == "" {
		return EventContext{}, nil
	}
	base := repoFromGitHub(p.Repository, "github")
	head := repoFromGitHub(p.PullRequest.Head.Repo, "github")
	if head.FullName == "" {
		head = base
	}
	return EventContext{
		Forge:          "github",
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
	}, nil
}

func (g *GitHub) FetchFile(ctx context.Context, repoFullName, path, ref string) (string, error) {
	u := g.apiBase() + "/repos/" + repoFullName + "/contents/" + strings.TrimPrefix(path, "/") + "?ref=" + url.QueryEscape(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if tok, err := g.authToken(ctx, repoFullName); err != nil {
		return "", err
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBodyBytes))
		return "", fmt.Errorf("GitHub API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var v struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPipelineJSONBytes)).Decode(&v); err != nil {
		return "", err
	}
	if v.Encoding != "base64" {
		return "", fmt.Errorf("unsupported GitHub content encoding %q", v.Encoding)
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(v.Content, "\n", ""))
	if err != nil {
		return "", err
	}
	if len(b) > maxFetchFileBytes {
		return "", fmt.Errorf("GitHub file exceeds %d byte limit", maxFetchFileBytes)
	}
	return string(b), nil
}

type githubComparePayload struct {
	Files []struct {
		Filename string `json:"filename"`
	} `json:"files"`
}

// GitHub caps compare-API diffs at 300 files; pages are fetched 100 at a
// time. A complete list is only claimed when pagination terminated on a
// short page, so exactly-300-file diffs are conservatively incomplete.
const (
	githubComparePerPage  = 100
	githubCompareMaxPages = 3
)

func (g *GitHub) ChangedFiles(ctx context.Context, ec EventContext) (ChangedFilesResult, error) {
	if ec.HeadSHA == "" || ec.BaseSHA == "" || ec.Repository.FullName == "" {
		return ChangedFilesResult{}, nil
	}
	files := make([]string, 0, githubComparePerPage)
	for page := 1; page <= githubCompareMaxPages; page++ {
		u := fmt.Sprintf("%s/repos/%s/compare/%s...%s?per_page=%d&page=%d",
			g.apiBase(), ec.Repository.FullName, url.PathEscape(ec.BaseSHA), url.PathEscape(ec.HeadSHA), githubComparePerPage, page)
		pageFiles, pageFull, err := g.changedFilesPage(ctx, ec.Repository.FullName, u)
		if err != nil {
			return ChangedFilesResult{}, err
		}
		files = append(files, pageFiles...)
		if !pageFull {
			return ChangedFilesResult{Files: files, Complete: true}, nil
		}
	}
	// Three full pages: the API truncates compare diffs at 300 files, so
	// the list may be incomplete.
	return ChangedFilesResult{Files: files, Complete: false}, nil
}

func (g *GitHub) changedFilesPage(ctx context.Context, repoFullName, u string) ([]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok, err := g.authToken(ctx, repoFullName); err != nil {
		return nil, false, err
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBodyBytes))
		return nil, false, fmt.Errorf("GitHub compare API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var v githubComparePayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiffResponseBytes)).Decode(&v); err != nil {
		return nil, false, err
	}
	files := make([]string, 0, len(v.Files))
	for _, f := range v.Files {
		files = append(files, f.Filename)
	}
	return files, len(files) == githubComparePerPage, nil
}

// PublishCheck creates or updates the "Kiwi / <name>" check run for sha.
// external_id is derived deterministically from the sha and name so that
// re-publishing the same run (or re-running the same commit) updates the
// existing check run instead of duplicating it.
func (g *GitHub) PublishCheck(ctx context.Context, repoFullName, sha, name, status, conclusion, detailsURL, summary string, annotations []CheckAnnotation) error {
	if repoFullName == "" || sha == "" {
		return fmt.Errorf("missing repo or sha for check publish")
	}
	externalID := "kiwi-" + shortSHA(sha) + "-" + slug(name)
	output := map[string]any{"title": "Kiwi / " + name, "summary": summary}
	if len(annotations) > 0 {
		output["annotations"] = annotations
	}
	body := map[string]any{
		"name":        "Kiwi / " + name,
		"head_sha":    sha,
		"status":      status,
		"external_id": externalID,
		"output":      output,
	}
	if detailsURL != "" {
		body["details_url"] = detailsURL
	}
	if status == "completed" {
		body["conclusion"] = conclusion
		now := time.Now().UTC().Format(time.RFC3339)
		body["completed_at"] = now
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := g.apiBase() + "/repos/" + repoFullName + "/check-runs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	if tok, err := g.authToken(ctx, repoFullName); err != nil {
		return err
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GitHub check-runs API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (g *GitHub) CloneCredentialFor(_ string) (string, bool) {
	if g.Token != "" {
		return g.Token, true
	}
	if t := os.Getenv("KIWI_GITHUB_TOKEN"); t != "" {
		return t, true
	}
	return "", false
}

func repoFromGitHub(r githubRepoPayload, forge string) Repository {
	return Repository{Forge: forge, ID: fmt.Sprintf("%d", r.ID), FullName: r.FullName, CloneURL: r.CloneURL, DefaultBranch: r.DefaultBranch}
}

func allZerosSHA(sha string) bool {
	if sha == "" {
		return false
	}
	for _, c := range sha {
		if c != '0' {
			return false
		}
	}
	return true
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func slug(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return "pipeline"
	}
	return s
}

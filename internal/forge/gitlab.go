package forge

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultGitLabBase = "https://gitlab.com"

// GitLab implements Forge for GitLab (gitlab.com or self-managed with a
// custom BaseURL). Webhook authentication is a plain secret token compared
// constant-time against X-GitLab-Token.
type GitLab struct {
	// SecretToken is the configured webhook secret token.
	SecretToken string
	// Token is the API token (fallback: KIWI_GITLAB_TOKEN).
	Token string
	// BaseURL is the GitLab instance root (default https://gitlab.com).
	BaseURL string
	Client  *http.Client
}

func (g *GitLab) apiBase() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/") + "/api/v4"
	}
	return defaultGitLabBase + "/api/v4"
}

func (g *GitLab) httpClient() *http.Client {
	if g.Client != nil {
		return NoRedirectClient(g.Client)
	}
	return NoRedirectClient(&http.Client{Timeout: 20 * time.Second})
}

func (g *GitLab) apiToken() string {
	if g.Token != "" {
		return g.Token
	}
	return os.Getenv("KIWI_GITLAB_TOKEN")
}

func (g *GitLab) VerifyWebhook(body []byte, signatureOrToken string, headers http.Header) error {
	if signatureOrToken == "" {
		return fmt.Errorf("webhook token is not configured")
	}
	got := headers.Get("X-GitLab-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(signatureOrToken)) != 1 {
		return fmt.Errorf("invalid webhook token")
	}
	return nil
}

type gitLabProjectPayload struct {
	ID                int64  `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
	HTTPURLToRepo     string `json:"http_url_to_repo"`
	WebURL            string `json:"web_url"`
}

type gitLabPushPayload struct {
	ObjectKind  string               `json:"object_kind"`
	Ref         string               `json:"ref"`
	Before      string               `json:"before"`
	After       string               `json:"after"`
	CheckoutSHA string               `json:"checkout_sha"`
	Project     gitLabProjectPayload `json:"project"`
	Repository  struct {
		Name       string `json:"name"`
		GitHTTPURL string `json:"git_http_url"`
		Homepage   string `json:"homepage"`
	} `json:"repository"`
}

type gitLabMergeRequestPayload struct {
	ObjectKind string               `json:"object_kind"`
	Project    gitLabProjectPayload `json:"project"`
	Attributes struct {
		ID           int64  `json:"iid"`
		Action       string `json:"action"`
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
		Draft        bool   `json:"draft"`
		WIP          bool   `json:"work_in_progress"`
		Source       struct {
			PathWithNamespace string `json:"path_with_namespace"`
			DefaultBranch     string `json:"default_branch"`
			GitHTTPURL        string `json:"git_http_url"`
			HTTPURLToRepo     string `json:"http_url_to_repo"`
		} `json:"source"`
		Target struct {
			PathWithNamespace string `json:"path_with_namespace"`
			DefaultBranch     string `json:"default_branch"`
			GitHTTPURL        string `json:"git_http_url"`
			HTTPURLToRepo     string `json:"http_url_to_repo"`
		} `json:"target"`
		LastCommit struct {
			ID string `json:"id"`
		} `json:"last_commit"`
		DiffRefs struct {
			BaseSHA  string `json:"base_sha"`
			HeadSHA  string `json:"head_sha"`
			StartSHA string `json:"start_sha"`
		} `json:"diff_refs"`
	} `json:"object_attributes"`
}

// gitLabActionMap normalizes GitLab MR action names to GitHub-style
// activity types where both exist.
var gitLabActionMap = map[string]string{
	"open":   "opened",
	"update": "synchronize",
	"reopen": "reopened",
}

func (g *GitLab) ParseEvent(body []byte) (EventContext, error) {
	var probe struct {
		ObjectKind string `json:"object_kind"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return EventContext{}, err
	}
	switch probe.ObjectKind {
	case "push", "tag_push":
		return g.parsePush(body, probe.ObjectKind == "tag_push")
	case "merge_request":
		return g.parseMergeRequest(body)
	default:
		return EventContext{}, nil
	}
}

func (g *GitLab) parsePush(body []byte, tagPush bool) (EventContext, error) {
	var p gitLabPushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return EventContext{}, err
	}
	if p.Ref == "" {
		return EventContext{}, nil
	}
	cloneURL := p.Repository.GitHTTPURL
	if cloneURL == "" {
		cloneURL = p.Project.HTTPURLToRepo
	}
	head := p.CheckoutSHA
	if head == "" {
		head = p.After
	}
	ec := EventContext{
		Forge:      "gitlab",
		Event:      "push",
		Ref:        p.Ref,
		HeadSHA:    head,
		BaseSHA:    p.Before,
		Trusted:    true,
		Repository: Repository{Forge: "gitlab", ID: fmt.Sprintf("%d", p.Project.ID), FullName: p.Project.PathWithNamespace, CloneURL: cloneURL, DefaultBranch: p.Project.DefaultBranch},
	}
	ec.HeadRepository = ec.Repository
	if tagPush || strings.HasPrefix(p.Ref, "refs/tags/") {
		ec.Tag = strings.TrimPrefix(p.Ref, "refs/tags/")
	}
	if allZerosSHA(head) {
		ec.HeadSHA = ""
	}
	return ec, nil
}

func (g *GitLab) parseMergeRequest(body []byte) (EventContext, error) {
	var p gitLabMergeRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return EventContext{}, err
	}
	if p.Attributes.Action == "" {
		return EventContext{}, nil
	}
	action := p.Attributes.Action
	if mapped, ok := gitLabActionMap[action]; ok {
		action = mapped
	}
	base := Repository{Forge: "gitlab", FullName: p.Project.PathWithNamespace, DefaultBranch: p.Project.DefaultBranch, ID: fmt.Sprintf("%d", p.Project.ID), CloneURL: p.Project.HTTPURLToRepo}
	head := Repository{Forge: "gitlab", FullName: p.Attributes.Source.PathWithNamespace, CloneURL: firstNonEmpty(p.Attributes.Source.GitHTTPURL, p.Attributes.Source.HTTPURLToRepo), DefaultBranch: p.Attributes.Source.DefaultBranch}
	if head.FullName == "" {
		head = base
	}
	headSHA := p.Attributes.LastCommit.ID
	if headSHA == "" {
		headSHA = p.Attributes.DiffRefs.HeadSHA
	}
	baseSHA := p.Attributes.DiffRefs.BaseSHA
	if baseSHA == "" {
		baseSHA = p.Attributes.DiffRefs.StartSHA
	}
	return EventContext{
		Forge:          "gitlab",
		Event:          "merge_request",
		Action:         action,
		Ref:            p.Attributes.SourceBranch,
		BaseRef:        p.Attributes.TargetBranch,
		HeadSHA:        headSHA,
		BaseSHA:        baseSHA,
		Repository:     base,
		HeadRepository: head,
		Trusted:        head.FullName == base.FullName,
		Draft:          p.Attributes.Draft || p.Attributes.WIP,
	}, nil
}

func (g *GitLab) FetchFile(ctx context.Context, repoFullName, path, ref string) (string, error) {
	u := g.apiBase() + "/projects/" + url.QueryEscape(repoFullName) + "/repository/files/" + url.PathEscape(strings.TrimPrefix(path, "/")) + "/raw?ref=" + url.QueryEscape(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if tok := g.apiToken(); tok != "" {
		req.Header.Set("PRIVATE-TOKEN", tok)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBodyBytes))
		return "", fmt.Errorf("GitLab API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxFetchFileBytes {
		return "", fmt.Errorf("GitLab file exceeds %d byte limit", maxFetchFileBytes)
	}
	return string(b), nil
}

type gitLabComparePayload struct {
	Diffs []struct {
		NewPath string `json:"new_path"`
		OldPath string `json:"old_path"`
	} `json:"diffs"`
}

// GitLab compare paginates diffs (per_page up to 100). A complete list is
// claimed only when pagination terminates on a short page; a 4xx (unknown
// refs, private repo, ...) means the diff is not available and yields an
// incomplete result instead of an error.
const gitLabComparePerPage = 100

func (g *GitLab) ChangedFiles(ctx context.Context, ec EventContext) (ChangedFilesResult, error) {
	if ec.HeadSHA == "" || ec.BaseSHA == "" || ec.Repository.FullName == "" {
		return ChangedFilesResult{}, nil
	}
	files := make([]string, 0, gitLabComparePerPage)
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/projects/%s/repository/compare?from=%s&to=%s&per_page=%d&page=%d",
			g.apiBase(), url.QueryEscape(ec.Repository.FullName), url.QueryEscape(ec.BaseSHA), url.QueryEscape(ec.HeadSHA), gitLabComparePerPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return ChangedFilesResult{}, err
		}
		if tok := g.apiToken(); tok != "" {
			req.Header.Set("PRIVATE-TOKEN", tok)
		}
		resp, err := g.httpClient().Do(req)
		if err != nil {
			return ChangedFilesResult{}, err
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			resp.Body.Close()
			return ChangedFilesResult{Files: files, Complete: false}, nil
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBodyBytes))
			resp.Body.Close()
			return ChangedFilesResult{}, fmt.Errorf("GitLab compare API %s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
		var v gitLabComparePayload
		err = json.NewDecoder(io.LimitReader(resp.Body, maxDiffResponseBytes)).Decode(&v)
		resp.Body.Close()
		if err != nil {
			return ChangedFilesResult{}, err
		}
		for _, d := range v.Diffs {
			name := d.NewPath
			if name == "" {
				name = d.OldPath
			}
			files = append(files, name)
		}
		if len(v.Diffs) < gitLabComparePerPage {
			return ChangedFilesResult{Files: files, Complete: true}, nil
		}
	}
}

// PublishCheck falls back to a commit status: GitLab has no check-runs
// equivalent. Annotations are dropped.
func (g *GitLab) PublishCheck(ctx context.Context, repoFullName, sha, name, status, conclusion, detailsURL, summary string, _ []CheckAnnotation) error {
	if repoFullName == "" || sha == "" {
		return fmt.Errorf("missing repo or sha for status publish")
	}
	state := "pending"
	if status == "in_progress" {
		state = "running"
	} else if status == "completed" {
		switch conclusion {
		case "success", "skipped", "neutral":
			state = "success"
		case "cancelled":
			state = "canceled"
		case "failure":
			state = "failed"
		}
	}
	body, err := json.Marshal(map[string]any{
		"state":       state,
		"name":        "Kiwi / " + name,
		"description": summary,
		"target_url":  detailsURL,
	})
	if err != nil {
		return err
	}
	u := g.apiBase() + "/projects/" + url.QueryEscape(repoFullName) + "/statuses/" + url.PathEscape(sha)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := g.apiToken(); tok != "" {
		req.Header.Set("PRIVATE-TOKEN", tok)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GitLab statuses API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (g *GitLab) CloneCredentialFor(_ string) (string, bool) {
	if t := g.apiToken(); t != "" {
		return t, true
	}
	return "", false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

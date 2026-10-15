package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultBitbucketAPI = "https://api.bitbucket.org/2.0"

// Bitbucket implements Forge for Bitbucket Cloud. Webhooks are verified
// with a shared token header (X-Hub-Signature is not Bitbucket's scheme;
// Bitbucket signs with X-Hub-Signature HMAC-SHA256 when configured, and
// also supports a simple token — both are accepted).
type Bitbucket struct {
	// Secret is the webhook HMAC secret (X-Hub-Signature). When empty the
	// Token header check is used instead.
	Secret string
	// Token is an app password / API token for API calls.
	Token string
	// Username is the Bitbucket username for basic auth with Token.
	Username string
	// BaseURL is the API base (default https://api.bitbucket.org/2.0).
	BaseURL string
	// Client is the HTTP client (default: 20s timeout, no redirects).
	Client *http.Client
}

func (b *Bitbucket) apiBase() string {
	if b.BaseURL != "" {
		return strings.TrimRight(b.BaseURL, "/")
	}
	return defaultBitbucketAPI
}

func (b *Bitbucket) httpClient() *http.Client {
	if b.Client != nil {
		return NoRedirectClient(b.Client)
	}
	return NoRedirectClient(&http.Client{Timeout: 20 * time.Second})
}

func (b *Bitbucket) VerifyWebhook(body []byte, signatureOrToken string, headers http.Header) error {
	// Prefer HMAC when a secret is configured (X-Hub-Signature-256).
	if b.Secret != "" || signatureOrToken != "" {
		secret := b.Secret
		if secret == "" {
			secret = signatureOrToken
		}
		if VerifyHMACSignature(secret, headers.Get("X-Hub-Signature-256"), body) {
			return nil
		}
		// Bitbucket also sends X-Hub-Signature (sha256=) and a raw
		// X-Event-Key + token header style. Fall through to token compare.
		if tok := headers.Get("X-Hub-Signature"); VerifyHMACSignature(secret, tok, body) {
			return nil
		}
	}
	// Token header fallback: X-Request-Token or Authorization bearer.
	want := b.Secret
	if want == "" {
		want = signatureOrToken
	}
	if want != "" {
		if got := headers.Get("X-Request-Token"); got != "" && got == want {
			return nil
		}
		if auth := headers.Get("Authorization"); auth == "Bearer "+want {
			return nil
		}
	}
	return fmt.Errorf("invalid webhook signature")
}

// ParseEvent normalizes a Bitbucket push/pull-request payload.
func (b *Bitbucket) ParseEvent(body []byte) (EventContext, error) {
	var env struct {
		Push    *bitbucketPush `json:"push"`
		PullReq *bitbucketPR   `json:"pullrequest"`
		Repo    bitbucketRepo  `json:"repository"`
		Actor   struct {
			Username string `json:"username"`
		} `json:"actor"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return EventContext{}, fmt.Errorf("parse bitbucket payload: %w", err)
	}
	repo := Repository{Forge: "bitbucket", FullName: env.Repo.FullName}
	if env.Push != nil && len(env.Push.Changes) > 0 {
		ch := env.Push.Changes[0]
		sha := ""
		ref := ""
		if ch.New != nil {
			sha = ch.New.Target.Hash
			ref = ch.New.Name
		}
		if sha == "" && ch.Old != nil {
			sha = ch.Old.Target.Hash
			ref = ch.Old.Name
		}
		return EventContext{
			Forge:          "bitbucket",
			Event:          "push",
			Ref:            ref,
			HeadSHA:        sha,
			Repository:     repo,
			HeadRepository: repo,
		}, nil
	}
	if env.PullReq != nil {
		srcRef := "refs/heads/" + env.PullReq.Source.Branch.Name
		dstRef := "refs/heads/" + env.PullReq.Destination.Branch.Name
		return EventContext{
			Forge:          "bitbucket",
			Event:          "pull_request",
			Action:         env.PullReq.State,
			Ref:            srcRef,
			BaseRef:        dstRef,
			HeadSHA:        env.PullReq.Source.Commit.Hash,
			BaseSHA:        env.PullReq.Destination.Commit.Hash,
			PullRequest:    env.PullReq.ID,
			Repository:     repo,
			HeadRepository: repo,
		}, nil
	}
	return EventContext{}, nil
}

type bitbucketPush struct {
	Changes []struct {
		Old *struct {
			Name   string `json:"name"`
			Target struct {
				Hash string `json:"hash"`
			} `json:"target"`
		} `json:"old"`
		New *struct {
			Name   string `json:"name"`
			Target struct {
				Hash string `json:"hash"`
			} `json:"target"`
		} `json:"new"`
	} `json:"changes"`
}

type bitbucketPR struct {
	ID     int    `json:"id"`
	State  string `json:"state"`
	Author struct {
		Username string `json:"username"`
	} `json:"author"`
	Source struct {
		Branch struct {
			Name string `json:"name"`
		} `json:"branch"`
		Commit struct {
			Hash string `json:"hash"`
		} `json:"commit"`
	} `json:"source"`
	Destination struct {
		Branch struct {
			Name string `json:"name"`
		} `json:"branch"`
		Commit struct {
			Hash string `json:"hash"`
		} `json:"commit"`
	} `json:"destination"`
}

type bitbucketRepo struct {
	FullName string `json:"full_name"`
	Scm      string `json:"scm"`
}

func (b *Bitbucket) do(ctx context.Context, method, urlStr string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return nil, err
	}
	if b.Token != "" {
		if b.Username != "" {
			req.SetBasicAuth(b.Username, b.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+b.Token)
		}
	}
	resp, err := b.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrFileNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("bitbucket %s %s: HTTP %d", method, urlStr, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func (b *Bitbucket) FetchFile(ctx context.Context, repoFullName, path, ref string) (string, error) {
	q := url.Values{}
	if ref != "" {
		q.Set("at", ref)
	}
	u := fmt.Sprintf("%s/repositories/%s/src/%s/%s", b.apiBase(), repoFullName, ref, strings.TrimPrefix(path, "/"))
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	raw, err := b.do(ctx, "GET", u)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (b *Bitbucket) ChangedFiles(ctx context.Context, ec EventContext) (ChangedFilesResult, error) {
	if ec.PullRequest == 0 {
		// Push: without a PR number we report incomplete so path filters
		// fail closed rather than guess a diff.
		return ChangedFilesResult{Complete: false}, nil
	}
	u := fmt.Sprintf("%s/repositories/%s/pullrequests/%d/diffstat?pagelen=100", b.apiBase(), ec.Repository.FullName, ec.PullRequest)
	raw, err := b.do(ctx, "GET", u)
	if err != nil {
		return ChangedFilesResult{}, err
	}
	var doc struct {
		Values []struct {
			New struct {
				Path string `json:"path"`
			} `json:"new"`
			Old struct {
				Path string `json:"path"`
			} `json:"old"`
		} `json:"values"`
		Next string `json:"next"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ChangedFilesResult{}, err
	}
	seen := map[string]bool{}
	var files []string
	for _, v := range doc.Values {
		for _, p := range []string{v.New.Path, v.Old.Path} {
			if p != "" && !seen[p] {
				seen[p] = true
				files = append(files, p)
			}
		}
	}
	// Pagination: a truncated diffstat must NEVER report Complete — include-
	// path triggers fail closed on an incomplete list.
	complete := doc.Next == ""
	return ChangedFilesResult{Files: files, Complete: complete}, nil
}

func (b *Bitbucket) PublishCheck(ctx context.Context, repoFullName, sha, name, status, conclusion, detailsURL, summary string, annotations []CheckAnnotation) error {
	// Bitbucket Cloud commit statuses use a build-status API.
	state := "INPROGRESS"
	switch conclusion {
	case "success":
		state = "SUCCESSFUL"
	case "failure", "timed_out", "cancelled":
		state = "FAILED"
	}
	payload := map[string]any{
		"key":         name,
		"state":       state,
		"name":        name,
		"description": summary,
		"url":         detailsURL,
	}
	raw, _ := json.Marshal(payload)
	u := fmt.Sprintf("%s/repositories/%s/commit/%s/statuses/build", b.apiBase(), repoFullName, sha)
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if b.Token != "" {
		if b.Username != "" {
			req.SetBasicAuth(b.Username, b.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+b.Token)
		}
	}
	resp, err := b.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("bitbucket publish status: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (b *Bitbucket) CloneCredentialFor(repoFullName string) (string, bool) {
	if b.Token == "" {
		return "", false
	}
	user := b.Username
	if user == "" {
		user = "x-token-auth"
	}
	return user + ":" + b.Token, true
}

// ResolveRevision returns the full commit SHA for a ref via the commit API.
func (b *Bitbucket) ResolveRevision(ctx context.Context, repoFullName, ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", fmt.Errorf("resolve revision: empty ref")
	}
	raw, err := b.do(ctx, "GET", fmt.Sprintf("%s/repositories/%s/commit/%s", b.apiBase(), repoFullName, url.QueryEscape(ref)))
	if err != nil {
		return "", err
	}
	var v struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	if v.Hash == "" {
		return "", fmt.Errorf("resolve revision %q: empty SHA", ref)
	}
	return v.Hash, nil
}

// TokenFor resolves the API token (env fallback KIWI_BITBUCKET_TOKEN).
func (b *Bitbucket) TokenFor() string {
	if b.Token != "" {
		return b.Token
	}
	return os.Getenv("KIWI_BITBUCKET_TOKEN")
}

// compile-time conformance
var _ Forge = (*Bitbucket)(nil)

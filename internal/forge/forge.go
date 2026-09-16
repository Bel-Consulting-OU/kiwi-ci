// Package forge abstracts GitHub, GitLab and Forgejo integrations for the
// Kiwi control plane: webhook verification and parsing, file/changed-file
// fetching, status publishing, and trigger matching against a pipeline's
// `on` section.
package forge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Repository is the minimal forge repository coordinate needed by the
// control plane. FullName is the canonical owner/name pair used for policy
// and status publishing.
type Repository struct {
	Forge         string `json:"forge"`
	ID            string `json:"id,omitempty"`
	FullName      string `json:"full_name"`
	CloneURL      string `json:"clone_url,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

// EventContext is the normalized view of one webhook event. Repository is
// always the canonical (base) repository; HeadRepository is the repository
// whose code will actually be checked out (a fork on cross-repo PRs).
type EventContext struct {
	Forge          string
	Event          string     // push, pull_request, merge_request, ...
	Action         string     // opened, synchronize, reopened, ...
	Ref            string     // full ref, e.g. refs/heads/main
	BaseRef        string     // base ref for PR/MR events
	HeadSHA        string     // commit to check out
	BaseSHA        string     // base commit (fork PRs: canonical pipeline revision)
	Repository     Repository // base repository (canonical coordinates)
	HeadRepository Repository // repository to clone
	Trusted        bool
	Draft          bool
	Tag            string   // tag name when Ref is refs/tags/...
	ChangedFiles   []string // server-fetched list when available
}

// CheckAnnotation is one annotation attached to a GitHub check run output.
type CheckAnnotation struct {
	Path    string `json:"path"`
	Line    int    `json:"start_line,omitempty"`
	Level   string `json:"annotation_level"` // notice | warning | failure
	Title   string `json:"title,omitempty"`
	Message string `json:"message"`
}

// ChangedFilesResult is the outcome of a changed-files fetch.
type ChangedFilesResult struct {
	// Files is the list of files changed between the event's base and
	// head commits.
	Files []string
	// Complete is true only when Files is the authoritative full diff:
	// not truncated, not a pagination-limited partial view, not a
	// fallback. Trigger evaluation with include-path filters must fail
	// closed when Complete is false.
	Complete bool
}

// Forge is the integration surface for one forge. Implementations must be
// safe for concurrent use.
type Forge interface {
	// VerifyWebhook authenticates a webhook delivery. signatureOrToken is
	// the configured secret (HMAC secret for GitHub/Forgejo, plain token
	// for GitLab); headers carry the forge-specific verification header.
	VerifyWebhook(body []byte, signatureOrToken string, headers http.Header) error
	// ParseEvent normalizes one delivery body into an EventContext. Events
	// the forge does not model (or ignored actions) yield Event=="".
	ParseEvent(body []byte) (EventContext, error)
	// FetchFile returns a raw file's contents at ref.
	FetchFile(ctx context.Context, repoFullName, path, ref string) (string, error)
	// ChangedFiles lists files changed between the event's base and head
	// commits. Complete reports whether the list is the authoritative
	// full diff; when it is false the caller must not use Files for
	// include-path trigger decisions (fail closed) or treat the list as
	// exhaustive.
	ChangedFiles(ctx context.Context, ec EventContext) (ChangedFilesResult, error)
	// PublishCheck publishes pipeline state. On GitHub this creates or
	// updates a check run; on GitLab/Forgejo it falls back to a commit
	// status. Implementations must be idempotent for identical arguments.
	PublishCheck(ctx context.Context, repoFullName, sha, name, status, conclusion, detailsURL, summary string, annotations []CheckAnnotation) error
	// CloneCredentialFor returns a credential string usable to clone the
	// repository (a token for https://x-access-token:$TOKEN@ URLs), or
	// (false) when the forge exposes no credential.
	CloneCredentialFor(repoFullName string) (string, bool)
}

// VerifyHMACSignature verifies a "sha256=<hex>" HMAC-SHA256 signature
// header against body using constant-time comparison. This is the GitHub
// X-Hub-Signature-256 scheme, shared by Forgejo.
func VerifyHMACSignature(secret, header string, body []byte) bool {
	if secret == "" || !strings.HasPrefix(header, "sha256=") {
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

// NoRedirectClient returns a copy of base that never follows redirects, so
// credential-bearing requests cannot leak Authorization headers to another
// origin. The caller's client is not mutated.
func NoRedirectClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	c := *base
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// Response-size bounds for forge API GETs. Pipeline files are fetched into
// memory wholesale, so 8 MiB caps them; compare (diff) payloads are capped
// at 16 MiB; API error bodies at 4 KiB.
const (
	maxFetchFileBytes    = 8 << 20
	maxPipelineJSONBytes = 16 << 20 // base64-encoded content plus envelope
	maxDiffResponseBytes = 16 << 20
	maxAPIErrorBodyBytes = 4096
)

// MatchesTrigger evaluates a pipeline's `on` section against a webhook
// event. It returns whether the event should enqueue a run and the trigger
// key that matched ("" for the empty-section fallback).
//
// Semantics:
//   - An empty/missing `on` section matches everything (backwards compat).
//   - The event key is ec.Event. A "<event>.<action>" key (e.g.
//     "pull_request.opened") is action-scoped and takes precedence over the
//     bare event key. For merge_request events, "pull_request" is used as a
//     fallback key when no "merge_request" key exists.
//   - Actions: when the matched trigger declares `actions`, the event's
//     action must appear in the list. Matching is canonicalized: exact
//     after case normalization (the forge adapters already normalize
//     forge-specific action names, e.g. GitLab "open" to "opened").
//   - Draft: the matched trigger's `draft` declares the draft stance. nil
//     (unset) admits both draft and non-draft events; false rejects draft
//     events; true admits ONLY draft events. There is no blanket draft
//     rejection.
//   - Ref matching: tag refs (refs/tags/... or ec.Tag != "") are matched
//     against tags/tags_ignore; branch refs against branches/branches_ignore.
//     Patterns are path.Match globs, plus exact equality. A tag ref only
//     matches a trigger with no ref filters or with tag filters configured.
//     For pull_request/merge_request events the branch filters match
//     ec.BaseRef — the TARGET branch the adapters supply — never the head
//     branch; push events match ec.Ref.
//   - Paths: pipeline.PathsMatch over ec.ChangedFiles. With no changed-file
//     data, paths filters cannot be evaluated and are treated as matching
//     (consistent with pipeline.PathsMatch's empty-list behavior).
func MatchesTrigger(triggers map[string]pipeline.Trigger, ec EventContext) (bool, string) {
	if len(triggers) == 0 {
		return true, ""
	}
	key := ec.Event
	if ec.Event == "merge_request" {
		if _, ok := triggers["merge_request"]; !ok {
			if _, ok := triggers["pull_request"]; ok {
				key = "pull_request"
			}
		}
	}
	actionKey := ""
	if ec.Action != "" {
		actionKey = ec.Event + "." + ec.Action
	}
	matched := ""
	var trg pipeline.Trigger
	if _, ok := triggers[actionKey]; actionKey != "" && ok {
		trg = triggers[actionKey]
		matched = actionKey
	} else if t, ok := triggers[key]; ok {
		trg = t
		matched = key
	} else {
		return false, ""
	}
	if len(trg.Actions) > 0 && !matchAction(trg.Actions, ec.Action) {
		return false, ""
	}
	if trg.Draft != nil && *trg.Draft != ec.Draft {
		return false, ""
	}
	tagRef := ec.Tag != "" || strings.HasPrefix(ec.Ref, "refs/tags/")
	if tagRef {
		name := ec.Tag
		if name == "" {
			name = strings.TrimPrefix(ec.Ref, "refs/tags/")
		}
		if len(trg.Tags) == 0 && len(trg.TagsIgnore) == 0 {
			// No tag filters: tag refs only match triggers with no ref
			// filters at all; branch filters never admit tags.
			if len(trg.Branches) > 0 || len(trg.BranchesIgnore) > 0 {
				return false, ""
			}
		} else {
			if len(trg.Tags) > 0 && !matchRefPatterns(name, trg.Tags) {
				return false, ""
			}
			if matchRefPatterns(name, trg.TagsIgnore) {
				return false, ""
			}
		}
	} else {
		// Push branch filters match the pushed ref; PR/MR branch filters
		// match the TARGET branch (ec.BaseRef) the adapters supply.
		branch := strings.TrimPrefix(strings.TrimPrefix(ec.Ref, "refs/heads/"), "refs/")
		if isPullRequestEvent(ec.Event) && ec.BaseRef != "" {
			branch = strings.TrimPrefix(strings.TrimPrefix(ec.BaseRef, "refs/heads/"), "refs/")
		}
		if len(trg.Branches) > 0 && !matchRefPatterns(branch, trg.Branches) {
			return false, ""
		}
		if matchRefPatterns(branch, trg.BranchesIgnore) {
			return false, ""
		}
	}
	if len(trg.Paths) > 0 || len(trg.PathsIgnore) > 0 {
		if !pipeline.PathsMatch(ec.ChangedFiles, trg.Paths, trg.PathsIgnore) {
			return false, ""
		}
	}
	return true, matched
}

func isPullRequestEvent(event string) bool {
	return event == "pull_request" || event == "merge_request"
}

// matchAction reports whether the event's action appears in the trigger's
// action list. Matching is canonicalized: exact after case normalization and
// trimming (the adapters already map forge-specific action names onto the
// canonical GitHub-style set).
func matchAction(actions []string, action string) bool {
	if action == "" {
		return false
	}
	for _, a := range actions {
		if strings.EqualFold(strings.TrimSpace(a), action) {
			return true
		}
	}
	return false
}

func matchRefPatterns(name string, patterns []string) bool {
	for _, ptn := range patterns {
		ptn = strings.TrimSpace(ptn)
		if ptn == "" {
			continue
		}
		if ptn == name {
			return true
		}
		if ok, err := path.Match(ptn, name); err == nil && ok {
			return true
		}
	}
	return false
}

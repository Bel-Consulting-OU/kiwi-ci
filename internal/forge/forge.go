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
	Tag            string // tag name when Ref is refs/tags/...
	// ChangedFiles is the changed-file diff for this event together with
	// its completeness. It is part of the matching contract: include-path
	// triggers never match unless Complete is true, so the matcher cannot
	// be evaluated fail-open by a caller that leaves the diff unknown.
	ChangedFiles ChangedFilesResult
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

// ReasonChangedFilesIncomplete is the MatchResult.Reason reported when a
// trigger declaring include-path filters (`paths`) cannot be evaluated
// because EventContext.ChangedFiles is not the authoritative complete diff.
// Matching fails closed in that case: the trigger does not match and the
// caller must not enqueue a run.
const ReasonChangedFilesIncomplete = "changed files incomplete: include-path trigger not evaluated"

// MatchResult is the detailed outcome of EvaluateTrigger. Reason is
// non-empty only for a fail-closed non-match (ReasonChangedFilesIncomplete);
// callers log it and must not enqueue a run.
type MatchResult struct {
	Matched bool
	Key     string
	Reason  string
}

// MatchesTrigger evaluates a pipeline's `on` section against a webhook
// event. It returns whether the event should enqueue a run and the trigger
// key that matched ("" for the empty-section fallback). It is the
// convenience form of EvaluateTrigger, which additionally reports the
// fail-closed reason for path-filtered triggers evaluated against an
// incomplete changed-file diff.
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
//     matches a trigger with no ref filters or with tag filters configured,
//     and symmetrically a branch ref only matches a trigger with no ref
//     filters or with branch filters configured: a tags-only trigger never
//     admits a branch push, a branches-only trigger never admits a tag push.
//     For pull_request/merge_request events the branch filters match
//     ec.BaseRef — the TARGET branch the adapters supply — never the head
//     branch; push events match ec.Ref.
//   - Paths: include-path filters (`paths`) are fail-closed. They evaluate
//     pipeline.PathsMatch over ec.ChangedFiles.Files only when
//     ec.ChangedFiles.Complete is true; a partial, truncated, fallback or
//     unknown diff never matches, even when it happens to contain a
//     matching path (EvaluateTrigger reports
//     ReasonChangedFilesIncomplete). `paths_ignore` alone is deliberately
//     best-effort: it is evaluated against whatever ec.ChangedFiles.Files
//     is present, so an unknown or empty diff admits the event rather than
//     silently skipping work on incomplete data, while a diff that does
//     contain an ignored path still rejects it.
func MatchesTrigger(triggers map[string]pipeline.Trigger, ec EventContext) (bool, string) {
	res := EvaluateTrigger(triggers, ec)
	return res.Matched, res.Key
}

// EvaluateTrigger evaluates MatchesTrigger's semantics and additionally
// reports the fail-closed reason. Reason is non-empty only when a trigger
// with include-path filters matched every non-path rule but the changed-file
// diff is not authoritative (ReasonChangedFilesIncomplete); Matched is false
// in that case and the caller must not enqueue.
func EvaluateTrigger(triggers map[string]pipeline.Trigger, ec EventContext) MatchResult {
	if len(triggers) == 0 {
		return MatchResult{Matched: true}
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
		return MatchResult{}
	}
	if len(trg.Actions) > 0 && !matchAction(trg.Actions, ec.Action) {
		return MatchResult{}
	}
	if trg.Draft != nil && *trg.Draft != ec.Draft {
		return MatchResult{}
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
				return MatchResult{}
			}
		} else {
			if len(trg.Tags) > 0 && !matchRefPatterns(name, trg.Tags) {
				return MatchResult{}
			}
			if matchRefPatterns(name, trg.TagsIgnore) {
				return MatchResult{}
			}
		}
	} else {
		// Push branch filters match the pushed ref; PR/MR branch filters
		// match the TARGET branch (ec.BaseRef) the adapters supply.
		branch := strings.TrimPrefix(strings.TrimPrefix(ec.Ref, "refs/heads/"), "refs/")
		if isPullRequestEvent(ec.Event) && ec.BaseRef != "" {
			branch = strings.TrimPrefix(strings.TrimPrefix(ec.BaseRef, "refs/heads/"), "refs/")
		}
		// A trigger that declares only tag filters is tag-scoped: a branch
		// ref must not match it, symmetric with the branch-only rejection
		// of tag refs above.
		if len(trg.Branches) == 0 && len(trg.BranchesIgnore) == 0 && (len(trg.Tags) > 0 || len(trg.TagsIgnore) > 0) {
			return MatchResult{}
		}
		if len(trg.Branches) > 0 && !matchRefPatterns(branch, trg.Branches) {
			return MatchResult{}
		}
		if matchRefPatterns(branch, trg.BranchesIgnore) {
			return MatchResult{}
		}
	}
	if len(trg.Paths) > 0 {
		// Include-path filters are fail-closed: without an authoritative
		// complete diff the trigger cannot be evaluated, so it must not
		// match. This invariant lives here, not in a caller wrapper.
		if !ec.ChangedFiles.Complete {
			return MatchResult{Reason: ReasonChangedFilesIncomplete}
		}
		if !pipeline.PathsMatch(ec.ChangedFiles.Files, trg.Paths, trg.PathsIgnore) {
			return MatchResult{}
		}
	} else if len(trg.PathsIgnore) > 0 {
		// Deliberate best-effort override: an ignore-only trigger is
		// evaluated against whatever diff is present. An unknown or empty
		// diff cannot prove an ignored path changed, so the event is
		// admitted; a visible ignored path still rejects it.
		if !pipeline.PathsMatch(ec.ChangedFiles.Files, nil, trg.PathsIgnore) {
			return MatchResult{}
		}
	}
	return MatchResult{Matched: true, Key: matched}
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

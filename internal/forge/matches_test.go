package forge

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func boolPtr(b bool) *bool { return &b }

func TestMatchesTrigger(t *testing.T) {
	pushMain := EventContext{Event: "push", Ref: "refs/heads/main", Trusted: true}
	pushFeature := EventContext{Event: "push", Ref: "refs/heads/feature/x", Trusted: true}
	pushTag := EventContext{Event: "push", Ref: "refs/tags/v1.0.0", Tag: "v1.0.0", Trusted: true}
	prOpened := EventContext{Event: "pull_request", Action: "opened", Ref: "refs/heads/feature/x", BaseRef: "main", ChangedFiles: []string{"src/main.go"}}
	prSyncDocs := EventContext{Event: "pull_request", Action: "synchronize", Ref: "refs/heads/feature/x", BaseRef: "main", ChangedFiles: []string{"docs/a.md"}}
	prSyncNoFiles := EventContext{Event: "pull_request", Action: "synchronize", Ref: "refs/heads/feature/x", BaseRef: "main"}
	prDraft := EventContext{Event: "pull_request", Action: "opened", Ref: "refs/heads/feature/x", BaseRef: "main", Draft: true}
	mrOpened := EventContext{Event: "merge_request", Action: "opened", Ref: "feature/x", BaseRef: "main"}

	cases := []struct {
		name     string
		triggers map[string]pipeline.Trigger
		ec       EventContext
		want     bool
		wantKey  string
	}{
		{name: "no triggers allows", triggers: nil, ec: pushMain, want: true, wantKey: ""},
		{name: "empty triggers allows", triggers: map[string]pipeline.Trigger{}, ec: prOpened, want: true, wantKey: ""},
		{name: "unknown event rejected", triggers: map[string]pipeline.Trigger{"push": {}}, ec: prOpened, want: false},
		{name: "push main exact branch", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}}}, ec: pushMain, want: true, wantKey: "push"},
		{name: "push glob branch", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"feature/*"}}}, ec: pushFeature, want: true, wantKey: "push"},
		{name: "push branch mismatch", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"release/*"}}}, ec: pushFeature, want: false},
		{name: "push branch ignored", triggers: map[string]pipeline.Trigger{"push": {BranchesIgnore: []string{"feature/*"}}}, ec: pushFeature, want: false},
		{name: "push branch not ignored", triggers: map[string]pipeline.Trigger{"push": {BranchesIgnore: []string{"release/*"}}}, ec: pushFeature, want: true, wantKey: "push"},
		{name: "tag push without tag filters rejected", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}}}, ec: pushTag, want: false},
		{name: "tag push matches tags", triggers: map[string]pipeline.Trigger{"push": {Tags: []string{"v*"}}}, ec: pushTag, want: true, wantKey: "push"},
		{name: "tag push ignored", triggers: map[string]pipeline.Trigger{"push": {TagsIgnore: []string{"v1.*"}}}, ec: pushTag, want: false},
		{name: "tag push no filters", triggers: map[string]pipeline.Trigger{"push": {}}, ec: pushTag, want: true, wantKey: "push"},
		{name: "pr paths match", triggers: map[string]pipeline.Trigger{"pull_request": {Paths: []string{"src/**"}}}, ec: prOpened, want: true, wantKey: "pull_request"},
		{name: "pr paths mismatch", triggers: map[string]pipeline.Trigger{"pull_request": {Paths: []string{"src/**"}}}, ec: prSyncDocs, want: false},
		{name: "pr paths_ignore", triggers: map[string]pipeline.Trigger{"pull_request": {PathsIgnore: []string{"docs/**"}}}, ec: prSyncDocs, want: false},
		{name: "pr paths with no files cannot match include", triggers: map[string]pipeline.Trigger{"pull_request": {Paths: []string{"src/**"}}}, ec: prSyncNoFiles, want: false},
		{name: "pr paths_ignore with no files matches", triggers: map[string]pipeline.Trigger{"pull_request": {PathsIgnore: []string{"docs/**"}}}, ec: prSyncNoFiles, want: true, wantKey: "pull_request"},
		{name: "pr action scoped", triggers: map[string]pipeline.Trigger{"pull_request.opened": {Branches: []string{"main"}}}, ec: prOpened, want: true, wantKey: "pull_request.opened"},
		{name: "pr action scoped mismatch", triggers: map[string]pipeline.Trigger{"pull_request.opened": {}}, ec: prSyncDocs, want: false},
		{name: "pr action scoped falls back to bare key", triggers: map[string]pipeline.Trigger{"pull_request": {}, "pull_request.opened": {}}, ec: prSyncDocs, want: true, wantKey: "pull_request"},
		{name: "draft pr allowed when draft unset", triggers: map[string]pipeline.Trigger{"pull_request": {}}, ec: prDraft, want: true, wantKey: "pull_request"},
		{name: "draft pr rejected when draft false", triggers: map[string]pipeline.Trigger{"pull_request": {Draft: boolPtr(false)}}, ec: prDraft, want: false},
		{name: "non-draft pr rejected when draft true", triggers: map[string]pipeline.Trigger{"pull_request": {Draft: boolPtr(true)}}, ec: prOpened, want: false},
		{name: "draft pr admitted when draft true", triggers: map[string]pipeline.Trigger{"pull_request": {Draft: boolPtr(true)}}, ec: prDraft, want: true, wantKey: "pull_request"},
		{name: "non-draft pr allowed when draft false", triggers: map[string]pipeline.Trigger{"pull_request": {Draft: boolPtr(false)}}, ec: prOpened, want: true, wantKey: "pull_request"},
		{name: "merge_request falls back to pull_request", triggers: map[string]pipeline.Trigger{"pull_request": {}}, ec: mrOpened, want: true, wantKey: "pull_request"},
		{name: "merge_request own key wins", triggers: map[string]pipeline.Trigger{"pull_request": {}, "merge_request": {Branches: []string{"main"}}}, ec: mrOpened, want: true, wantKey: "merge_request"},
		{name: "branch ignore exact", triggers: map[string]pipeline.Trigger{"push": {BranchesIgnore: []string{"main"}}}, ec: pushMain, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, key := MatchesTrigger(tc.triggers, tc.ec)
			if ok != tc.want || key != tc.wantKey {
				t.Fatalf("MatchesTrigger = (%v, %q), want (%v, %q)", ok, key, tc.want, tc.wantKey)
			}
		})
	}
}

// TestMatchesTriggerCrossForge drives the PR/MR semantics against the exact
// EventContext shapes the three forge adapters produce: GitHub and Forgejo
// carry "pull_request" events with head refs in Ref and the target branch in
// BaseRef; GitLab carries "merge_request" events with the source branch in
// Ref and the target branch in BaseRef, plus GitLab-native action names
// normalized to the canonical set by the adapter.
func TestMatchesTriggerCrossForge(t *testing.T) {
	githubPR := EventContext{Forge: "github", Event: "pull_request", Action: "opened", Ref: "refs/heads/feature/x", BaseRef: "main", Draft: false}
	forgejoPR := EventContext{Forge: "forgejo", Event: "pull_request", Action: "synchronize", Ref: "feature/x", BaseRef: "develop"}
	gitlabMR := EventContext{Forge: "gitlab", Event: "merge_request", Action: "opened", Ref: "ms-viewport", BaseRef: "main"}
	githubPush := EventContext{Forge: "github", Event: "push", Ref: "refs/heads/main"}

	cases := []struct {
		name     string
		triggers map[string]pipeline.Trigger
		ec       EventContext
		want     bool
		wantKey  string
	}{
		// Branch-on-base-ref: PR/MR branch filters match the TARGET branch
		// even though Ref carries the head/source branch.
		{name: "github pr branch matches base ref", triggers: map[string]pipeline.Trigger{"pull_request": {Branches: []string{"main"}}}, ec: githubPR, want: true, wantKey: "pull_request"},
		{name: "github pr branch ignores head ref", triggers: map[string]pipeline.Trigger{"pull_request": {Branches: []string{"feature/x"}}}, ec: githubPR, want: false},
		{name: "forgejo pr branch matches base ref", triggers: map[string]pipeline.Trigger{"pull_request": {Branches: []string{"develop"}}}, ec: forgejoPR, want: true, wantKey: "pull_request"},
		{name: "forgejo pr branches_ignore matches base ref", triggers: map[string]pipeline.Trigger{"pull_request": {BranchesIgnore: []string{"develop"}}}, ec: forgejoPR, want: false},
		{name: "gitlab mr branch matches target branch", triggers: map[string]pipeline.Trigger{"merge_request": {Branches: []string{"main"}}}, ec: gitlabMR, want: true, wantKey: "merge_request"},
		{name: "gitlab mr branch ignores source branch", triggers: map[string]pipeline.Trigger{"merge_request": {Branches: []string{"ms-viewport"}}}, ec: gitlabMR, want: false},
		{name: "gitlab mr glob on target branch", triggers: map[string]pipeline.Trigger{"merge_request": {Branches: []string{"ma*"}}}, ec: gitlabMR, want: true, wantKey: "merge_request"},
		{name: "push branch matches ref not base", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}}}, ec: githubPush, want: true, wantKey: "push"},

		// Action matching: canonicalized (exact, case-normalized) against
		// the adapter-normalized action set.
		{name: "github action exact", triggers: map[string]pipeline.Trigger{"pull_request": {Actions: []string{"opened", "synchronize"}}}, ec: githubPR, want: true, wantKey: "pull_request"},
		{name: "github action mismatch", triggers: map[string]pipeline.Trigger{"pull_request": {Actions: []string{"synchronize", "reopened"}}}, ec: githubPR, want: false},
		{name: "forgejo action case-normalized", triggers: map[string]pipeline.Trigger{"pull_request": {Actions: []string{"SYNCHRONIZE"}}}, ec: forgejoPR, want: true, wantKey: "pull_request"},
		{name: "forgejo action whitespace trimmed", triggers: map[string]pipeline.Trigger{"pull_request": {Actions: []string{" synchronize "}}}, ec: forgejoPR, want: true, wantKey: "pull_request"},
		{name: "gitlab canonicalized action matches", triggers: map[string]pipeline.Trigger{"merge_request": {Actions: []string{"opened"}}}, ec: gitlabMR, want: true, wantKey: "merge_request"},
		{name: "gitlab raw action name does not match", triggers: map[string]pipeline.Trigger{"merge_request": {Actions: []string{"open"}}}, ec: gitlabMR, want: false},
		{name: "push action filter empty action", triggers: map[string]pipeline.Trigger{"push": {Actions: []string{"opened"}}}, ec: githubPush, want: false},

		// Draft: nil admits both, false rejects drafts, true admits only
		// drafts — no blanket rejection.
		{name: "github draft nil admits draft", triggers: map[string]pipeline.Trigger{"pull_request": {}}, ec: EventContext{Forge: "github", Event: "pull_request", Action: "opened", Ref: "feature/x", BaseRef: "main", Draft: true}, want: true, wantKey: "pull_request"},
		{name: "github draft nil admits non-draft", triggers: map[string]pipeline.Trigger{"pull_request": {}}, ec: githubPR, want: true, wantKey: "pull_request"},
		{name: "github draft false rejects draft", triggers: map[string]pipeline.Trigger{"pull_request": {Draft: boolPtr(false)}}, ec: EventContext{Forge: "github", Event: "pull_request", Action: "opened", Ref: "feature/x", BaseRef: "main", Draft: true}, want: false},
		{name: "github draft false admits non-draft", triggers: map[string]pipeline.Trigger{"pull_request": {Draft: boolPtr(false)}}, ec: githubPR, want: true, wantKey: "pull_request"},
		{name: "github draft true admits draft", triggers: map[string]pipeline.Trigger{"pull_request": {Draft: boolPtr(true)}}, ec: EventContext{Forge: "github", Event: "pull_request", Action: "opened", Ref: "feature/x", BaseRef: "main", Draft: true}, want: true, wantKey: "pull_request"},
		{name: "github draft true rejects non-draft", triggers: map[string]pipeline.Trigger{"pull_request": {Draft: boolPtr(true)}}, ec: githubPR, want: false},
		{name: "gitlab draft false rejects draft", triggers: map[string]pipeline.Trigger{"merge_request": {Draft: boolPtr(false)}}, ec: EventContext{Forge: "gitlab", Event: "merge_request", Action: "opened", Ref: "ms-viewport", BaseRef: "main", Draft: true}, want: false},
		{name: "gitlab draft true admits draft", triggers: map[string]pipeline.Trigger{"merge_request": {Draft: boolPtr(true)}}, ec: EventContext{Forge: "gitlab", Event: "merge_request", Action: "opened", Ref: "ms-viewport", BaseRef: "main", Draft: true}, want: true, wantKey: "merge_request"},
		{name: "forgejo draft nil admits draft", triggers: map[string]pipeline.Trigger{"pull_request": {}}, ec: EventContext{Forge: "forgejo", Event: "pull_request", Action: "opened", Ref: "feature/x", BaseRef: "main", Draft: true}, want: true, wantKey: "pull_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, key := MatchesTrigger(tc.triggers, tc.ec)
			if ok != tc.want || key != tc.wantKey {
				t.Fatalf("MatchesTrigger = (%v, %q), want (%v, %q)", ok, key, tc.want, tc.wantKey)
			}
		})
	}
}

package forge

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

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
		{name: "pr action scoped", triggers: map[string]pipeline.Trigger{"pull_request.opened": {Branches: []string{"feature/*"}}}, ec: prOpened, want: true, wantKey: "pull_request.opened"},
		{name: "pr action scoped mismatch", triggers: map[string]pipeline.Trigger{"pull_request.opened": {}}, ec: prSyncDocs, want: false},
		{name: "pr action scoped falls back to bare key", triggers: map[string]pipeline.Trigger{"pull_request": {}, "pull_request.opened": {}}, ec: prSyncDocs, want: true, wantKey: "pull_request"},
		{name: "draft pr skipped", triggers: map[string]pipeline.Trigger{"pull_request": {}}, ec: prDraft, want: false},
		{name: "merge_request falls back to pull_request", triggers: map[string]pipeline.Trigger{"pull_request": {}}, ec: mrOpened, want: true, wantKey: "pull_request"},
		{name: "merge_request own key wins", triggers: map[string]pipeline.Trigger{"pull_request": {}, "merge_request": {Branches: []string{"main"}}}, ec: mrOpened, want: false},
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

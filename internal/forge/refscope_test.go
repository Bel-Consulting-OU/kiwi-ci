package forge

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestMatchesTriggerRefScopeCrossForge locks the ref-axis scoping fixed in
// MatchesTrigger: a trigger that declares only tag filters is tag-scoped and
// must not admit a branch push, and a trigger that declares only branch
// filters is branch-scoped and must not admit a tag push. The same rules hold
// across the forge-specific EventContext shapes.
func TestMatchesTriggerRefScopeCrossForge(t *testing.T) {
	branchPushes := map[string]EventContext{
		"github":  {Forge: "github", Event: "push", Ref: "refs/heads/main"},
		"forgejo": {Forge: "forgejo", Event: "push", Ref: "main"},
		"gitlab":  {Forge: "gitlab", Event: "push", Ref: "refs/heads/main"},
	}
	tagPushes := map[string]EventContext{
		"github":  {Forge: "github", Event: "push", Ref: "refs/tags/v1.0.0", Tag: "v1.0.0"},
		"forgejo": {Forge: "forgejo", Event: "push", Ref: "refs/tags/v1.0.0", Tag: "v1.0.0"},
		"gitlab":  {Forge: "gitlab", Event: "push", Ref: "refs/tags/v1.0.0", Tag: "v1.0.0"},
	}

	cases := []struct {
		name     string
		triggers map[string]pipeline.Trigger
		ec       EventContext
		want     bool
	}{
		// tags-only: branch pushes rejected on every forge, tag pushes admitted.
		{name: "tags-only rejects branch push", triggers: map[string]pipeline.Trigger{"push": {Tags: []string{"v*"}}}, ec: branchPushes["github"], want: false},
		{name: "tags-only rejects branch push forgejo", triggers: map[string]pipeline.Trigger{"push": {Tags: []string{"v*"}}}, ec: branchPushes["forgejo"], want: false},
		{name: "tags-only rejects branch push gitlab", triggers: map[string]pipeline.Trigger{"push": {Tags: []string{"v*"}}}, ec: branchPushes["gitlab"], want: false},
		{name: "tags-only admits matching tag push", triggers: map[string]pipeline.Trigger{"push": {Tags: []string{"v*"}}}, ec: tagPushes["github"], want: true},
		{name: "tags-only rejects non-matching tag push", triggers: map[string]pipeline.Trigger{"push": {Tags: []string{"release-*"}}}, ec: tagPushes["forgejo"], want: false},
		{name: "tags_ignore-only rejects branch push", triggers: map[string]pipeline.Trigger{"push": {TagsIgnore: []string{"v1.*"}}}, ec: branchPushes["github"], want: false},
		{name: "tags_ignore-only rejects ignored tag push", triggers: map[string]pipeline.Trigger{"push": {TagsIgnore: []string{"v1.*"}}}, ec: tagPushes["gitlab"], want: false},

		// branches-only: tag pushes rejected (already true before), branch
		// pushes admitted.
		{name: "branches-only rejects tag push", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}}}, ec: tagPushes["github"], want: false},
		{name: "branches-only admits branch push", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}}}, ec: branchPushes["forgejo"], want: true},
		{name: "branches_ignore-only admits unignored branch push", triggers: map[string]pipeline.Trigger{"push": {BranchesIgnore: []string{"release/*"}}}, ec: branchPushes["gitlab"], want: true},

		// Both axes: each ref is evaluated only against its own axis.
		{name: "both admits branch on branch axis", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}, Tags: []string{"v*"}}}, ec: branchPushes["github"], want: true},
		{name: "both rejects branch missing on branch axis", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"release/*"}, Tags: []string{"v*"}}}, ec: branchPushes["forgejo"], want: false},
		{name: "both admits tag on tag axis", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}, Tags: []string{"v*"}}}, ec: tagPushes["gitlab"], want: true},
		{name: "both rejects tag missing on tag axis", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}, Tags: []string{"release-*"}}}, ec: tagPushes["github"], want: false},
		{name: "both ignore-only axes stay independent", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}, TagsIgnore: []string{"v1.*"}}}, ec: tagPushes["forgejo"], want: false},
		{name: "both ignore-only admits other tag", triggers: map[string]pipeline.Trigger{"push": {Branches: []string{"main"}, TagsIgnore: []string{"v1.*"}}}, ec: EventContext{Forge: "forgejo", Event: "push", Ref: "refs/tags/v2.0.0", Tag: "v2.0.0"}, want: true},

		// PR/MR events evaluate their target branch against the branch axis:
		// a tags-only trigger never admits them.
		{name: "tags-only rejects github pr", triggers: map[string]pipeline.Trigger{"pull_request": {Tags: []string{"v*"}}}, ec: EventContext{Forge: "github", Event: "pull_request", Action: "opened", Ref: "feature/x", BaseRef: "main"}, want: false},
		{name: "tags-only rejects gitlab mr", triggers: map[string]pipeline.Trigger{"merge_request": {Tags: []string{"v*"}}}, ec: EventContext{Forge: "gitlab", Event: "merge_request", Action: "opened", Ref: "feature/x", BaseRef: "main"}, want: false},
		{name: "branches-only admits github pr", triggers: map[string]pipeline.Trigger{"pull_request": {Branches: []string{"main"}}}, ec: EventContext{Forge: "github", Event: "pull_request", Action: "opened", Ref: "feature/x", BaseRef: "main"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, _ := MatchesTrigger(tc.triggers, tc.ec)
			if ok != tc.want {
				t.Fatalf("MatchesTrigger = %v, want %v", ok, tc.want)
			}
		})
	}
}

// Package trigger owns trigger matching and schedule idempotency. The
// matching semantics mirror forge.MatchesTrigger (which the server still
// calls directly for webhook intake): an empty `on` section matches
// everything, "<event>.<action>" keys take precedence over bare event keys,
// draft PRs never match, ref filters apply to branches or tags, and path
// filters evaluate against the event's changed files.
//
// The duplication with forge.MatchesTrigger is deliberate: forge must not
// import this package (trigger imports forge for EventContext), and the
// server's webhook path keeps using forge.MatchesTrigger. Any semantic
// change must be applied to both; the tests in forge/matches_test.go and
// trigger/trigger_test.go keep them in lockstep.
package trigger

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TriggerSet is the typed form of a pipeline's `on` section.
type TriggerSet map[string]pipeline.Trigger

// Matches evaluates the trigger set against a normalized forge event.
func (t TriggerSet) Matches(ec forge.EventContext) (bool, string) {
	return Matches(t, ec)
}

// Matches evaluates a pipeline's `on` section against a webhook event. It
// returns whether the event should enqueue a run and the trigger key that
// matched ("" for the empty-section fallback). See the package comment for
// the exact semantics.
func Matches(triggers map[string]pipeline.Trigger, ec forge.EventContext) (bool, string) {
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
	if ec.Draft {
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
		branch := strings.TrimPrefix(strings.TrimPrefix(ec.Ref, "refs/heads/"), "refs/")
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

// ScheduleKey returns the stable idempotency key for one nominal schedule
// occurrence: the same schedule ID and nominal time always produce the same
// key, so a scheduler retry cannot enqueue the occurrence twice.
func ScheduleKey(scheduleID string, nominal time.Time) string {
	return fmt.Sprintf("%s@%s", scheduleID, nominal.UTC().Format(time.RFC3339))
}

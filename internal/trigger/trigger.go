// Package trigger owns trigger matching and schedule idempotency. The
// matching semantics mirror forge.MatchesTrigger (which the server still
// calls directly for webhook intake): an empty `on` section matches
// everything, "<event>.<action>" keys take precedence over bare event keys,
// draft PRs never match, ref filters apply to branches or tags, and path
// filters evaluate against the event's changed files.
//
// Matching DELEGATES to forge.MatchesTrigger (the authoritative
// implementation); this package exists so forge never imports trigger.
package trigger

import (
	"fmt"
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
// Matches delegates to forge.MatchesTrigger: the forge package owns the
// authoritative trigger semantics (PR/MR base-ref branch matching,
// canonicalized action matching, draft true/false/nil handling, and path
// filters), and this package must never re-implement them — earlier
// duplication drifted and diverged. trigger imports forge for EventContext
// and forge never imports trigger, so the dependency direction is clean.
func Matches(triggers map[string]pipeline.Trigger, ec forge.EventContext) (bool, string) {
	return forge.MatchesTrigger(triggers, ec)
}

// ScheduleKey returns the stable idempotency key for one nominal schedule
// occurrence: the same schedule ID and nominal time always produce the same
// key, so a scheduler retry cannot enqueue the occurrence twice.
func ScheduleKey(scheduleID string, nominal time.Time) string {
	return fmt.Sprintf("%s@%s", scheduleID, nominal.UTC().Format(time.RFC3339))
}

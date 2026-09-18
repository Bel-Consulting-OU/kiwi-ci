package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// publishGitHubStatus mirrors run state to the forge via the durable
// outbox: one "Kiwi / Pipeline" check plus one per-job check for every
// finished job. It only queues intents and returns immediately, so it is
// safe to call while holding the server lock. Dispatch happens in
// Maintain's flushOutbox tick and is best-effort by design.
// publishForgeStatus is the forge-NEUTRAL completion publication: it fans
// out per-job and pipeline check intents whose kind is chosen from the run's
// persisted forge identity, so GitLab and Forgejo runs publish through their
// own adapters instead of being silently dropped (and never routed to
// GitHub). A run without a forge identity publishes nowhere.
func (s *Server) publishForgeStatus(ctx context.Context, run model.Run) error {
	if run.ForgeKind != "github" && run.ForgeKind != "gitlab" && run.ForgeKind != "forgejo" {
		return nil
	}
	if run.RepoFullName == "" || run.SHA == "" {
		return nil
	}
	// No publishing credential or endpoint for this forge: nothing can be
	// published, so enqueueing would create rows that 401 forever. This is
	// the explicit "publish_status disabled" state (a read-only
	// integration); production startup validation warns when it is implicit.
	if !s.forgePublishingConfigured(run.ForgeKind) {
		return nil
	}
	status, conclusion := checkStateForRun(run.Status)
	summary := "pipeline " + string(run.Status)
	items := []forge.OutboxItem{s.checkIntent(run, "Pipeline", status, conclusion, summary, nil)}
	// Job enumeration must be AUTHORITATIVE in DB mode: the in-memory map
	// is not the source of truth and another replica may run this effect.
	if s.DB != nil {
		jobs, err := s.DB.ListJobsByRun(ctx, run.ID)
		if err != nil {
			return fmt.Errorf("forge status: list jobs: %w", err)
		}
		for _, j := range jobs {
			if !j.Status.Terminal() {
				continue
			}
			jstatus, jconclusion := checkStateForRun(j.Status)
			jsummary := "job " + j.Key + " " + string(j.Status)
			if j.Error != "" {
				jsummary += ": " + j.Error
			}
			items = append(items, s.checkIntent(run, j.Key, jstatus, jconclusion, jsummary, nil))
		}
	} else {
		s.mu.Lock()
		for _, j := range s.jobs {
			if j.RunID != run.ID || !j.Status.Terminal() {
				continue
			}
			jstatus, jconclusion := checkStateForRun(j.Status)
			jsummary := "job " + j.Key + " " + string(j.Status)
			if j.Error != "" {
				jsummary += ": " + j.Error
			}
			items = append(items, s.checkIntent(run, j.Key, jstatus, jconclusion, jsummary, nil))
		}
		s.mu.Unlock()
	}
	// Deterministic order: pipeline first, then jobs by name.
	sort.Slice(items[1:], func(i, j int) bool {
		var a, b forge.CheckPayload
		_ = json.Unmarshal(items[i+1].Payload, &a)
		_ = json.Unmarshal(items[j+1].Payload, &b)
		return a.Name < b.Name
	})
	// Durable-first: every intended row must be recorded before the effect
	// reports success, otherwise the completion effect would be ACKed with
	// forge statuses missing. Every item carries a concrete kind: the
	// forge-kind gate above makes checkIntent's kind selection total.
	for _, it := range items {
		if err := s.outbox.Enqueue(it); err != nil {
			return fmt.Errorf("forge status: enqueue %s: %w", it.Kind, err)
		}
	}
	return nil
}

// forgePublishingConfigured reports whether the control plane holds any
// credential or endpoint for the forge kind.
func (s *Server) forgePublishingConfigured(kind string) bool {
	switch kind {
	case "github":
		return s.GitHubToken != "" || s.GitHubAppID != 0 || s.gitHubAPIBase != ""
	case "gitlab":
		return s.GitLabToken != "" || s.gitLabAPIBase != ""
	case "forgejo":
		return s.ForgejoToken != "" || s.forgejoAPIBase != ""
	}
	return false
}

func (s *Server) checkIntent(run model.Run, name, status, conclusion, summary string, annotations []forge.CheckAnnotation) forge.OutboxItem {
	detailsURL := ""
	if s.ExternalURL != "" {
		detailsURL = s.ExternalURL + "/?run=" + run.ID
	}
	// The LOGICAL key is the stable identity of one remote check
	// (forge host + run + check name); the state version is the rank of the
	// logical state this intent carries. Row identity is key#version, so a
	// newer state never collides with an older one (P1 fix): queued -> running
	// -> completed are DISTINCT outbox rows, each superseding the older
	// pending one.
	logicalKey := forgeCheckLogicalKey(run.ForgeHost, run.ID, name)
	version := checkStateVersion(status)
	payload, err := jsonMarshal(forge.CheckPayload{
		RunID:        run.ID,
		ForgeKind:    run.ForgeKind,
		ForgeHost:    run.ForgeHost,
		RepoFullName: run.RepoFullName,
		SHA:          run.SHA,
		Name:         name,
		Status:       status,
		Conclusion:   conclusion,
		DetailsURL:   detailsURL,
		Summary:      summary,
		Annotations:  annotations,
		LogicalKey:   logicalKey,
		StateVersion: version,
	})
	if err != nil {
		payload = []byte("{}")
	}
	kind := ""
	switch run.ForgeKind {
	case "github":
		kind = forge.OutboxKindGitHubCheck
	case "gitlab":
		kind = forge.OutboxKindGitLabCheck
	case "forgejo":
		kind = forge.OutboxKindForgejoCheck
	}
	return forge.OutboxItem{
		ID:           forgeCheckRowID(logicalKey, version),
		Kind:         kind,
		Payload:      payload,
		LogicalKey:   logicalKey,
		StateVersion: version,
	}
}

// forgeCheckLogicalKey derives the STABLE logical identity of one remote
// check: sha256("forge-check\x00host\x00run\x00name") truncated to the
// canonical 128-bit hex ID. It is the pre-existing deterministic intent
// identity, now used as the logical key that survives across state versions
// (the check-run mapping is still keyed by runID|name, matching this key
// one-to-one for a given run/name pair).
func forgeCheckLogicalKey(forgeHost, runID, name string) string {
	sum := sha256.Sum256([]byte("forge-check\x00" + forgeHost + "\x00" + runID + "\x00" + name))
	return hex.EncodeToString(sum[:16])
}

// forgeCheckRowID is the versioned durable outbox row identity:
// logicalKey + "#" + stateVersion.
func forgeCheckRowID(logicalKey string, version int64) string {
	return logicalKey + "#" + strconv.FormatInt(version, 10)
}

// checkStateVersion ranks the mapped remote check state monotonically:
// queued=1, in_progress=2, completed=3. The rank is derived from the LOGICAL
// state, not from an enqueue counter, so a stale caller re-publishing an
// older state can never supersede a newer delivered one; an unknown state is
// treated as in_progress to match checkStateForRun's default.
func checkStateVersion(checkStatus string) int64 {
	switch checkStatus {
	case "queued":
		return 1
	case "completed":
		return 3
	default:
		return 2
	}
}

// checkStateForRun maps Kiwi run/job statuses onto GitHub check-run
// status/conclusion pairs.
func checkStateForRun(status model.Status) (checkStatus, conclusion string) {
	switch status {
	case model.StatusQueued:
		return "queued", ""
	case model.StatusRunning, model.StatusWaitingApproval, model.StatusPending:
		return "in_progress", ""
	case model.StatusSuccess:
		return "completed", "success"
	case model.StatusSkipped:
		return "completed", "skipped"
	case model.StatusCancelled:
		return "completed", "cancelled"
	case model.StatusFailure, model.StatusBlocked:
		return "completed", "failure"
	default:
		return "in_progress", ""
	}
}

// publishGitHubStatusFromPayload is the legacy commit-status dispatch for
// github_status outbox intents. It posts directly to the GitHub statuses
// API and is kept for intents enqueued by older state or external callers.
func (s *Server) publishGitHubStatusFromPayload(ctx context.Context, p forge.StatusPayload) error {
	if p.RepoFullName == "" || p.SHA == "" {
		return nil
	}
	body, err := jsonMarshal(map[string]any{
		"state":       p.State,
		"description": p.Description,
		"context":     p.Context,
		"target_url":  p.TargetURL,
	})
	if err != nil {
		return err
	}
	url := "https://api.github.com/repos/" + p.RepoFullName + "/statuses/" + p.SHA
	if s.gitHubAPIBase != "" {
		url = s.gitHubAPIBase + "/repos/" + p.RepoFullName + "/statuses/" + p.SHA
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	g := s.gitHubForge()
	if tok, err := g.TokenFor(ctx, p.RepoFullName); err != nil {
		return err
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	client := NoRedirectClient(&http.Client{Timeout: 15 * time.Second})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GitHub statuses API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

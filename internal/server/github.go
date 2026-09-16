package server

import (
	"io"
	"log"
	"net/http"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"go.opentelemetry.io/otel/attribute"
)

// gitHubForge builds the forge adapter from the server's current
// configuration. It is cheap to construct and safe to rebuild per use, so
// late-bound config (webhook secret, tokens, App credentials, test base
// URLs) is always honored.
func (s *Server) gitHubForge() *forge.GitHub {
	g := &forge.GitHub{
		Secret:  s.GitHubWebhookSecret,
		Token:   s.GitHubToken,
		BaseURL: s.gitHubAPIBase,
	}
	if s.GitHubAppID > 0 && s.GitHubAppPrivateKey != "" {
		g.App = forge.NewApp(s.GitHubAppID, []byte(s.GitHubAppPrivateKey))
		g.App.BaseURL = s.gitHubAPIBase
	}
	return g
}

func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, span := s.startSpan(r.Context(), "forge.webhook.github")
	defer span.End()
	span.SetAttributes(attribute.String("kiwi.event", r.Header.Get("X-GitHub-Event")))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if s.GitHubWebhookSecret == "" {
		http.Error(w, "GitHub webhook secret is not configured", http.StatusServiceUnavailable)
		return
	}
	fg := s.gitHubForge()
	if err := fg.VerifyWebhook(body, s.GitHubWebhookSecret, r.Header); err != nil {
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	if event == "ping" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ec, err := fg.ParseEvent(body)
	if err != nil {
		http.Error(w, "bad webhook payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	if ec.Event == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ec.Event == "push" {
		if ec.HeadSHA == "" {
			// Branch/tag deletion.
			w.WriteHeader(http.StatusNoContent)
			return
		}
	} else if ec.Event == "pull_request" {
		switch ec.Action {
		case "opened", "reopened", "synchronize", "ready_for_review":
		default:
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// The base repository is the canonical coordinate for policy and
	// status publishing. Fork PRs fetch the pipeline from the base
	// repository at the base revision (head code is untrusted); the head
	// repository is what gets cloned.
	pipelineSHA := ec.HeadSHA
	if !ec.Trusted {
		pipelineSHA = ec.BaseSHA
	}
	content, err := fg.FetchFile(ctx, ec.Repository.FullName, s.pipelinePath(), pipelineSHA)
	if err != nil {
		http.Error(w, "fetch pipeline: "+err.Error(), http.StatusBadGateway)
		return
	}
	spec, err := pipeline.Parse([]byte(content))
	if err != nil {
		http.Error(w, "parse pipeline: "+err.Error(), http.StatusBadRequest)
		return
	}
	ok, matched, filesKnown, terr := s.evalTriggerMatches(ctx, fg, spec, &ec)
	if terr != nil {
		http.Error(w, terr.Error(), http.StatusBadGateway)
		return
	}
	if !ok {
		// The event does not match the pipeline's on section: acknowledge
		// without enqueueing. Logged so silenced pipelines are discoverable.
		log.Printf("webhook: github %s %s ignored (trigger %q)", ec.Event, ec.Repository.FullName, matched)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Authoritative changed files were populated by evalTriggerMatches
	// before trigger evaluation: the runner is never the source of truth,
	// and include-path triggers fail closed when the list is unobtainable.
	files := ec.ChangedFiles

	delivery := r.Header.Get("X-GitHub-Delivery")
	if delivery != "" {
		if run, ok := s.dedupeRun(delivery, ec.Repository.FullName); ok {
			writeJSON(w, http.StatusOK, run)
			return
		}
	}
	in := SubmitRun{
		RepoURL:           ec.HeadRepository.CloneURL,
		RepoFullName:      ec.Repository.FullName,
		Ref:               ec.Ref,
		SHA:               ec.HeadSHA,
		Event:             ec.Event,
		Pipeline:          content,
		Trusted:           ec.Trusted,
		ChangedFiles:      files,
		ChangedFilesKnown: filesKnown,
		Metadata:          map[string]string{"github_delivery": delivery},
	}
	run, err := s.enqueue(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.recordDelivery(delivery, run.ID)
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) pipelinePath() string {
	if s.PipelinePath == "" {
		return ".kiwi/pipeline.yaml"
	}
	return s.PipelinePath
}

// dedupeRun returns the run already created for a webhook delivery ID, so
// forge retries (which reuse the delivery ID) acknowledge the original run
// instead of enqueueing a duplicate. The stored run must belong to the same
// canonical repository.
func (s *Server) dedupeRun(delivery, repoFullName string) (model.Run, bool) {
	if delivery == "" {
		return model.Run{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.deliveries[delivery]
	if !ok {
		return model.Run{}, false
	}
	run, ok := s.runs[id]
	if !ok {
		return model.Run{}, false
	}
	if repoFullName != "" && run.RepoFullName != repoFullName {
		return model.Run{}, false
	}
	return run, true
}

// recordDelivery remembers a delivery ID after a successful enqueue. The
// authoritative check-and-set lives in enqueue (under the same lock as run
// creation); this call only fills the map for in-memory servers that were
// not routed through the metadata path.
func (s *Server) recordDelivery(delivery, runID string) {
	if delivery == "" {
		return
	}
	s.mu.Lock()
	if _, exists := s.deliveries[delivery]; !exists {
		s.deliveries[delivery] = runID
	}
	s.mu.Unlock()
}

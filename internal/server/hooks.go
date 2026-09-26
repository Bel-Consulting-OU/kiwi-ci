package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// triggerFilesFetch fetches the event's changed-file diff once, before
// trigger evaluation, and attaches the authoritative complete list to the
// event context. The matcher itself owns the fail-closed invariant:
// forge.MatchesTrigger refuses include-path triggers when the attached diff
// is incomplete, so this wrapper no longer inspects the trigger set.
// Incomplete, partial or failed fetches leave the context with an unknown
// diff; non-authoritative partial lists are deliberately not propagated
// downstream. The fetch error is returned so the caller can surface a
// retryable failure when the diff was required.
func (s *Server) triggerFilesFetch(ctx context.Context, fg forge.Forge, ec *forge.EventContext) (forge.ChangedFilesResult, error) {
	res, err := fg.ChangedFiles(ctx, *ec)
	if err != nil {
		ec.ChangedFiles = forge.ChangedFilesResult{}
		return forge.ChangedFilesResult{}, err
	}
	if !res.Complete {
		ec.ChangedFiles = forge.ChangedFilesResult{}
		return res, nil
	}
	ec.ChangedFiles = res
	return res, nil
}

// evalTriggerMatches attaches the changed files (when authoritative),
// evaluates the pipeline trigger, and reports whether the attached list is
// the authoritative complete diff: the enqueue persists it as
// ChangedFilesKnown so the runner never applies a local git fallback over a
// known (possibly empty) server-side list.
//
// forge.MatchesTrigger itself fails closed for include-path triggers on an
// incomplete diff. When that fail-closed reason fires, the webhook answers a
// retryable error so the forge redelivers instead of silently dropping a
// path-filtered event. A fetch failure on a trigger that does not depend on
// the diff is only logged: paths_ignore-only and path-less triggers remain
// best-effort.
func (s *Server) evalTriggerMatches(ctx context.Context, fg forge.Forge, spec *pipeline.Spec, ec *forge.EventContext) (bool, string, bool, error) {
	res, ferr := s.triggerFilesFetch(ctx, fg, ec)
	if ferr != nil {
		log.Printf("webhook: changed files for %s: %v", ec.Repository.FullName, ferr)
	} else if !res.Complete {
		log.Printf("webhook: changed files for %s: incomplete diff", ec.Repository.FullName)
	}
	match := forge.EvaluateTrigger(spec.On, *ec)
	if match.Reason == forge.ReasonChangedFilesIncomplete {
		if ferr != nil {
			return false, "", false, fmt.Errorf("changed files unavailable for path-filtered trigger: %w", ferr)
		}
		return false, "", false, errors.New("changed files incomplete for path-filtered trigger")
	}
	return match.Matched, match.Key, res.Complete, nil
}

func (s *Server) gitLabForge() *forge.GitLab {
	return &forge.GitLab{SecretToken: s.GitLabWebhookSecret, Token: s.GitLabToken, BaseURL: s.gitLabAPIBase}
}

func (s *Server) forgejoForge() *forge.Forgejo {
	return &forge.Forgejo{Secret: s.ForgejoWebhookSecret, Token: s.ForgejoToken, BaseURL: s.forgejoAPIBase}
}

func (s *Server) gitlabWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if s.GitLabWebhookSecret == "" {
		http.Error(w, "GitLab webhook secret is not configured", http.StatusServiceUnavailable)
		return
	}
	fg := s.gitLabForge()
	if err := fg.VerifyWebhook(body, s.GitLabWebhookSecret, r.Header); err != nil {
		http.Error(w, "invalid webhook token", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-Gitlab-Event") == "Ping Hook" {
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
			w.WriteHeader(http.StatusNoContent)
			return
		}
	} else if ec.Event == "merge_request" {
		switch ec.Action {
		case "opened", "reopened", "synchronize":
		default:
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	pipelineSHA := ec.HeadSHA
	if !ec.Trusted {
		pipelineSHA = ec.BaseSHA
	}
	content, err := fg.FetchFile(r.Context(), ec.Repository.FullName, s.pipelinePath(), pipelineSHA)
	if err != nil {
		s.serverError(w, r, http.StatusBadGateway, err, "bad gateway")
		return
	}
	spec, err := pipeline.Parse([]byte(content))
	if err != nil {
		http.Error(w, "parse pipeline: "+err.Error(), http.StatusBadRequest)
		return
	}
	ok, matched, filesKnown, terr := s.evalTriggerMatches(r.Context(), fg, spec, &ec)
	if terr != nil {
		s.serverError(w, r, http.StatusBadGateway, terr, "bad gateway")
		return
	}
	if !ok {
		log.Printf("webhook: gitlab %s %s ignored (trigger %q)", ec.Event, ec.Repository.FullName, matched)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	files := ec.ChangedFiles.Files

	repoID := s.forgeRepoID("gitlab", webhookRepoCoordinate(ec))
	delivery := r.Header.Get("X-GitLab-Event-UUID")
	if delivery != "" {
		if run, ok := s.dedupeRun(delivery, repoID); ok {
			writeJSON(w, http.StatusOK, run)
			return
		}
	}
	checkout := checkoutCloneURL(ec)
	in := SubmitRun{
		RepoID:            repoID,
		PolicyRepoID:      repoID,
		CheckoutRepoURL:   checkout,
		RepoURL:           checkout,
		RepoFullName:      ec.Repository.FullName,
		Ref:               ec.Ref,
		SHA:               ec.HeadSHA,
		Event:             ec.Event,
		Pipeline:          content,
		Trusted:           ec.Trusted,
		ChangedFiles:      files,
		ChangedFilesKnown: filesKnown,
		Metadata:          map[string]string{"gitlab_delivery": delivery},
		identityBound:     true,
	}
	run, err := s.enqueue(r.Context(), in)
	if err != nil {
		// A durability failure is not a client error: answer 503 so the
		// forge retries the delivery instead of treating it as rejected.
		var nd *stateNotDurableError
		if errors.As(err, &nd) {
			s.serverError(w, r, http.StatusServiceUnavailable, nd, "state not durable")
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.recordDelivery(delivery, run.ID)
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) forgejoWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if s.ForgejoWebhookSecret == "" {
		http.Error(w, "Forgejo webhook secret is not configured", http.StatusServiceUnavailable)
		return
	}
	fg := s.forgejoForge()
	if err := fg.VerifyWebhook(body, s.ForgejoWebhookSecret, r.Header); err != nil {
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}
	event := r.Header.Get("X-Forgejo-Event")
	if event == "" {
		event = r.Header.Get("X-Gitea-Event")
	}
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

	pipelineSHA := ec.HeadSHA
	if !ec.Trusted {
		pipelineSHA = ec.BaseSHA
	}
	content, err := fg.FetchFile(r.Context(), ec.Repository.FullName, s.pipelinePath(), pipelineSHA)
	if err != nil {
		s.serverError(w, r, http.StatusBadGateway, err, "bad gateway")
		return
	}
	spec, err := pipeline.Parse([]byte(content))
	if err != nil {
		http.Error(w, "parse pipeline: "+err.Error(), http.StatusBadRequest)
		return
	}
	ok, matched, filesKnown, terr := s.evalTriggerMatches(r.Context(), fg, spec, &ec)
	if terr != nil {
		s.serverError(w, r, http.StatusBadGateway, terr, "bad gateway")
		return
	}
	if !ok {
		log.Printf("webhook: forgejo %s %s ignored (trigger %q)", ec.Event, ec.Repository.FullName, matched)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	files := ec.ChangedFiles.Files

	repoID := s.forgeRepoID("forgejo", webhookRepoCoordinate(ec))
	delivery := r.Header.Get("X-Forgejo-Delivery")
	if delivery != "" {
		if run, ok := s.dedupeRun(delivery, repoID); ok {
			writeJSON(w, http.StatusOK, run)
			return
		}
	}
	checkout := checkoutCloneURL(ec)
	in := SubmitRun{
		RepoID:            repoID,
		PolicyRepoID:      repoID,
		CheckoutRepoURL:   checkout,
		RepoURL:           checkout,
		RepoFullName:      ec.Repository.FullName,
		Ref:               ec.Ref,
		SHA:               ec.HeadSHA,
		Event:             ec.Event,
		Pipeline:          content,
		Trusted:           ec.Trusted,
		ChangedFiles:      files,
		ChangedFilesKnown: filesKnown,
		Metadata:          map[string]string{"forgejo_delivery": delivery},
		identityBound:     true,
	}
	run, err := s.enqueue(r.Context(), in)
	if err != nil {
		var nd *stateNotDurableError
		if errors.As(err, &nd) {
			s.serverError(w, r, http.StatusServiceUnavailable, nd, "state not durable")
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.recordDelivery(delivery, run.ID)
	writeJSON(w, http.StatusAccepted, run)
}

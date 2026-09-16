package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// triggerFilesFetch fetches the authoritative changed-file list BEFORE
// trigger evaluation when the pipeline declares include-path filters:
// matching against an empty or partial list is fail-open. The fetch must
// also be complete: an include-path trigger with a truncated or
// best-effort diff fails the webhook closed. When the pipeline only uses
// paths_ignore the fetch is best-effort — a missing or incomplete list
// cannot wrongly admit an event, because a paths_ignore filter never
// matches an empty list. It returns the files, whether the list is the
// authoritative complete diff, and whether a fetch error must fail the
// webhook closed.
func (s *Server) triggerFilesFetch(ctx context.Context, fg forge.Forge, spec *pipeline.Spec, ec *forge.EventContext) (files []string, complete bool, mustFail error) {
	needsInclude := false
	for _, t := range spec.On {
		if len(t.Paths) > 0 {
			needsInclude = true
			break
		}
	}
	res, err := fg.ChangedFiles(ctx, *ec)
	if err != nil {
		if needsInclude {
			return nil, false, fmt.Errorf("changed files unavailable for path-filtered trigger: %w", err)
		}
		log.Printf("webhook: changed files for %s: %v", ec.Repository.FullName, err)
		return nil, false, nil
	}
	if !res.Complete {
		if needsInclude {
			return nil, false, fmt.Errorf("changed files incomplete for path-filtered trigger")
		}
		// Ignore-only trigger: proceeding without the list is safe — a
		// paths_ignore filter never matches an empty list, so an
		// incomplete diff cannot wrongly admit an event.
		log.Printf("webhook: changed files for %s: incomplete diff (ignore-only trigger)", ec.Repository.FullName)
		return nil, false, nil
	}
	return res.Files, true, nil
}

// evalTriggerMatches evaluates the pipeline trigger with authoritative
// changed files populated. A failed include-path fetch fails closed. The
// third return reports whether the changed-files list attached to the
// event context is the authoritative complete diff: the enqueue persists
// it as ChangedFilesKnown so the runner never applies a local git
// fallback over a known (possibly empty) server-side list.
func (s *Server) evalTriggerMatches(ctx context.Context, fg forge.Forge, spec *pipeline.Spec, ec *forge.EventContext) (bool, string, bool, error) {
	files, complete, err := s.triggerFilesFetch(ctx, fg, spec, ec)
	if err != nil {
		return false, "", false, err
	}
	if files != nil {
		ec.ChangedFiles = files
	}
	ok, matched := forge.MatchesTrigger(spec.On, *ec)
	return ok, matched, complete, nil
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
		http.Error(w, "fetch pipeline: "+err.Error(), http.StatusBadGateway)
		return
	}
	spec, err := pipeline.Parse([]byte(content))
	if err != nil {
		http.Error(w, "parse pipeline: "+err.Error(), http.StatusBadRequest)
		return
	}
	ok, matched, filesKnown, terr := s.evalTriggerMatches(r.Context(), fg, spec, &ec)
	if terr != nil {
		http.Error(w, terr.Error(), http.StatusBadGateway)
		return
	}
	if !ok {
		log.Printf("webhook: gitlab %s %s ignored (trigger %q)", ec.Event, ec.Repository.FullName, matched)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	files := ec.ChangedFiles

	delivery := r.Header.Get("X-GitLab-Event-UUID")
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
		Metadata:          map[string]string{"gitlab_delivery": delivery},
	}
	run, err := s.enqueue(in)
	if err != nil {
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
		http.Error(w, "fetch pipeline: "+err.Error(), http.StatusBadGateway)
		return
	}
	spec, err := pipeline.Parse([]byte(content))
	if err != nil {
		http.Error(w, "parse pipeline: "+err.Error(), http.StatusBadRequest)
		return
	}
	ok, matched, filesKnown, terr := s.evalTriggerMatches(r.Context(), fg, spec, &ec)
	if terr != nil {
		http.Error(w, terr.Error(), http.StatusBadGateway)
		return
	}
	if !ok {
		log.Printf("webhook: forgejo %s %s ignored (trigger %q)", ec.Event, ec.Repository.FullName, matched)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	files := ec.ChangedFiles

	delivery := r.Header.Get("X-Forgejo-Delivery")
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
		Metadata:          map[string]string{"forgejo_delivery": delivery},
	}
	run, err := s.enqueue(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.recordDelivery(delivery, run.ID)
	writeJSON(w, http.StatusAccepted, run)
}

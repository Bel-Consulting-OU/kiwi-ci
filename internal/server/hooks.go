package server

import (
	"io"
	"log"
	"net/http"

	"github.com/kiwici/kiwi/internal/forge"
	"github.com/kiwici/kiwi/internal/pipeline"
)

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
	ok, matched := forge.MatchesTrigger(spec.On, ec)
	if !ok {
		log.Printf("webhook: gitlab %s %s ignored (trigger %q)", ec.Event, ec.Repository.FullName, matched)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	files, err := fg.ChangedFiles(r.Context(), ec)
	if err != nil {
		log.Printf("webhook: changed files for %s: %v", ec.Repository.FullName, err)
		files = nil
	}

	delivery := r.Header.Get("X-GitLab-Event-UUID")
	if delivery != "" {
		if run, ok := s.dedupeRun(delivery, ec.Repository.FullName); ok {
			writeJSON(w, http.StatusOK, run)
			return
		}
	}
	in := SubmitRun{
		RepoURL:      ec.HeadRepository.CloneURL,
		RepoFullName: ec.Repository.FullName,
		Ref:          ec.Ref,
		SHA:          ec.HeadSHA,
		Event:        ec.Event,
		Pipeline:     content,
		Trusted:      ec.Trusted,
		ChangedFiles: files,
		Metadata:     map[string]string{"gitlab_delivery": delivery},
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
	ok, matched := forge.MatchesTrigger(spec.On, ec)
	if !ok {
		log.Printf("webhook: forgejo %s %s ignored (trigger %q)", ec.Event, ec.Repository.FullName, matched)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	files, err := fg.ChangedFiles(r.Context(), ec)
	if err != nil {
		log.Printf("webhook: changed files for %s: %v", ec.Repository.FullName, err)
		files = nil
	}

	delivery := r.Header.Get("X-Forgejo-Delivery")
	if delivery != "" {
		if run, ok := s.dedupeRun(delivery, ec.Repository.FullName); ok {
			writeJSON(w, http.StatusOK, run)
			return
		}
	}
	in := SubmitRun{
		RepoURL:      ec.HeadRepository.CloneURL,
		RepoFullName: ec.Repository.FullName,
		Ref:          ec.Ref,
		SHA:          ec.HeadSHA,
		Event:        ec.Event,
		Pipeline:     content,
		Trusted:      ec.Trusted,
		ChangedFiles: files,
		Metadata:     map[string]string{"forgejo_delivery": delivery},
	}
	run, err := s.enqueue(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.recordDelivery(delivery, run.ID)
	writeJSON(w, http.StatusAccepted, run)
}

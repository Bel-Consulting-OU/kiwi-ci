package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
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
	// Replay fast path BEFORE any forge API work: the delivery ID and the
	// authenticated body digest identify an already-created run, so a replayed
	// (or header-swapped) webhook performs no pipeline fetch, changed-files
	// fetch or trigger evaluation.
	repoID := s.forgeRepoID("github", webhookRepoCoordinate(ec))
	delivery := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	if delivery == "" {
		http.Error(w, "missing X-GitHub-Delivery", http.StatusBadRequest)
		return
	}
	digest := webhookPayloadDigest(body)
	if prior, ok, derr := s.webhookDeliveryRun(ctx, "github", delivery, digest, repoID); derr != nil {
		if errors.Is(derr, errDeliveryDigestMismatch) {
			http.Error(w, "delivery id was already used with different content", http.StatusConflict)
			return
		}
		s.internalError(w, r, derr, "")
		return
	} else if ok {
		writeJSON(w, http.StatusOK, prior)
		return
	}

	pipelineSHA := ec.HeadSHA
	if !ec.Trusted {
		pipelineSHA = ec.BaseSHA
	}
	content, err := fg.FetchFile(ctx, ec.Repository.FullName, s.pipelinePath(), pipelineSHA)
	if err != nil {
		s.serverError(w, r, http.StatusBadGateway, err, "bad gateway")
		return
	}
	spec, err := pipeline.Parse([]byte(content))
	if err != nil {
		http.Error(w, "parse pipeline: "+err.Error(), http.StatusBadRequest)
		return
	}
	ok, matched, filesKnown, terr := s.evalTriggerMatches(ctx, fg, spec, &ec)
	if terr != nil {
		s.serverError(w, r, http.StatusBadGateway, terr, "bad gateway")
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
	files := ec.ChangedFiles.Files

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
		Metadata:          map[string]string{"github_delivery": delivery, webhookDeliveryDigestKey("github"): digest},
		deliveryDigest:    digest,
		identityBound:     true,
	}
	run, err := s.enqueue(r.Context(), in)
	if err != nil {
		if errors.Is(err, errDeliveryDigestMismatch) {
			http.Error(w, "delivery id was already used with different content", http.StatusConflict)
			return
		}
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
	s.recordWebhookDelivery(r.Context(), "github", repoID, delivery, digest, run.ID)
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) pipelinePath() string {
	if s.PipelinePath == "" {
		return ".kiwi/pipeline.yaml"
	}
	return s.PipelinePath
}

// errDeliveryDigestMismatch reports that a delivery ID was reused with a
// different authenticated body. The signed payload digest is the replay
// identity, so a captured signature cannot be paired with a fresh delivery
// header (or an old header with different content).
var errDeliveryDigestMismatch = errors.New("server: webhook delivery id reused with a different payload")

// webhookPayloadDigest is the SHA-256 of the authenticated webhook body,
// stored with the run so every replay can be bound to the exact signed bytes.
func webhookPayloadDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// webhookDeliveryDigestKey is the run-metadata key holding the signed body
// digest for one forge's delivery header.
func webhookDeliveryDigestKey(forge string) string {
	return forge + "_delivery_digest"
}

// webhookDeliveryRun is the replay fast path: it returns the run already
// created for an authenticated (forge, delivery ID) so a forge retry is
// acknowledged BEFORE any expensive pipeline fetch/parse/trigger work. The
// stored run must belong to the same canonical repository, and when both the
// stored and presented digests are known they must match (a reused delivery
// header with a different signed body fails with errDeliveryDigestMismatch).
// In DB mode the lookup is durable (webhook_deliveries + the run row); in
// memory mode it uses the persisted-run mirror.
func (s *Server) webhookDeliveryRun(ctx context.Context, forge, delivery, digest, repoID string) (model.Run, bool, error) {
	if delivery == "" {
		return model.Run{}, false, nil
	}
	if digest != "" {
		// Strict body-replay suppression: the same AUTHENTICATED body
		// delivered under a FRESH delivery header (provider redelivery or an
		// attacker swapping the unauthenticated header) maps to the original
		// run instead of enqueueing another.
		if s.DB != nil {
			if runID, found, err := s.DB.FindDelivery(ctx, forge+"-body", digest); err != nil {
				return model.Run{}, false, err
			} else if found {
				prior, err := s.DB.GetRun(ctx, runID)
				if err != nil && !errors.Is(err, storage.ErrNotFound) {
					return model.Run{}, false, err
				}
				if err == nil {
					if got, ok, merr := s.matchDeliveryRun(prior, forge, digest, repoID); merr != nil || ok {
						return got, ok, merr
					}
				}
			}
		} else {
			key := webhookBodyKey(forge, repoID, digest)
			s.mu.Lock()
			id, ok := s.deliveries[key]
			prior, priorOK := s.runs[id]
			s.mu.Unlock()
			if ok && priorOK {
				if got, ok, merr := s.matchDeliveryRun(prior, forge, digest, repoID); merr != nil || ok {
					return got, ok, merr
				}
			}
		}
	}
	if s.DB != nil {
		runID, found, err := s.DB.FindDelivery(ctx, forge, delivery)
		if err != nil {
			return model.Run{}, false, err
		}
		if !found {
			return model.Run{}, false, nil
		}
		prior, err := s.DB.GetRun(ctx, runID)
		if errors.Is(err, storage.ErrNotFound) {
			return model.Run{}, false, nil
		}
		if err != nil {
			return model.Run{}, false, err
		}
		return s.matchDeliveryRun(prior, forge, digest, repoID)
	}
	s.mu.Lock()
	id, ok := s.deliveries[delivery]
	prior, priorOK := s.runs[id]
	s.mu.Unlock()
	if !ok || !priorOK {
		return model.Run{}, false, nil
	}
	return s.matchDeliveryRun(prior, forge, digest, repoID)
}

// webhookBodyKey is the in-memory body-receipt key: one authenticated body
// maps to one run per repository.
func webhookBodyKey(forge, repoID, digest string) string {
	return forge + "-body|" + repoID + "|" + digest
}

// recordWebhookDelivery records the delivery receipt (delivery ID -> run) and
// the BODY receipt (authenticated digest -> run, per repository) after a
// successful enqueue. In DB mode the body receipt is persisted through the
// same webhook_deliveries table under a synthetic forge key, so replica
// failover keeps the strict replay suppression.
func (s *Server) recordWebhookDelivery(ctx context.Context, forge, repoID, delivery, digest, runID string) {
	s.recordDelivery(delivery, runID)
	if digest == "" {
		return
	}
	key := webhookBodyKey(forge, repoID, digest)
	s.mu.Lock()
	if _, exists := s.deliveries[key]; !exists {
		s.deliveries[key] = runID
	}
	s.mu.Unlock()
	if s.DB != nil {
		if err := s.DB.UpsertDelivery(ctx, forge+"-body", digest, runID, digest); err != nil {
			s.logError("webhook body receipt persist failed", "forge", forge, "error", err.Error())
		}
	}
}

// matchDeliveryRun applies the repository and body-digest binding to a
// candidate stored run. A digest mismatch is a hard refusal; a repository
// mismatch is a miss (a delivery ID collision across forges/repositories can
// never borrow another run).
func (s *Server) matchDeliveryRun(prior model.Run, forge, digest, repoID string) (model.Run, bool, error) {
	if stored := strings.TrimSpace(prior.Metadata[webhookDeliveryDigestKey(forge)]); stored != "" && digest != "" && stored != digest {
		return model.Run{}, false, errDeliveryDigestMismatch
	}
	if repoID != "" && repoIDForRun(prior) != repoID {
		return model.Run{}, false, nil
	}
	return prior, true, nil
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

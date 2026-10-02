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
	if prior, enqueued, ignored, derr := s.webhookDeliveryRun(ctx, "github", delivery, digest, repoID); derr != nil {
		if errors.Is(derr, errDeliveryDigestMismatch) {
			http.Error(w, "delivery id was already used with different content", http.StatusConflict)
			return
		}
		s.internalError(w, r, derr, "")
		return
	} else if ignored {
		// Terminal ignored replay: the original delivery was fully processed
		// without creating a run, so answer the same 204 with no work.
		w.WriteHeader(http.StatusNoContent)
		return
	} else if enqueued {
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
		// The terminal receipt means a replay performs no forge API work.
		log.Printf("webhook: github %s %s ignored (trigger %q)", ec.Event, ec.Repository.FullName, matched)
		s.recordIgnoredWebhook(ctx, "github", repoID, delivery, digest)
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

// webhookDeliveryRun is the replay fast path: it resolves an authenticated
// (forge, delivery ID) against its durable/ mirrored receipt BEFORE any
// expensive pipeline fetch/parse/trigger work. enqueued=true returns the run
// already created; ignored=true means the original delivery was terminally
// processed WITHOUT creating a run (no trigger match, unsupported action,
// branch deletion) and the replay deserves the same terminal success. A
// stored run must belong to the same canonical repository, and when both
// digests are known they must match (a reused delivery header with different
// signed content fails with errDeliveryDigestMismatch). The body receipt
// additionally suppresses the same authenticated body under a FRESH header.
//
// Returns: (prior, enqueued, ignored, error).
func (s *Server) webhookDeliveryRun(ctx context.Context, forge, delivery, digest, repoID string) (model.Run, bool, bool, error) {
	if delivery == "" {
		return model.Run{}, false, false, nil
	}
	if digest != "" {
		runID, storedDigest, found, err := s.findBodyReceipt(ctx, forge, repoID, digest)
		if err != nil {
			return model.Run{}, false, false, err
		}
		if found {
			return s.resolveDeliveryReceipt(ctx, runID, storedDigest, forge, digest, repoID)
		}
	}
	runID, storedDigest, found, err := s.findDeliveryReceipt(ctx, forge, delivery)
	if err != nil || !found {
		return model.Run{}, false, false, err
	}
	return s.resolveDeliveryReceipt(ctx, runID, storedDigest, forge, digest, repoID)
}

// findDeliveryReceipt looks up a delivery-ID receipt. An empty run ID marks an
// ignored terminal receipt; DB mode reads webhook_deliveries, memory mode the
// persisted-run mirror.
func (s *Server) findDeliveryReceipt(ctx context.Context, forge, deliveryID string) (string, string, bool, error) {
	if s.DB != nil {
		return s.DB.FindDelivery(ctx, forge, deliveryID)
	}
	s.mu.Lock()
	v, ok := s.deliveries[deliveryID]
	s.mu.Unlock()
	if !ok {
		return "", "", false, nil
	}
	// Ignored receipts are encoded as "<digest>" so the same-delivery
	// digest binding works without a run; enqueued receipts hold the run ID
	// and their digest lives in the run metadata.
	if strings.HasPrefix(v, ignoredDeliveryPrefix) {
		return "", strings.TrimPrefix(v, ignoredDeliveryPrefix), true, nil
	}
	return v, "", true, nil
}

// findBodyReceipt looks up the per-repository body receipt: DB mode keys the
// synthetic forge by the digest; memory mode uses the composite body key.
func (s *Server) findBodyReceipt(ctx context.Context, forge, repoID, digest string) (string, string, bool, error) {
	if s.DB != nil {
		return s.DB.FindDelivery(ctx, forge+"-body", digest)
	}
	s.mu.Lock()
	v, ok := s.deliveries[webhookBodyKey(forge, repoID, digest)]
	s.mu.Unlock()
	if !ok {
		return "", "", false, nil
	}
	if strings.HasPrefix(v, ignoredDeliveryPrefix) {
		return "", strings.TrimPrefix(v, ignoredDeliveryPrefix), true, nil
	}
	return v, digest, true, nil
}

// resolveDeliveryReceipt applies the repository/body-digest binding to a
// receipt's run (or reports the ignored outcome).
func (s *Server) resolveDeliveryReceipt(ctx context.Context, runID, storedDigest, forge, digest, repoID string) (model.Run, bool, bool, error) {
	// The stored digest is part of the replay identity for EVERY receipt,
	// including ignored ones (which have no run metadata to compare):
	// reusing a delivery ID with different signed content is a hard conflict,
	// never a terminal-success replay.
	if storedDigest != "" && digest != "" && storedDigest != digest {
		return model.Run{}, false, false, errDeliveryDigestMismatch
	}
	if runID == "" {
		// Terminal ignored receipt: replay returns the same 204 without work.
		return model.Run{}, false, true, nil
	}
	var prior model.Run
	if s.DB != nil {
		var err error
		prior, err = s.DB.GetRun(ctx, runID)
		if errors.Is(err, storage.ErrNotFound) {
			return model.Run{}, false, false, nil
		}
		if err != nil {
			return model.Run{}, false, false, err
		}
	} else {
		s.mu.Lock()
		found := false
		prior, found = s.runs[runID]
		s.mu.Unlock()
		if !found {
			return model.Run{}, false, false, nil
		}
	}
	if stored := strings.TrimSpace(prior.Metadata[webhookDeliveryDigestKey(forge)]); stored != "" && digest != "" && stored != digest {
		return model.Run{}, false, false, errDeliveryDigestMismatch
	}
	if repoID != "" && repoIDForRun(prior) != repoID {
		return model.Run{}, false, false, nil
	}
	return prior, true, false, nil
}

// ignoredDeliveryPrefix encodes an in-memory IGNORED terminal receipt
// (no run) with the authenticated body digest, so a reused delivery ID with
// different content is still refused in fs mode. Run IDs can never contain
// NUL, so the encoding cannot collide with a real receipt.
const ignoredDeliveryPrefix = "ignored:"

// recordIgnoredWebhook persists the terminal receipt for an authenticated
// delivery that produced NO run, so a replay performs no forge API work and
// returns the same terminal success. The body receipt is recorded too, which
// suppresses the same signed payload under a fresh delivery header.
func (s *Server) recordIgnoredWebhook(ctx context.Context, forge, repoID, delivery, digest string) {
	if delivery == "" {
		return
	}
	s.mu.Lock()
	value := ignoredDeliveryPrefix + digest
	if _, exists := s.deliveries[delivery]; !exists {
		s.deliveries[delivery] = value
	}
	if digest != "" {
		key := webhookBodyKey(forge, repoID, digest)
		if _, exists := s.deliveries[key]; !exists {
			s.deliveries[key] = value
		}
	}
	s.mu.Unlock()
	if s.DB != nil {
		if err := s.DB.UpsertDelivery(ctx, forge, delivery, "", digest); err != nil {
			s.logError("webhook ignored receipt persist failed", "forge", forge, "error", err.Error())
		}
		if digest != "" {
			if err := s.DB.UpsertDelivery(ctx, forge+"-body", digest, "", digest); err != nil {
				s.logError("webhook ignored body receipt persist failed", "forge", forge, "error", err.Error())
			}
		}
	}
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

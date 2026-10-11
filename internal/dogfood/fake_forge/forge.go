// Package fake_forge is a hermetic forge emulator (GitHub/GitLab/Forgejo
// stand-in) for dogfood scenarios: it accepts webhooks with HMAC signatures,
// emits push/PR events, applies branch filters, records status callbacks,
// and can deliberately misbehave (duplicate delivery, bad signature, rate
// limit, timeout, retry) so the trigger path's defenses are exercised
// without a network.
package fake_forge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EventType is the closed forge event vocabulary the emulator emits.
type EventType string

const (
	EventPush EventType = "push"
	EventPR   EventType = "pull_request"
)

// Event is one forge webhook payload (the fields the trigger path reads).
type Event struct {
	Type   EventType `json:"type"`
	Repo   string    `json:"repo"`
	Ref    string    `json:"ref"`
	Commit string    `json:"commit"`
	PR     int       `json:"pr,omitempty"`
	Action string    `json:"action,omitempty"`
	Sender string    `json:"sender"`
}

// DeliveryResult is what the forge observed for one delivery attempt.
type DeliveryResult struct {
	Accepted bool
	Reason   string
	// Duplicate marks a re-delivery of an event id the forge already saw.
	Duplicate bool
}

// StatusCallback is a commit status the forge recorded (the status surface
// scenarios assert on).
type StatusCallback struct {
	Repo    string
	Commit  string
	State   string
	Context string
	At      time.Time
}

// Config knobs make the emulator misbehave deterministically.
type Config struct {
	// Secret is the HMAC-SHA256 shared secret the forge signs with and
	// expects. Empty means signature checking is disabled (hermetic local).
	Secret string
	// BranchFilter, when non-empty, is a prefix every event Ref must match
	// to be accepted (refs/heads/main etc.).
	BranchFilter string
	// FailSignatures makes every delivery carry a bad signature.
	FailSignatures bool
	// RateLimitAfter rejects deliveries after N accepted ones with 429.
	RateLimitAfter int
	// TimeoutAfter makes deliveries after N hang (the scenario cancels).
	TimeoutAfter int
	// RetryAfterNFailures reports the retry hint on failures after N tries.
	RetryAfterNFailures int
}

// Forge is the hermetic forge emulator. It is safe for concurrent use.
type Forge struct {
	cfg Config
	mu  sync.Mutex
	// seen ids every delivered event id (duplicate detection).
	seen map[string]bool
	// accepted counts deliveries the trigger path accepted.
	accepted int
	// deliveries is the append-only delivery ledger.
	deliveries []DeliveryResult
	// statuses is the append-only status-callback ledger.
	statuses []StatusCallback
	// handler is the registered trigger sink; nil drops events.
	handler func(Event) error
	// now is the clock (injectable for expiry scenarios).
	now func() time.Time
}

// New builds a forge emulator.
func New(cfg Config) *Forge {
	return &Forge{cfg: cfg, seen: make(map[string]bool), now: time.Now}
}

// OnEvent registers the trigger-path sink the forge delivers to.
func (f *Forge) OnEvent(fn func(Event) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = fn
}

// Sign computes the HMAC the forge would attach to payload.
func (f *Forge) Sign(payload []byte) string {
	if f.cfg.Secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(f.cfg.Secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// Deliver performs one webhook delivery of event with id eventID. It
// enforces the configured misbehavior knobs and the branch filter, detects
// duplicates, verifies the signature and only then invokes the sink.
func (f *Forge) Deliver(eventID string, ev Event, signature string) (DeliveryResult, error) {
	f.mu.Lock()
	if f.cfg.RateLimitAfter > 0 && f.accepted >= f.cfg.RateLimitAfter {
		f.deliveries = append(f.deliveries, DeliveryResult{Accepted: false, Reason: "rate-limited"})
		f.mu.Unlock()
		return DeliveryResult{Accepted: false, Reason: "rate-limited"}, fmt.Errorf("fake_forge: rate limited")
	}
	if f.cfg.TimeoutAfter > 0 && f.accepted >= f.cfg.TimeoutAfter {
		f.mu.Unlock()
		return DeliveryResult{Accepted: false, Reason: "timeout"}, fmt.Errorf("fake_forge: delivery timeout")
	}
	if f.cfg.BranchFilter != "" && !strings.HasPrefix(ev.Ref, f.cfg.BranchFilter) {
		f.deliveries = append(f.deliveries, DeliveryResult{Accepted: false, Reason: "branch-filtered"})
		f.mu.Unlock()
		return DeliveryResult{Accepted: false, Reason: "branch-filtered"}, nil
	}
	if f.seen[eventID] {
		f.deliveries = append(f.deliveries, DeliveryResult{Accepted: false, Reason: "duplicate", Duplicate: true})
		f.mu.Unlock()
		return DeliveryResult{Accepted: false, Reason: "duplicate", Duplicate: true}, nil
	}
	payload, _ := json.Marshal(ev)
	want := f.Sign(payload)
	if f.cfg.FailSignatures {
		want = "bad-signature"
	}
	if f.cfg.Secret != "" && !hmac.Equal([]byte(signature), []byte(want)) {
		f.deliveries = append(f.deliveries, DeliveryResult{Accepted: false, Reason: "bad-signature"})
		f.mu.Unlock()
		return DeliveryResult{Accepted: false, Reason: "bad-signature"}, fmt.Errorf("fake_forge: bad webhook signature")
	}
	f.seen[eventID] = true
	f.accepted++
	fn := f.handler
	f.deliveries = append(f.deliveries, DeliveryResult{Accepted: true})
	f.mu.Unlock()
	if fn == nil {
		return DeliveryResult{Accepted: true}, nil
	}
	if err := fn(ev); err != nil {
		return DeliveryResult{Accepted: false, Reason: "sink-error"}, err
	}
	return DeliveryResult{Accepted: true}, nil
}

// Status records a commit-status callback the pipeline would send back.
func (f *Forge) Status(repo, commit, state, context string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, StatusCallback{Repo: repo, Commit: commit, State: state, Context: context, At: f.now()})
}

// Deliveries returns the append-only delivery ledger.
func (f *Forge) Deliveries() []DeliveryResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]DeliveryResult(nil), f.deliveries...)
}

// Statuses returns the append-only status-callback ledger.
func (f *Forge) Statuses() []StatusCallback {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]StatusCallback(nil), f.statuses...)
}

// AcceptedCount is the number of deliveries the trigger path accepted —
// the authority for "exactly one trigger effect per event".
func (f *Forge) AcceptedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted
}

// WebhookHandler exposes the forge over HTTP for harnesses that want a real
// HTTP hop. The body is the signed event; the signature arrives in the
// configured header.
func (f *Forge) WebhookHandler(header string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EventID string `json:"event_id"`
			Event   Event  `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		res, err := f.Deliver(body.EventID, body.Event, r.Header.Get(header))
		switch {
		case err != nil && res.Reason == "rate-limited":
			w.WriteHeader(http.StatusTooManyRequests)
		case err != nil && res.Reason == "timeout":
			w.WriteHeader(http.StatusGatewayTimeout)
		case err != nil:
			http.Error(w, res.Reason, http.StatusForbidden)
		case res.Duplicate:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
}

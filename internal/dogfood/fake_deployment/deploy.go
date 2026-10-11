// Package fake_deployment is a hermetic deployment sink for dogfood
// scenarios. Its append-only request ledger is the AUTHORITATIVE count of
// external deployment effects: every request records the run/job/attempt
// identity, the lease generation, the capability it arrived under, a
// timestamp and a payload digest. "Exactly one effect" is decided by this
// ledger, never by what a runner or the control plane claims.
package fake_deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Request is one deployment request the sink received. It is the durable
// identity of an external effect.
type Request struct {
	RunID string `json:"run_id"`
	JobID string `json:"job_id"`
	// AttemptID is the canonical attempt identity (<jobID>:<generation>).
	AttemptID  string `json:"attempt_id"`
	Generation int64  `json:"generation"`
	// Capability is the Kiwi capability the request was mediated under.
	Capability string    `json:"capability"`
	Timestamp  time.Time `json:"timestamp"`
	// PayloadDigest is the sha256 of the deployment payload body.
	PayloadDigest string `json:"payload_digest"`
}

// Sink is the fake deployment target with an append-only ledger.
type Sink struct {
	mu     sync.Mutex
	ledger []Request
	now    func() time.Time
	// rejectAfter rejects requests after N accepted ones (rate-limit /
	// outage scenarios).
	rejectAfter int
}

// New builds a deployment sink. now is injectable for deterministic
// timestamps (nil means wall time).
func New(now func() time.Time) *Sink {
	if now == nil {
		now = time.Now
	}
	return &Sink{now: now}
}

// RejectAfter configures the sink to refuse requests after n accepted ones
// (n<=0 disables). Used to prove the retry/effect rules under outage.
func (s *Sink) RejectAfter(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectAfter = n
}

// Deploy appends one request to the ledger. The sink never mutates or
// rewrites a recorded request: the ledger is append-only so a duplicate or
// speculative effect is visible as an extra row, not hidden by an update.
func (s *Sink) Deploy(req Request, payload []byte) error {
	sum := sha256.Sum256(payload)
	req.PayloadDigest = hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejectAfter > 0 && len(s.ledger) >= s.rejectAfter {
		return fmt.Errorf("fake_deployment: sink unavailable")
	}
	req.Timestamp = s.now()
	s.ledger = append(s.ledger, req)
	return nil
}

// Ledger returns a copy of the append-only request ledger.
func (s *Sink) Ledger() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.ledger...)
}

// Count is the authoritative total number of deployment effects.
func (s *Sink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ledger)
}

// CountForAttempt is the authoritative effect count of one attempt — the
// number the "exactly one effect" oracle compares against.
func (s *Sink) CountForAttempt(jobID string, generation int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.ledger {
		if r.JobID == jobID && r.Generation == generation {
			n++
		}
	}
	return n
}

package fake_deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// TestSinkCountsAuthoritativeEffects: the append-only request ledger is the
// authority for "exactly once" / "exactly zero" external-effect claims. A
// valid winner must produce one effect; a rejected competitor zero.
func TestSinkCountsAuthoritativeEffects(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	s := New(func() time.Time { return now })
	payload := []byte(`{"target":"prod"}`)

	winner := Request{
		RunID: "run-1", JobID: "job-1", AttemptID: "job-1:2",
		Generation: 2, Capability: "deploy:prod",
	}
	if err := s.Deploy(winner, payload); err != nil {
		t.Fatalf("winner deploy: %v", err)
	}
	if s.Count() != 1 || s.CountForAttempt("job-1", 2) != 1 {
		t.Fatalf("counts = %d / %d, want 1 / 1", s.Count(), s.CountForAttempt("job-1", 2))
	}
	sum := sha256.Sum256(payload)
	if s.Ledger()[0].PayloadDigest != hex.EncodeToString(sum[:]) {
		t.Fatal("ledger must record the payload digest the sink computed")
	}
	// A speculative loser must not add an effect once the sink is closed.
	loser := winner
	loser.AttemptID = "job-1:3"
	loser.Generation = 3
	s.RejectAfter(1)
	if err := s.Deploy(loser, payload); err == nil {
		t.Fatal("sink must reject after the armed budget")
	}
	if s.Count() != 1 {
		t.Fatalf("count after rejected loser = %d, want 1", s.Count())
	}
}

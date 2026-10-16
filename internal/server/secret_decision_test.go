package server

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// The decision must carry the rejected alternatives: explanation must
// explain the DECISION, including what it did NOT pick.
func TestSecretDecisionCarriesRejectedAlternatives(t *testing.T) {
	s := New("secret")
	s.StubRemoteIdentityForTest()
	s.SecretBroker = secretbroker.StaticBroker{}
	j := model.Job{
		ID: "j1", RunID: "r1", Trusted: true,
		DeclaredSecrets: []string{"TOKEN", "OTHER", "THIRD"},
		Ref:             "refs/heads/main", Event: "push",
	}
	d := s.explainSecret(context.Background(), j, "TOKEN")
	if !d.Allowed {
		t.Fatalf("decision must allow: %s", d.Reason)
	}
	if d.Stage != "declared" {
		t.Fatalf("stage = %q", d.Stage)
	}
	// The two un-requested declared secrets must appear as rejected.
	rejected := map[string]bool{}
	for _, r := range d.Rejected {
		rejected[r.Source+"|"+r.Dimension] = true
	}
	if !rejected["declaration|not-requested"] {
		t.Fatalf("rejected = %+v, want a not-requested declaration entry", d.Rejected)
	}
	found := false
	for _, r := range d.Rejected {
		if strings.Contains(r.Detail, "OTHER") || strings.Contains(r.Detail, "THIRD") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rejected must name the un-requested secrets: %+v", d.Rejected)
	}
	// The trust dimension is recorded as a would-have-refused alternative.
	if !rejected["trust|trust-floor"] {
		t.Fatalf("rejected = %+v, want a trust-floor entry", d.Rejected)
	}
}

// A refused decision names the gate that refused it and carries no audit id
// (nothing was delivered).
func TestSecretDecisionRefusalStage(t *testing.T) {
	s := New("secret")
	s.StubRemoteIdentityForTest()
	j := model.Job{
		ID: "j1", RunID: "r1", Trusted: false,
		DeclaredSecrets: []string{"TOKEN"},
	}
	d := s.explainSecret(context.Background(), j, "TOKEN")
	if d.Allowed {
		t.Fatal("untrusted job must be refused")
	}
	if d.Stage != "trust" {
		t.Fatalf("stage = %q, want trust", d.Stage)
	}
	if d.AuditID != "" {
		t.Fatalf("refused decision must carry no audit id, got %q", d.AuditID)
	}
}

// Undeclared secrets are refused at the declaration gate.
func TestSecretDecisionDeclarationGate(t *testing.T) {
	s := New("secret")
	s.StubRemoteIdentityForTest()
	j := model.Job{ID: "j1", RunID: "r1", Trusted: true, DeclaredSecrets: []string{"TOKEN"}}
	d := s.explainSecret(context.Background(), j, "NOPE")
	if d.Allowed || d.Stage != "declaration" {
		t.Fatalf("decision = %+v", d)
	}
}

// Malformed names are refused at the grammar gate before anything else.
func TestSecretDecisionNameGrammarGate(t *testing.T) {
	s := New("secret")
	s.StubRemoteIdentityForTest()
	j := model.Job{ID: "j1", RunID: "r1", Trusted: true, DeclaredSecrets: []string{"TOKEN"}}
	d := s.explainSecret(context.Background(), j, "bad name!")
	if d.Allowed || d.Stage != "name-grammar" {
		t.Fatalf("decision = %+v", d)
	}
}

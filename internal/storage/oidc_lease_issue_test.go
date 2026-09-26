package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// oidcIssueTestJob is a production-shaped running job: the lease fields and
// the repository identity are populated exactly like an enqueued+leased job.
func oidcIssueTestJob() model.Job {
	exp := time.Now().UTC().Add(time.Hour)
	return model.Job{
		ID: "job-oidc", RunID: "run-oidc", Key: "build",
		RepoID: "github.com/acme/backend", RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Status: model.StatusRunning, Trusted: true, OIDCAllowed: true,
		OIDCAudiences:   []string{"https://aud.example.com"},
		LeaseRunnerID:   "runner-1",
		LeaseGeneration: 2, LeaseTokenHash: []byte("lease-hash"),
		LeaseExpiresAt: &exp,
	}
}

func oidcIssueTestRequest(j model.Job) OIDCIssuance {
	now := time.Now().UTC()
	return OIDCIssuance{
		JobID: j.ID, RunnerID: j.LeaseRunnerID, LeaseGeneration: j.LeaseGeneration,
		LeaseTokenHash: j.LeaseTokenHash, Audience: "https://aud.example.com",
		KID: "kid-1", JTI: "jti-1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Claims: map[string]string{
			OIDCClaimJobID:        j.ID,
			OIDCClaimRunID:        j.RunID,
			OIDCClaimJob:          j.Key,
			OIDCClaimRepositoryID: RepoIDForJob(j),
			OIDCClaimRepository:   j.RepoFullName,
			OIDCClaimTrusted:      "true",
			OIDCClaimAudience:     "https://aud.example.com",
		},
	}
}

func seedOIDCIssueMemStore(t *testing.T, j model.Job) *memStore {
	t.Helper()
	m := newMemStore()
	if err := m.UpdateJob(context.Background(), j); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	return m
}

// TestOIDCIssuanceCommitMemStoreParity pins the in-memory commit contract:
// the authoritative job is re-read under the store lock, the shared predicate
// and claim binding are evaluated, and the oidc.issued audit row is appended
// in the same critical section. A refusal is the same typed error as
// PostgreSQL and appends NOTHING.
func TestOIDCIssuanceCommitMemStoreParity(t *testing.T) {
	j := oidcIssueTestJob()
	m := seedOIDCIssueMemStore(t, j)
	locked, err := m.CommitOIDCIssuance(ctx(), oidcIssueTestRequest(j))
	if err != nil {
		t.Fatalf("live commit: %v", err)
	}
	if locked.JobID != j.ID || locked.RunID != j.RunID || locked.JobKey != j.Key {
		t.Fatalf("locked identity = %+v", locked)
	}
	if locked.RepoID != RepoIDForJob(j) || locked.RepoFullName != j.RepoFullName || !locked.Trusted || !locked.OIDCAllowed {
		t.Fatalf("locked repository/trust = %+v", locked)
	}
	if len(locked.AllowedAudiences) != 1 || locked.AllowedAudiences[0] != "https://aud.example.com" {
		t.Fatalf("locked audiences = %v", locked.AllowedAudiences)
	}
	events, err := m.ReadAudit(ctx(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "oidc.issued" || events[0].JobID != j.ID || events[0].RunID != j.RunID {
		t.Fatalf("audit after live commit = %+v", events)
	}
	if events[0].Metadata["audience"] != "https://aud.example.com" || events[0].Metadata["kid"] != "kid-1" || events[0].Metadata["job"] != j.Key {
		t.Fatalf("audit metadata = %v", events[0].Metadata)
	}

	cases := []struct {
		name   string
		mutate func(*model.Job)
		req    func(OIDCIssuance) OIDCIssuance
		want   error
	}{
		{name: "cancelled", mutate: func(j *model.Job) { j.Status = model.StatusCancelled }, want: ErrOIDCIssuanceRevoked},
		{name: "completed", mutate: func(j *model.Job) { j.Status = model.StatusSuccess }, want: ErrOIDCIssuanceRevoked},
		{name: "expired", mutate: func(j *model.Job) { past := time.Now().UTC().Add(-time.Minute); j.LeaseExpiresAt = &past }, want: ErrOIDCIssuanceExpired},
		{name: "missing lease", mutate: func(j *model.Job) { j.LeaseExpiresAt = nil }, want: ErrOIDCIssuanceExpired},
		{name: "generation changed", mutate: func(j *model.Job) { j.LeaseGeneration++ }, want: ErrOIDCIssuanceGeneration},
		{name: "runner changed", mutate: func(j *model.Job) { j.LeaseRunnerID = "runner-2" }, want: ErrOIDCIssuanceRunner},
		{name: "token changed", mutate: func(j *model.Job) { j.LeaseTokenHash = []byte("other") }, want: ErrOIDCIssuanceToken},
		{name: "untrusted", mutate: func(j *model.Job) { j.Trusted = false }, want: ErrOIDCIssuanceUntrusted},
		{name: "not allowed", mutate: func(j *model.Job) { j.OIDCAllowed = false }, want: ErrOIDCIssuanceNotAllowed},
		{name: "audience narrowed", mutate: func(j *model.Job) { j.OIDCAudiences = []string{"https://other.example.com"} }, want: ErrOIDCIssuanceAudience},
		{name: "claim job mismatch", req: func(r OIDCIssuance) OIDCIssuance { r.Claims[OIDCClaimJob] = "other"; return r }, want: ErrOIDCIssuanceIdentity},
		{name: "claim repository mismatch", req: func(r OIDCIssuance) OIDCIssuance { r.Claims[OIDCClaimRepositoryID] = "github.com/other/repo"; return r }, want: ErrOIDCIssuanceIdentity},
		{name: "claim audience mismatch", req: func(r OIDCIssuance) OIDCIssuance { r.Claims[OIDCClaimAudience] = "https://other.example.com"; return r }, want: ErrOIDCIssuanceIdentity},
		{name: "empty audience", req: func(r OIDCIssuance) OIDCIssuance { r.Audience = ""; return r }, want: ErrOIDCIssuanceInvalid},
		{name: "empty runner", req: func(r OIDCIssuance) OIDCIssuance { r.RunnerID = ""; return r }, want: ErrOIDCIssuanceInvalid},
		{name: "empty token hash", req: func(r OIDCIssuance) OIDCIssuance { r.LeaseTokenHash = nil; return r }, want: ErrOIDCIssuanceInvalid},
		{name: "empty kid", req: func(r OIDCIssuance) OIDCIssuance { r.KID = ""; return r }, want: ErrOIDCIssuanceInvalid},
		{name: "negative generation", req: func(r OIDCIssuance) OIDCIssuance { r.LeaseGeneration = -1; return r }, want: ErrOIDCIssuanceInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := oidcIssueTestJob()
			if tc.mutate != nil {
				tc.mutate(&job)
			}
			m := seedOIDCIssueMemStore(t, job)
			req := oidcIssueTestRequest(oidcIssueTestJob())
			if tc.req != nil {
				req = tc.req(req)
			}
			if _, err := m.CommitOIDCIssuance(ctx(), req); !errors.Is(err, tc.want) {
				t.Fatalf("commit = %v, want %v", err, tc.want)
			}
			events, err := m.ReadAudit(ctx(), 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 {
				t.Fatalf("refused commit wrote %d audit rows: %+v", len(events), events)
			}
		})
	}

	// Unknown job: ErrNotFound, no audit.
	m2 := newMemStore()
	if _, err := m2.CommitOIDCIssuance(ctx(), oidcIssueTestRequest(j)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown job commit = %v, want ErrNotFound", err)
	}
}

// TestOIDCIssuanceCommitFaultyStoreParity pins the wrapper contract: the
// pass-through commits exactly like the inner store, an armed fault refuses
// before anything is written, and an inner store without the capability fails
// closed with the typed missing-interface error instead of panicking.
func TestOIDCIssuanceCommitFaultyStoreParity(t *testing.T) {
	j := oidcIssueTestJob()
	inner := seedOIDCIssueMemStore(t, j)
	fs := &FaultyStore{Inner: inner}
	locked, err := fs.CommitOIDCIssuance(ctx(), oidcIssueTestRequest(j))
	if err != nil {
		t.Fatalf("pass-through commit: %v", err)
	}
	if locked.JobID != j.ID {
		t.Fatalf("pass-through locked = %+v", locked)
	}
	events, _ := inner.ReadAudit(ctx(), 10)
	if len(events) != 1 {
		t.Fatalf("pass-through audit = %d rows, want 1", len(events))
	}

	armedInner := seedOIDCIssueMemStore(t, j)
	armed := &FaultyStore{Inner: armedInner, FailAfter: 1, Err: errBoom}
	if _, err := armed.CommitOIDCIssuance(ctx(), oidcIssueTestRequest(j)); !errors.Is(err, errBoom) {
		t.Fatalf("armed commit = %v, want the injected fault", err)
	}
	if events, _ := armedInner.ReadAudit(ctx(), 10); len(events) != 0 {
		t.Fatalf("armed commit wrote %d audit rows", len(events))
	}
	if armed.Mutations() != 1 {
		t.Fatalf("armed commit consumed %d mutations, want 1", armed.Mutations())
	}

	miss := &FaultyStore{Inner: storeOnlyInner{}}
	_, err = miss.CommitOIDCIssuance(ctx(), oidcIssueTestRequest(j))
	assertMissingInterface(t, err, "LeaseOIDCIssueStore")
	if miss.Mutations() != 0 {
		t.Fatalf("missing-capability call consumed %d faults", miss.Mutations())
	}
	armedMiss := &FaultyStore{Inner: storeOnlyInner{}, FailAfter: 1, Err: errBoom}
	_, err = armedMiss.CommitOIDCIssuance(ctx(), oidcIssueTestRequest(j))
	assertMissingInterface(t, err, "LeaseOIDCIssueStore")
	if errors.Is(err, errBoom) || armedMiss.Mutations() != 0 {
		t.Fatalf("armed missing-capability call fired/consumed a fault: %v mutations=%d", err, armedMiss.Mutations())
	}
}

package storage

import (
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// secretIssueLeaseJob stores a running, trusted, declared-secret job holding a
// live lease in the in-memory store and returns a matching commit request.
func secretIssueLeaseJob(t *testing.T, m *memStore) SecretIssuance {
	t.Helper()
	exp := time.Now().UTC().Add(time.Hour)
	j := testJob
	j.Status = model.StatusRunning
	j.Trusted = true
	j.DeclaredSecrets = []string{"TOKEN"}
	j.LeaseRunnerID = testRunner.ID
	j.LeaseTokenHash = []byte("lease-hash")
	j.LeaseGeneration = 1
	j.LeaseExpiresAt = &exp
	if err := m.InsertJob(ctx(), j); err != nil {
		t.Fatalf("InsertJob: %v", err)
	}
	return SecretIssuance{
		JobID: testJob.ID, RunnerID: testRunner.ID, LeaseGeneration: 1,
		LeaseTokenHash: []byte("lease-hash"), SecretName: "TOKEN", IssuedAt: time.Now().UTC(),
	}
}

// secretIssueClaimCount counts once-only claims in the in-memory store.
func secretIssueClaimCount(m *memStore) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.claims)
}

// secretIssueAuditCount counts secret.issued audit rows in the in-memory
// store.
func secretIssueAuditCount(m *memStore) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.audit {
		if e.Action == "secret.issued" {
			n++
		}
	}
	return n
}

// TestMemCommitSecretIssuanceRecordsClaimAndAudit pins the memory-mode
// transactional contract: one successful commit records exactly one once-only
// claim and one secret.issued audit event, and a replay refuses typed without
// recording anything else.
func TestMemCommitSecretIssuanceRecordsClaimAndAudit(t *testing.T) {
	m := newMemStore()
	req := secretIssueLeaseJob(t, m)
	if err := m.CommitSecretIssuance(ctx(), req); err != nil {
		t.Fatalf("CommitSecretIssuance: %v", err)
	}
	if got := secretIssueClaimCount(m); got != 1 {
		t.Fatalf("claims = %d, want 1", got)
	}
	if got := secretIssueAuditCount(m); got != 1 {
		t.Fatalf("secret.issued audits = %d, want 1", got)
	}
	m.mu.Lock()
	ev := m.audit[len(m.audit)-1]
	m.mu.Unlock()
	if ev.Actor != testRunner.ID || ev.JobID != testJob.ID || ev.RunID != testRun.ID {
		t.Fatalf("audit identity = %+v", ev)
	}
	if ev.Metadata["secret"] != "TOKEN" || ev.Metadata["generation"] != "1" {
		t.Fatalf("audit metadata = %v", ev.Metadata)
	}
	if err := m.CommitSecretIssuance(ctx(), req); !errors.Is(err, ErrSecretIssuanceDuplicate) {
		t.Fatalf("replay = %v, want ErrSecretIssuanceDuplicate", err)
	}
	if got := secretIssueClaimCount(m); got != 1 {
		t.Fatalf("claims after replay = %d, want 1", got)
	}
	if got := secretIssueAuditCount(m); got != 1 {
		t.Fatalf("audits after replay = %d, want 1", got)
	}
}

// TestMemCommitSecretIssuanceRefusals is the typed-refusal matrix: every
// revocation applied to the authoritative job (or the request) before the
// commit returns its typed error and records NO claim and NO audit.
func TestMemCommitSecretIssuanceRefusals(t *testing.T) {
	update := func(m *memStore, mutate func(*model.Job)) {
		m.mu.Lock()
		j := m.jobs[testJob.ID]
		mutate(&j)
		m.jobs[testJob.ID] = j
		m.mu.Unlock()
	}
	past := time.Now().UTC().Add(-time.Second)
	cases := []struct {
		name   string
		mutate func(*memStore)
		edit   func(*SecretIssuance)
		want   error
	}{
		{name: "cancelled", mutate: func(m *memStore) {
			update(m, func(j *model.Job) { j.Status = model.StatusCancelled })
		}, want: ErrSecretIssuanceRevoked},
		{name: "completed", mutate: func(m *memStore) {
			update(m, func(j *model.Job) { j.Status = model.StatusSuccess })
		}, want: ErrSecretIssuanceRevoked},
		{name: "expired", mutate: func(m *memStore) {
			update(m, func(j *model.Job) { j.LeaseExpiresAt = &past })
		}, want: ErrSecretIssuanceExpired},
		{name: "generation changed", mutate: func(m *memStore) {
			update(m, func(j *model.Job) { j.LeaseGeneration++ })
		}, want: ErrSecretIssuanceGeneration},
		{name: "runner changed", mutate: func(m *memStore) {
			update(m, func(j *model.Job) { j.LeaseRunnerID = "someone-else" })
		}, want: ErrSecretIssuanceRunner},
		{name: "token changed", mutate: func(m *memStore) {
			update(m, func(j *model.Job) { j.LeaseTokenHash = []byte("other") })
		}, want: ErrSecretIssuanceToken},
		{name: "untrusted", mutate: func(m *memStore) {
			update(m, func(j *model.Job) { j.Trusted = false })
		}, want: ErrSecretIssuanceUntrusted},
		{name: "undeclared", mutate: func(m *memStore) {
			update(m, func(j *model.Job) { j.DeclaredSecrets = []string{"OTHER"} })
		}, want: ErrSecretIssuanceNotDeclared},
		{name: "invalid request", edit: func(r *SecretIssuance) { r.RunnerID = "" }, want: ErrSecretIssuanceInvalid},
		{name: "missing job", mutate: func(m *memStore) {
			m.mu.Lock()
			delete(m.jobs, testJob.ID)
			m.mu.Unlock()
		}, want: ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMemStore()
			req := secretIssueLeaseJob(t, m)
			if tc.mutate != nil {
				tc.mutate(m)
			}
			if tc.edit != nil {
				tc.edit(&req)
			}
			if err := m.CommitSecretIssuance(ctx(), req); !errors.Is(err, tc.want) {
				t.Fatalf("CommitSecretIssuance = %v, want %v", err, tc.want)
			}
			if got := secretIssueClaimCount(m); got != 0 {
				t.Fatalf("refused commit recorded %d claims", got)
			}
			if got := secretIssueAuditCount(m); got != 0 {
				t.Fatalf("refused commit recorded %d audits", got)
			}
		})
	}
}

// TestValidateSecretIssuanceRequestShape pins the request-shape contract.
func TestValidateSecretIssuanceRequestShape(t *testing.T) {
	base := func() SecretIssuance {
		return SecretIssuance{
			JobID: "job", RunnerID: "runner", LeaseGeneration: 1,
			LeaseTokenHash: []byte("h"), SecretName: "TOKEN", IssuedAt: time.Now().UTC(),
		}
	}
	cases := []struct {
		name string
		edit func(*SecretIssuance)
	}{
		{"empty job", func(r *SecretIssuance) { r.JobID = "" }},
		{"empty runner", func(r *SecretIssuance) { r.RunnerID = "" }},
		{"negative generation", func(r *SecretIssuance) { r.LeaseGeneration = -1 }},
		{"empty token hash", func(r *SecretIssuance) { r.LeaseTokenHash = nil }},
		{"empty secret name", func(r *SecretIssuance) { r.SecretName = "  " }},
		{"zero issued at", func(r *SecretIssuance) { r.IssuedAt = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base()
			tc.edit(&req)
			if err := ValidateSecretIssuanceRequest(req); !errors.Is(err, ErrSecretIssuanceInvalid) {
				t.Fatalf("ValidateSecretIssuanceRequest = %v, want ErrSecretIssuanceInvalid", err)
			}
		})
	}
	if err := ValidateSecretIssuanceRequest(base()); err != nil {
		t.Fatalf("valid request = %v", err)
	}
}

// TestFaultyStoreCommitSecretIssuance pins the wrapper parity: the fault-free
// call reaches the inner store (recording the claim), while an armed fault
// surfaces before any write and a plain Store inner fails closed with the
// missing-interface error.
func TestFaultyStoreCommitSecretIssuance(t *testing.T) {
	inner := newMemStore()
	req := secretIssueLeaseJob(t, inner)
	fs := &FaultyStore{Inner: inner}
	if err := fs.CommitSecretIssuance(ctx(), req); err != nil {
		t.Fatalf("pass-through: %v", err)
	}
	if got := secretIssueClaimCount(inner); got != 1 {
		t.Fatalf("pass-through claims = %d, want 1", got)
	}

	faulted := newMemStore()
	faultReq := secretIssueLeaseJob(t, faulted)
	armed := &FaultyStore{Inner: faulted, FailAfter: 1, Err: errBoom}
	if err := armed.CommitSecretIssuance(ctx(), faultReq); !errors.Is(err, errBoom) {
		t.Fatalf("armed fault = %v, want errBoom", err)
	}
	if got := secretIssueClaimCount(faulted); got != 0 {
		t.Fatalf("faulted wrapper leaked %d claims", got)
	}
	if got := secretIssueAuditCount(faulted); got != 0 {
		t.Fatalf("faulted wrapper leaked %d audits", got)
	}

	missing := &FaultyStore{Inner: storeOnlyInner{}}
	if err := missing.CommitSecretIssuance(ctx(), SecretIssuance{}); err == nil {
		t.Fatal("missing inner interface = nil error")
	} else if want := errMissingInnerInterface("SecretIssuanceStore"); err.Error() != want.Error() {
		t.Fatalf("missing inner interface = %v, want %v", err, want)
	}
}

// TestSecretIssuanceAuditEventShape pins the ONE audit event shape both store
// modes and the server write: name and generation only, never the value.
func TestSecretIssuanceAuditEventShape(t *testing.T) {
	at := time.Unix(1234, 0).UTC()
	ev := SecretIssuanceAuditEvent(SecretIssuance{JobID: "j", RunnerID: "r", LeaseGeneration: 9, SecretName: "S", IssuedAt: at}, "run", "id-1")
	if ev.ID != "id-1" || ev.Action != "secret.issued" || ev.Actor != "r" || ev.RunID != "run" || ev.JobID != "j" {
		t.Fatalf("event identity = %+v", ev)
	}
	if !ev.CreatedAt.Equal(at) || ev.Metadata["secret"] != "S" || ev.Metadata["generation"] != "9" {
		t.Fatalf("event payload = %+v", ev)
	}
}

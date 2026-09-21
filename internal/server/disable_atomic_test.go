package server

// S6-B fs-mode parity for the atomic runner disable: the disable flag, the
// lease revocations and the certificate revocation commit under ONE lock
// section and are persisted by ONE snapshot write before the 200, so a
// restart can never observe a disabled runner whose certificate was not
// revoked (or vice versa). A failed snapshot write restores the CRL too.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func seedRunnerCertSerial(t *testing.T, s *Server, runnerID, serial string) {
	t.Helper()
	s.mu.Lock()
	ri := s.runners[runnerID]
	ri.CertSerial = serial
	s.runners[runnerID] = ri
	s.mu.Unlock()
}

// TestRunnerDisableFSCRLCommitsWithSnapshot proves the fs-mode disable writes
// the runner flag AND the CRL in the same durable snapshot before acking,
// and that a restart restores both.
func TestRunnerDisableFSCRLCommitsWithSnapshot(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)
	const serial = "fs-serial-1"
	seedRunnerCertSerial(t, s, runnerID, serial)

	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	// The snapshot carries both effects: a crash after the ack can never
	// recover a disabled runner with an un-revoked certificate.
	snap, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Runners[runnerID].Disabled {
		t.Fatalf("snapshot runner = %+v, want disabled", snap.Runners[runnerID])
	}
	if snap.CRL[serial] != runnerID {
		t.Fatalf("snapshot CRL = %v, want %s -> %s", snap.CRL, serial, runnerID)
	}
	if snap.Jobs[task.Job.ID].Status != model.StatusCancelled {
		t.Fatalf("snapshot job = %+v, want cancelled", snap.Jobs[task.Job.ID])
	}

	// A restart restores the disabled runner and the revoked serial.
	restarted, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.runners[runnerID].Disabled {
		t.Fatalf("restarted runner = %+v, want disabled", restarted.runners[runnerID])
	}
	if !crlRevoked(t, restarted, serial) {
		t.Fatal("restart lost the revoked certificate serial")
	}
}

// TestRunnerDisableFSPersistFailureRestoresCRL proves the other half: a
// failed snapshot write rolls the CRL and the runner flag back together and
// answers 503, and the healed retry commits both.
func TestRunnerDisableFSPersistFailureRestoresCRL(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)
	const serial = "fs-serial-2"
	seedRunnerCertSerial(t, s, runnerID, serial)

	s.persistFailForTest = errors.New("synthetic snapshot write failure")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disable with broken snapshot = %d, want 503: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	ri, job := s.runners[runnerID], s.jobs[task.Job.ID]
	_, crlHasSerial := s.crl[serial]
	s.mu.Unlock()
	if ri.Disabled {
		t.Fatalf("failed disable marked the runner disabled: %+v", ri)
	}
	if job.Status != model.StatusRunning || job.LeaseTokenHash == nil {
		t.Fatalf("failed disable moved the lease: %+v", job)
	}
	if crlHasSerial {
		t.Fatal("failed disable left the CRL entry behind")
	}
	if crlRevoked(t, s, serial) {
		t.Fatal("failed disable left the certificate revoked")
	}

	s.persistFailForTest = nil
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("healed disable = %d: %s", w.Code, w.Body.String())
	}
	if !crlRevoked(t, s, serial) {
		t.Fatal("healed disable did not revoke the certificate")
	}
	snap, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Runners[runnerID].Disabled || snap.CRL[serial] != runnerID {
		t.Fatalf("healed snapshot = runner %+v CRL %v, want both effects", snap.Runners[runnerID], snap.CRL)
	}
}

package server

// Memory-mode supersession identity: the concurrency-group cancel-in-progress
// path keys on the canonical RepoID of the run's checkout repository
// (storage.RepoIDForRun), so the same repository submitted once via HTTPS and
// once via SSH supersedes, while a same-named repository on another forge in
// the same group is never cancelled.

import (
	"context"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemorySupersessionCanonicalRepoIDSpellingPair drives the in-memory
// enqueue path (no DB) with the HTTPS/SSH spelling pair of one repository.
func TestMemorySupersessionCanonicalRepoIDSpellingPair(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	submit := func(repoURL, fullName string) model.Run {
		t.Helper()
		run, err := s.enqueue(context.Background(), SubmitRun{RepoURL: repoURL, RepoFullName: fullName, Ref: "refs/heads/main", SHA: "abc", Event: "push", Pipeline: concurrencyPipeline})
		if err != nil {
			t.Fatalf("enqueue %s: %v", repoURL, err)
		}
		return run
	}
	httpsRun := submit("https://github.com/o/r.git", "o/r")
	// Another forge, same owner/name and same group: never superseded by the
	// github repository's runs.
	gitlabRun := submit("https://gitlab.company.com/o/r.git", "o/r")
	// The SSH spelling of the github repository supersedes the HTTPS run.
	sshRun := submit("git@github.com:o/r.git", "o/r")

	s.mu.Lock()
	httpsStored := s.runs[httpsRun.ID]
	gitlabStored := s.runs[gitlabRun.ID]
	sshStored := s.runs[sshRun.ID]
	var httpsJobsCancelled, gitlabJobsCancelled bool
	for _, j := range s.jobs {
		if j.RunID == httpsRun.ID && j.Status == model.StatusCancelled {
			httpsJobsCancelled = true
		}
		if j.RunID == gitlabRun.ID && j.Status == model.StatusCancelled {
			gitlabJobsCancelled = true
		}
	}
	s.mu.Unlock()

	if httpsStored.Status != model.StatusCancelled {
		t.Fatalf("HTTPS run status = %s, want cancelled by the SSH spelling", httpsStored.Status)
	}
	if !httpsJobsCancelled {
		t.Fatal("HTTPS run's job was not cancelled by the SSH spelling")
	}
	if gitlabStored.Status.Terminal() {
		t.Fatalf("other-forge run status = %s, want untouched (different canonical identity)", gitlabStored.Status)
	}
	if gitlabJobsCancelled {
		t.Fatal("other-forge run's job was cancelled: supersession crossed repositories")
	}
	if sshStored.Status.Terminal() {
		t.Fatalf("successor run status = %s, want queued", sshStored.Status)
	}
}

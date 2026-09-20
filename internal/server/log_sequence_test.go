package server

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestLogAppendIdentitySequencesOutOfClockOrder proves the DB append path
// never trusts the caller's wall-clock sequence: two appends delivered in
// reverse clock order receive strictly increasing store-assigned sequences,
// and the read cursor after any position never skips an entry.
func TestLogAppendIdentitySequencesOutOfClockOrder(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: smokePipeline, Trusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseRunJob(t, s)
	runID := task.Job.RunID

	// Append three lines whose requested sequences are deliberately out of
	// clock order (the legacy wall-clock model): the store must assign its
	// own identity sequence.
	inputs := []int64{9, 3, 7}
	lines := []string{"first", "second", "third"}
	for i, seq := range inputs {
		if err := f.AppendLog(context.Background(), model.LogEntry{
			Seq: seq, RunID: runID, JobID: task.Job.ID, JobKey: task.Job.Key,
			Line: lines[i], CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	stored := append([]model.LogEntry(nil), f.logs...)
	f.mu.Unlock()
	if len(stored) != 3 {
		t.Fatalf("stored %d log entries, want 3", len(stored))
	}
	for i := 1; i < len(stored); i++ {
		if stored[i].Seq <= stored[i-1].Seq {
			t.Fatalf("sequences not strictly increasing: %v", seqsOf(stored))
		}
	}

	// Read after-cursor never skips: after the first sequence the remaining
	// two entries come back in order.
	after := stored[0].Seq
	got, err := f.ReadLogs(context.Background(), runID, after, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Seq != stored[1].Seq || got[1].Seq != stored[2].Seq {
		t.Fatalf("read after cursor = %v, want the two remaining entries in order", seqsOf(got))
	}

	// The HTTP endpoint acknowledges appends; the store-assigned sequence
	// is strictly increasing across appends too.
	h := s.Handler()
	for _, line := range []string{"http-a", "http-b"} {
		body := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":%d,"line":%q}`,
			runnerID, task.LeaseToken, task.LeaseGeneration, line)
		w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/log", "token", body)
		if w.Code != http.StatusNoContent {
			t.Fatalf("log line = %d: %s", w.Code, w.Body.String())
		}
	}
	f.mu.Lock()
	stored = append([]model.LogEntry(nil), f.logs...)
	f.mu.Unlock()
	for i := 1; i < len(stored); i++ {
		if stored[i].Seq <= stored[i-1].Seq {
			t.Fatalf("http appends broke monotonicity: %v", seqsOf(stored))
		}
	}
	_ = h
}

func seqsOf(entries []model.LogEntry) []int64 {
	out := make([]int64, len(entries))
	for i, e := range entries {
		out[i] = e.Seq
	}
	return out
}

// TestLogReadAfterCursorNeverSkips (DB fake) verifies that reads strictly
// beyond the cursor return the tail in sequence order without gaps.
func TestLogReadAfterCursorNeverSkips(t *testing.T) {
	f := newDBFakeStore()
	runID := "run-1"
	for i := 0; i < 5; i++ {
		if err := f.AppendLog(context.Background(), model.LogEntry{RunID: runID, Line: fmt.Sprintf("l%d", i), CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	stored := append([]model.LogEntry(nil), f.logs...)
	f.mu.Unlock()
	all, err := f.ReadLogs(context.Background(), runID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("read all = %d entries, want 5", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Seq <= all[i-1].Seq {
			t.Fatalf("read order not strictly increasing: %v", seqsOf(all))
		}
	}
	// Reading after the middle cursor yields exactly the tail.
	mid := stored[2].Seq
	tail, err := f.ReadLogs(context.Background(), runID, mid, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 2 || tail[0].Seq != stored[3].Seq || tail[1].Seq != stored[4].Seq {
		t.Fatalf("tail after cursor = %v, want entries 4 and 5", seqsOf(tail))
	}
}

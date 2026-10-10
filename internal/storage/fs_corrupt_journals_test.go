package storage

// Corrupt-journal fail-closed branches for the fs store: a malformed
// execution-events JSONL and a malformed max-seq checkpoint must surface an
// error (never a silent zero or a skipped prefix) on every reader.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestFSCorruptExecutionEventJournalFailsClosed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repo := New(root)
	if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-1", Type: "attempt.created"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, executionEventsFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{not-json\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if _, _, err := repo.PruneExecutionEvents(ctx, time.Now().UTC().Add(time.Hour), 10); err == nil {
		t.Fatal("prune over a corrupt journal succeeded")
	}
	// A fresh instance must fail its startup scan rather than silently
	// truncate the unreadable prefix.
	fresh := New(root)
	if err := fresh.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-1"}); err == nil {
		t.Fatal("append after a restart over a corrupt journal succeeded")
	}
	if _, _, err := repo.ListExecutionEvents(ctx, 0, 10, ""); err == nil {
		t.Fatal("list over a corrupt journal succeeded")
	}
	if _, _, _, _, err := repo.ReadExecutionEventsRetention(ctx, 0, 10, ""); err == nil {
		t.Fatal("retention read over a corrupt journal succeeded")
	}
}

func TestFSMalformedMaxLogSeqCheckpointFailsClosed(t *testing.T) {
	for name, contents := range map[string]string{
		"undecodable": "not-a-number\n",
		"negative":    "-5\n",
	} {
		t.Run(name, func(t *testing.T) {
			repo := New(t.TempDir())
			path := repo.logBatchMaxSeqPath()
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			repo.mu.Lock()
			_, err := repo.initLogBatchMaxSeqLocked()
			repo.mu.Unlock()
			if err == nil {
				t.Fatal("malformed max-seq checkpoint was tolerated")
			}
		})
	}
}

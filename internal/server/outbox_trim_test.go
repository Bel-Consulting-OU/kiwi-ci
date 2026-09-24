package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestTrimDoneLockedBoundsMemory pins the in-memory acked-id trim: only the
// most-recent outboxDoneMaxIDs entries survive, the done map matches, and the
// next compaction threshold is raised.
func TestTrimDoneLockedBoundsMemory(t *testing.T) {
	o := NewOutbox(nil)
	for i := 0; i < outboxDoneMaxIDs+50; i++ {
		id := fmt.Sprintf("id-%d", i)
		o.doneOrder = append(o.doneOrder, id)
		o.done[id] = true
	}
	o.doneCompactAt = len(o.doneOrder) + outboxDoneMaxIDs
	o.trimDoneLocked()
	if len(o.doneOrder) != outboxDoneMaxIDs {
		t.Fatalf("doneOrder = %d, want %d", len(o.doneOrder), outboxDoneMaxIDs)
	}
	if len(o.done) != outboxDoneMaxIDs {
		t.Fatalf("done map = %d, want %d", len(o.done), outboxDoneMaxIDs)
	}
	if o.done["id-0"] {
		t.Fatal("oldest acked id survived the trim")
	}
	if !o.done[fmt.Sprintf("id-%d", outboxDoneMaxIDs+49)] {
		t.Fatal("most-recent acked id was trimmed")
	}
	if o.doneCompactAt != outboxDoneMaxIDs+outboxDoneMaxIDs {
		t.Fatalf("doneCompactAt = %d, want %d", o.doneCompactAt, 2*outboxDoneMaxIDs)
	}
}

// TestCompactDoneIfNeededPaths covers the trigger guard and both compaction
// paths: the in-memory trim when there is no fs journal, and the fs journal
// rewrite (with its error log arm) when a repository is attached.
func TestCompactDoneIfNeededPaths(t *testing.T) {
	// Below the trigger: no-op.
	o := NewOutbox(nil)
	o.doneOrder = []string{"a"}
	o.done["a"] = true
	o.doneCompactAt = 10
	o.compactDoneIfNeeded()
	if len(o.doneOrder) != 1 {
		t.Fatal("below-threshold compaction ran")
	}

	// No store: the in-memory trim path.
	mem := NewOutbox(nil)
	for i := 0; i < outboxDoneMaxIDs+1; i++ {
		id := fmt.Sprintf("m-%d", i)
		mem.doneOrder = append(mem.doneOrder, id)
		mem.done[id] = true
	}
	mem.doneCompactAt = outboxDoneMaxIDs
	mem.compactDoneIfNeeded()
	if len(mem.doneOrder) != outboxDoneMaxIDs {
		t.Fatalf("in-memory compact doneOrder = %d, want %d", len(mem.doneOrder), outboxDoneMaxIDs)
	}

	// With a repository: the fs journal is rewritten.
	dir := t.TempDir()
	fs := NewOutbox(&storage.Repository{Root: dir})
	fs.items = []forge.OutboxItem{{ID: "pending-1"}}
	fs.delivered["logical"] = 3
	for i := 0; i < outboxDoneMaxIDs+1; i++ {
		id := fmt.Sprintf("f-%d", i)
		fs.doneOrder = append(fs.doneOrder, id)
		fs.done[id] = true
	}
	fs.doneCompactAt = outboxDoneMaxIDs
	fs.compactDoneIfNeeded()
	if len(fs.doneOrder) != outboxDoneMaxIDs {
		t.Fatalf("fs compact doneOrder = %d, want %d", len(fs.doneOrder), outboxDoneMaxIDs)
	}
	if _, err := os.Stat(filepath.Join(dir, outboxFile)); err != nil {
		t.Fatalf("pending journal not rewritten: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, outboxDoneFile)); err != nil {
		t.Fatalf("done journal not rewritten: %v", err)
	}

	// A failing rewrite is logged, not fatal (the store root is a file).
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := NewOutbox(&storage.Repository{Root: blocker})
	for i := 0; i < outboxDoneMaxIDs+1; i++ {
		bad.doneOrder = append(bad.doneOrder, fmt.Sprintf("b-%d", i))
	}
	bad.doneCompactAt = outboxDoneMaxIDs
	bad.compactDoneIfNeeded()
}

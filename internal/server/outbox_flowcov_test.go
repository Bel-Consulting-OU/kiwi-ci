package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// fcOutboxStore is a programmable storage.OutboxStore.
type fcOutboxStore struct {
	mu         sync.Mutex
	claimErr   error
	ackErr     error
	pendingErr error
	pending    []storage.OutboxItem
	claims     int
	maxClaims  int
	acked      []string
}

func (f *fcOutboxStore) OutboxHas(ctx context.Context, id string) (bool, error) {
	for _, it := range f.pending {
		if it.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func (f *fcOutboxStore) OutboxAppend(ctx context.Context, e storage.OutboxItem) error { return nil }

func (f *fcOutboxStore) OutboxAck(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ackErr != nil {
		return f.ackErr
	}
	f.acked = append(f.acked, id)
	return nil
}

func (f *fcOutboxStore) OutboxPending(ctx context.Context) ([]storage.OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingErr != nil {
		return nil, f.pendingErr
	}
	return append([]storage.OutboxItem(nil), f.pending...), nil
}

func (f *fcOutboxStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]storage.OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	if f.maxClaims > 0 && f.claims >= f.maxClaims {
		return nil, nil
	}
	f.claims++
	return []storage.OutboxItem{{
		ID:        fmt.Sprintf("batch-item-%d", f.claims),
		Kind:      storage.OutboxKindUsageAccount,
		Payload:   []byte(`{"job_id":"gone"}`),
		CreatedAt: time.Now().UTC(),
	}}, nil
}

func (f *fcOutboxStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error { return nil }

func TestFlowOutboxReplayDBBranches(t *testing.T) {
	if err := NewOutbox(nil).ReplayDB(context.Background()); err != nil {
		t.Fatalf("replay without db = %v", err)
	}
	os := &fcOutboxStore{pendingErr: errors.New("pending read down")}
	o := NewOutbox(nil)
	o.db = os
	if err := o.ReplayDB(context.Background()); err == nil {
		t.Fatal("replay pending failure must propagate")
	}
	// Duplicate IDs are skipped; new IDs are appended in FIFO order.
	o2 := NewOutbox(nil)
	o2.db = &fcOutboxStore{pending: []storage.OutboxItem{
		{ID: "dup", Kind: storage.OutboxKindUsageAccount},
		{ID: "fresh", Kind: storage.OutboxKindRunAggregate},
	}}
	o2.items = []forge.OutboxItem{{ID: "dup", Kind: storage.OutboxKindUsageAccount}}
	if err := o2.ReplayDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending := o2.Pending()
	if len(pending) != 2 || pending[0].ID != "dup" || pending[1].ID != "fresh" {
		t.Fatalf("replayed items = %+v", pending)
	}
}

func TestFlowOutboxReadItemsErrors(t *testing.T) {
	// A directory where the JSONL file belongs: decode failure.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, outboxFile), 0o700); err != nil {
		t.Fatal(err)
	}
	o := NewOutbox(storage.New(root))
	if len(o.Pending()) != 0 {
		t.Fatal("corrupt JSONL must start empty")
	}
	if _, err := o.readItems(); err == nil {
		t.Fatal("directory decode must be an error")
	}
	// An open failure that is not ENOENT: every path under a regular file
	// resolves to ENOTDIR, which the OS reports for any euid.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	o2 := NewOutbox(nil)
	o2.store = storage.New(filepath.Join(blocker, "data"))
	if _, err := o2.readItems(); err == nil {
		t.Fatal("unreadable root must be an error")
	}
	if err := o2.loadLocked(); err == nil {
		t.Fatal("load with unreadable root must be an error")
	}
}

func TestFlowOutboxEnqueueLocalBranches(t *testing.T) {
	o := NewOutbox(nil)
	o.EnqueueLocal(forge.OutboxItem{ID: "a", Kind: forge.OutboxKindWebhookCall})
	if o.Pending()[0].CreatedAt.IsZero() {
		t.Fatal("EnqueueLocal must stamp CreatedAt")
	}
	o.EnqueueLocal(forge.OutboxItem{ID: "a", Kind: forge.OutboxKindWebhookCall})
	if len(o.Pending()) != 1 {
		t.Fatal("duplicate ID must be skipped")
	}
}

func TestFlowOutboxAppendJSONLBranches(t *testing.T) {
	o := NewOutbox(nil)
	if err := o.appendJSONLLocked("x.jsonl", map[string]string{"a": "b"}); err != nil {
		t.Fatalf("nil store append = %v", err)
	}
	// Encode failure.
	root := t.TempDir()
	o2 := NewOutbox(storage.New(root))
	if err := o2.appendJSONLLocked("x.jsonl", make(chan int)); err == nil {
		t.Fatal("unencodable value must fail")
	}
	// Open failure: a directory at the append path is rejected by the OS for
	// every euid.
	blocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(blocked, "x.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	o3 := NewOutbox(nil)
	o3.store = storage.New(blocked)
	if err := o3.appendJSONLLocked("x.jsonl", map[string]string{"a": "b"}); err == nil {
		t.Fatal("directory at the append path must fail the append")
	}
	// Durable-first: Enqueue surfaces the persistence error and the item is
	// NOT queued — the side effect must never be dispatchable before the
	// record of it exists. A store root under a regular file fails MkdirAll
	// for every euid, so this holds under root too.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	o4 := NewOutbox(nil)
	o4.store = storage.New(filepath.Join(blocker, "data"))
	if err := o4.Enqueue(context.Background(), forge.OutboxItem{Kind: forge.OutboxKindWebhookCall}); err == nil {
		t.Fatal("Enqueue must surface the fs persistence error")
	}
	if len(o4.Pending()) != 0 {
		t.Fatal("failed persistence must not queue the item")
	}
}

func TestFlowOutboxFlushNilDispatch(t *testing.T) {
	o := NewOutbox(nil)
	if n, err := o.Flush(context.Background(), nil); n != 0 || err != nil {
		t.Fatalf("nil dispatch flush = %d %v", n, err)
	}
}

func TestFlowOutboxDBBatchBound(t *testing.T) {
	store := &fcOutboxStore{}
	o := NewOutbox(nil)
	o.db = store
	d := newOutboxDispatcher()
	n, err := o.Flush(context.Background(), d.dispatch)
	if err != nil {
		t.Fatal(err)
	}
	if n != outboxFlushMaxBatches {
		t.Fatalf("batched flush dispatched %d, want %d", n, outboxFlushMaxBatches)
	}
	if store.claims != outboxFlushMaxBatches {
		t.Fatalf("claims = %d, want %d", store.claims, outboxFlushMaxBatches)
	}
	if got := len(store.acked); got != outboxFlushMaxBatches {
		t.Fatalf("acks = %d, want %d", got, outboxFlushMaxBatches)
	}
}

func TestFlowOutboxDBClaimError(t *testing.T) {
	o := NewOutbox(nil)
	o.db = &fcOutboxStore{claimErr: errors.New("claim down")}
	if _, err := o.Flush(context.Background(), func(context.Context, forge.OutboxItem) error { return nil }); err == nil {
		t.Fatal("claim failure must propagate")
	}
}

func TestFlowOutboxDBPrunePendingError(t *testing.T) {
	store := &fcOutboxStore{pendingErr: errors.New("pending read down"), maxClaims: 1}
	o := NewOutbox(nil)
	o.db = store
	n, err := o.Flush(context.Background(), func(context.Context, forge.OutboxItem) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("flush dispatched %d, want 1", n)
	}
}

func TestFlowOutboxDispatchKinds(t *testing.T) {
	s := New("tok")
	ctx := context.Background()
	if err := s.dispatchOutbox(ctx, forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{")}); err == nil {
		t.Fatal("bad check payload must fail")
	}
	if err := s.dispatchOutbox(ctx, forge.OutboxItem{Kind: forge.OutboxKindGitHubStatus, Payload: []byte("{")}); err == nil {
		t.Fatal("bad status payload must fail")
	}
	if err := s.dispatchOutbox(ctx, forge.OutboxItem{Kind: forge.OutboxKindDownstream, Payload: []byte("{")}); err == nil {
		t.Fatal("bad downstream payload must fail")
	}
	if err := s.dispatchOutbox(ctx, forge.OutboxItem{Kind: storage.OutboxKindUsageAccount, Payload: []byte("{")}); err == nil {
		t.Fatal("bad completion effect payload must fail")
	}
	if err := s.dispatchOutbox(ctx, forge.OutboxItem{Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":""}`)}); err != nil {
		t.Fatalf("empty effect job id must be dropped silently: %v", err)
	}
	if err := s.dispatchOutbox(ctx, forge.OutboxItem{Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":"gone"}`)}); err != nil {
		t.Fatalf("missing job effect must reconcile to a no-op: %v", err)
	}
	if err := s.dispatchOutbox(ctx, forge.OutboxItem{ID: "w", Kind: forge.OutboxKindWebhookCall, Payload: []byte(`{}`)}); err != nil {
		t.Fatalf("webhook call must be dropped: %v", err)
	}
	// An unknown kind must NOT be dropped (that would ACK it away) or
	// dead-lettered: the typed error keeps the row durable for a newer
	// replica during a rolling upgrade.
	unknown := s.dispatchOutbox(ctx, forge.OutboxItem{ID: "u", Kind: "unknown-kind", Payload: []byte(`{}`)})
	if !errors.Is(unknown, errUnknownOutboxKind) {
		t.Fatalf("unknown kind = %v, want errUnknownOutboxKind", unknown)
	}
	// Well-formed check/status payloads reach the forge adapter; without a
	// configured forge they resolve to an error or a no-op, never a panic.
	_ = s.dispatchOutbox(ctx, forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{"repo_full_name":"o/r","sha":"abc"}`)})
	_ = s.dispatchOutbox(ctx, forge.OutboxItem{Kind: forge.OutboxKindGitHubStatus, Payload: []byte(`{"repo_full_name":"o/r","sha":"abc"}`)})
}

package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// publicationBarrier is the deterministic Save-vs-mutation seam: it replaces
// atomicWriteFile with a function that, on the first call, records whether the
// token-state WRITE lock was free while Save was publishing (it must not be),
// signals that publication has begun, and blocks until released. No sleeps and
// no wall-clock ordering are involved: the test holds Save inside publication
// while it drives the mutation.
type publicationBarrier struct {
	entered chan struct{}
	release chan struct{}

	mu    sync.Mutex
	calls int
	free  bool
}

func newPublicationBarrier() *publicationBarrier {
	return &publicationBarrier{entered: make(chan struct{}), release: make(chan struct{})}
}

// install points the Save durability seam at the barrier for the test's
// lifetime.
func (b *publicationBarrier) install(t *testing.T, store *TokenStore) {
	t.Helper()
	prev := atomicWriteFile
	atomicWriteFile = func(path string, data []byte, mode os.FileMode) error {
		b.mu.Lock()
		b.calls++
		first := b.calls == 1
		b.mu.Unlock()
		if first {
			// The fixed Save holds store.mu's read lock here, so a mutation
			// can never acquire the write lock while an older snapshot is in
			// publication. In the pre-fix implementation the lock is free and
			// this TryLock succeeds: the barrier records the defect and the
			// test fails deterministically.
			if store.mu.TryLock() {
				store.mu.Unlock()
				b.mu.Lock()
				b.free = true
				b.mu.Unlock()
			}
			close(b.entered)
			<-b.release
		}
		return prev(path, data, mode)
	}
	t.Cleanup(func() { atomicWriteFile = prev })
}

func (b *publicationBarrier) lockWasFree() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.free
}

// crashLoad reads path into a fresh store, modeling a process restart from the
// durable file.
func crashLoad(t *testing.T, path string) *TokenStore {
	t.Helper()
	out := NewTokenStore()
	if err := out.Load(path); err != nil {
		t.Fatalf("crash reload: %v", err)
	}
	return out
}

// TestSaveSerializesAgainstRemoveToken is the X3-C deterministic regression
// for revocation: while a Save is publishing, RemoveToken must not complete.
// Pre-fix, Save snapshots the map, releases the read lock, RemoveToken revokes
// in memory and returns success, and Save then publishes the OLD snapshot — a
// crash would resurrect the revoked token. The barrier makes the interleaving
// explicit: the pre-fix write lock is free during publication (recorded), the
// mutation completes mid-save (observed by the non-blocking select), and the
// crash reload would still carry the token.
func TestSaveSerializesAgainstRemoveToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	store := NewTokenStore()
	if err := store.AddToken("revoke-me", Principal{Subject: "s", Roles: []Role{RoleRun}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	barrier := newPublicationBarrier()
	barrier.install(t, store)
	saveDone := make(chan error, 1)
	go func() { saveDone <- store.Save(path) }()
	<-barrier.entered

	removeDone := make(chan bool, 1)
	go func() { removeDone <- store.RemoveToken("revoke-me") }()

	// The mutation needs the write lock Save holds for reading: it cannot have
	// completed while publication is still blocked.
	select {
	case <-removeDone:
		t.Fatal("RemoveToken completed while Save was publishing an older snapshot")
	default:
	}
	if barrier.lockWasFree() {
		t.Fatal("token-state write lock was free during publication: a mutation can complete mid-save")
	}

	close(barrier.release)
	if err := <-saveDone; err != nil {
		t.Fatalf("blocked Save: %v", err)
	}
	if !<-removeDone {
		t.Fatal("RemoveToken did not revoke the token")
	}

	// Make the acknowledged revocation durable and prove a restart from the
	// durable file cannot resurrect the token.
	if err := store.Save(path); err != nil {
		t.Fatalf("save after revoke: %v", err)
	}
	if _, ok := crashLoad(t, path).Authenticate("revoke-me"); ok {
		t.Fatal("crash restore resurrected a revoked token")
	}
	assertOnlyTokenFile(t, dir, path)
}

// TestSaveSerializesAgainstAddToken is the X3-C deterministic regression for
// addition: an AddToken that returned success can never be lost by a Save that
// was already in flight. Pre-fix, AddToken completes while Save is between its
// snapshot and publication, and Save then publishes the pre-add snapshot.
func TestSaveSerializesAgainstAddToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	store := NewTokenStore()
	if err := store.Save(path); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	barrier := newPublicationBarrier()
	barrier.install(t, store)
	saveDone := make(chan error, 1)
	go func() { saveDone <- store.Save(path) }()
	<-barrier.entered

	addDone := make(chan error, 1)
	go func() { addDone <- store.AddToken("grant-me", Principal{Subject: "s", Roles: []Role{RoleRun}}) }()

	select {
	case <-addDone:
		t.Fatal("AddToken completed while Save was publishing an older snapshot")
	default:
	}
	if barrier.lockWasFree() {
		t.Fatal("token-state write lock was free during publication: a mutation can complete mid-save")
	}

	close(barrier.release)
	if err := <-saveDone; err != nil {
		t.Fatalf("blocked Save: %v", err)
	}
	if err := <-addDone; err != nil {
		t.Fatalf("AddToken: %v", err)
	}

	if err := store.Save(path); err != nil {
		t.Fatalf("save after add: %v", err)
	}
	if _, ok := crashLoad(t, path).Authenticate("grant-me"); !ok {
		t.Fatal("crash restore lost an acknowledged token addition")
	}
	assertOnlyTokenFile(t, dir, path)
}

// TestSaveConcurrentMutationsStayIntact exercises the new serialization under
// real concurrency (run under -race): saves and mutations race, every call
// must succeed, and the final durable file must be one intact JSON snapshot
// with no scratch files left behind.
func TestSaveConcurrentMutationsStayIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	store := NewTokenStore()
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	const workers = 6
	const rounds = 24
	start := make(chan struct{})
	errs := make(chan error, workers*2)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < rounds; i++ {
				raw := fmt.Sprintf("tok-%d-%d", w, i)
				if err := store.AddToken(raw, Principal{Subject: fmt.Sprintf("s-%d-%d", w, i), Roles: []Role{RoleRead}}); err != nil {
					errs <- err
					return
				}
				store.RemoveToken(raw)
			}
		}(w)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < rounds; i++ {
				if err := store.Save(path); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent save/mutation: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]Principal
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("final durable file is not intact JSON (%d bytes): %v", len(b), err)
	}
	assertOnlyTokenFile(t, dir, path)
}

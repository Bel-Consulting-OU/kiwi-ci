package server

// Dispatch-level branch coverage for the outbox dispatcher: the fail-closed
// forge-check guard contract (both outside and INSIDE the publication fence),
// the superseded-skip inside the fence, and the legacy/attestation intents
// with unknown or empty job identities. Calls go through the package-private
// dispatcher with crafted intents, so no external forge API is contacted.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func outboxDispatchItem(t *testing.T, kind string, payload any) forge.OutboxItem {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return forge.OutboxItem{ID: "outbox-branch-1", Kind: kind, Payload: b, CreatedAt: time.Now().UTC()}
}

// flakyGuardStore delegates to dbFakeStore but answers the version-guard
// calls from a script, so the guard can pass the pre-fence check and then
// change its answer INSIDE the fence (the race the fence exists to close).
type flakyGuardStore struct {
	*dbFakeStore
	answers []struct {
		ok  bool
		err error
	}
	calls int
}

func (f *flakyGuardStore) OutboxVersionGuard(context.Context, string, string, int64) (bool, error) {
	i := f.calls
	f.calls++
	if i >= len(f.answers) {
		i = len(f.answers) - 1
	}
	a := f.answers[i]
	return a.ok, a.err
}

func newDispatchServer(t *testing.T, db storage.Store) *Server {
	t.Helper()
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.DB = db
	return s
}

func TestDispatchOutboxForgeCheckGuardInFence(t *testing.T) {
	ctx := context.Background()
	payload := forge.CheckPayload{RunID: "run-1", ForgeKind: "github", RepoFullName: "acme/backend", SHA: "sha", Name: "build", Status: "completed"}

	checkKinds := []struct {
		kind    string
		forge   string
		base    *dbFakeStore
		newItem func() forge.OutboxItem
	}{
		{forge.OutboxKindGitHubCheck, "github", newDBFakeStore(), func() forge.OutboxItem {
			p := payload
			return outboxDispatchItem(t, forge.OutboxKindGitHubCheck, p)
		}},
		{forge.OutboxKindGitLabCheck, "gitlab", newDBFakeStore(), func() forge.OutboxItem {
			p := payload
			p.ForgeKind = "gitlab"
			return outboxDispatchItem(t, forge.OutboxKindGitLabCheck, p)
		}},
		{forge.OutboxKindForgejoCheck, "forgejo", newDBFakeStore(), func() forge.OutboxItem {
			p := payload
			p.ForgeKind = "forgejo"
			return outboxDispatchItem(t, forge.OutboxKindForgejoCheck, p)
		}},
	}

	for _, tc := range checkKinds {
		t.Run(tc.kind+"/guard error inside fence", func(t *testing.T) {
			f := &flakyGuardStore{dbFakeStore: tc.base, answers: []struct {
				ok  bool
				err error
			}{{ok: true}, {err: errors.New("injected guard failure")}}}
			s := newDispatchServer(t, f)
			err := s.dispatchOutbox(ctx, tc.newItem())
			if err == nil || !strings.Contains(err.Error(), "injected guard failure") {
				t.Fatalf("dispatch = %v, want the in-fence guard failure", err)
			}
			if f.calls < 2 {
				t.Fatalf("guard calls = %d, want the in-fence re-check", f.calls)
			}
		})

		t.Run(tc.kind+"/superseded inside fence", func(t *testing.T) {
			f := &flakyGuardStore{dbFakeStore: tc.base, answers: []struct {
				ok  bool
				err error
			}{{ok: true}, {ok: false}}}
			s := newDispatchServer(t, f)
			if err := s.dispatchOutbox(ctx, tc.newItem()); err != nil {
				t.Fatalf("superseded dispatch = %v, want nil (skip)", err)
			}
			if f.calls < 2 {
				t.Fatalf("guard calls = %d, want the in-fence re-check", f.calls)
			}
		})

		t.Run(tc.kind+"/guard contract missing", func(t *testing.T) {
			// A store that hides the versioned guard contract must fail
			// closed BEFORE any publication for every forge-check kind.
			s := newDispatchServer(t, noAtomicEnqueueStore{newDBFakeStore()})
			err := s.dispatchOutbox(ctx, tc.newItem())
			if err == nil || !strings.Contains(err.Error(), "guard contract") {
				t.Fatalf("dispatch without the guard contract = %v, want fail-closed", err)
			}
		})
	}
}

func TestDispatchOutboxLegacyAndAttestationIntents(t *testing.T) {
	ctx := context.Background()
	s := newDispatchServer(t, newDBFakeStore())

	// Execution attestation with an empty job identity is dropped, never
	// dispatched against an unknown job.
	empty := storage.CompletionEffectsPayload{JobID: ""}
	item := outboxDispatchItem(t, "execution_attest", empty)
	if err := s.dispatchOutbox(ctx, item); err != nil {
		t.Fatalf("empty attestation intent = %v, want dropped", err)
	}
	// A legacy forge_status row with an unknown job converges to nil (the
	// job was already pruned; nothing remains to mirror).
	known := storage.CompletionEffectsPayload{JobID: "11111111111111111111111111111111", Generation: 1}
	item = outboxDispatchItem(t, "forge_status", known)
	if err := s.dispatchOutbox(ctx, item); err != nil {
		t.Fatalf("unknown-job forge_status = %v, want nil", err)
	}
	// Legacy completion-effect kinds with an empty job id are dropped.
	item = outboxDispatchItem(t, "run_aggregate", empty)
	if err := s.dispatchOutbox(ctx, item); err != nil {
		t.Fatalf("empty legacy effect = %v, want dropped", err)
	}
	// An unknown kind fails closed so a newer replica owns it.
	item = outboxDispatchItem(t, "future_kind", empty)
	err := s.dispatchOutbox(ctx, item)
	var unknown *unknownOutboxKindError
	if !errors.As(err, &unknown) {
		t.Fatalf("unknown kind = %v, want *unknownOutboxKindError", err)
	}
	// A payload that cannot decode is a hard error for every decode path.
	for _, kind := range []string{forge.OutboxKindGitHubCheck, forge.OutboxKindGitLabCheck, forge.OutboxKindForgejoCheck, "execution_attest", "forge_status"} {
		bad := forge.OutboxItem{ID: "bad", Kind: kind, Payload: []byte("{"), CreatedAt: time.Now().UTC()}
		if err := s.dispatchOutbox(ctx, bad); err == nil {
			t.Fatalf("kind %s: undecodable payload accepted", kind)
		}
	}
}

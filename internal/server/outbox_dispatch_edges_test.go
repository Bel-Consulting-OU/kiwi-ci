package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestDispatchOutboxDropAndDecodeArms covers every decode-error, wrong-forge
// and empty-identity drop arm of the intent dispatcher without touching a
// remote forge.
func TestDispatchOutboxDropAndDecodeArms(t *testing.T) {
	ctx := context.Background()
	s := New("runner-tok")
	bad := []byte("{not json")

	cases := []struct {
		name    string
		item    forge.OutboxItem
		wantErr bool
	}{
		{"github check decode", forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: bad}, true},
		{"github check wrong forge", forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{"forge_kind":"gitlab"}`)}, false},
		{"gitlab check decode", forge.OutboxItem{Kind: forge.OutboxKindGitLabCheck, Payload: bad}, true},
		{"gitlab check wrong forge", forge.OutboxItem{Kind: forge.OutboxKindGitLabCheck, Payload: []byte(`{"forge_kind":"github"}`)}, false},
		{"forgejo check decode", forge.OutboxItem{Kind: forge.OutboxKindForgejoCheck, Payload: bad}, true},
		{"forgejo check wrong forge", forge.OutboxItem{Kind: forge.OutboxKindForgejoCheck, Payload: []byte(`{"forge_kind":"github"}`)}, false},
		{"status decode", forge.OutboxItem{Kind: forge.OutboxKindGitHubStatus, Payload: bad}, true},
		{"completion reconcile decode", forge.OutboxItem{Kind: storage.OutboxKindCompletionReconcile, Payload: bad}, true},
		{"completion reconcile empty job", forge.OutboxItem{Kind: storage.OutboxKindCompletionReconcile, Payload: []byte(`{"job_id":""}`)}, false},
		{"forge delivery decode", forge.OutboxItem{Kind: storage.OutboxKindForgeDelivery, Payload: bad}, true},
		{"forge delivery empty job", forge.OutboxItem{Kind: storage.OutboxKindForgeDelivery, Payload: []byte(`{}`)}, false},
		{"forge status decode", forge.OutboxItem{Kind: storage.OutboxKindForgeStatus, Payload: bad}, true},
		{"forge status empty job", forge.OutboxItem{Kind: storage.OutboxKindForgeStatus, Payload: []byte(`{}`)}, false},
		{"legacy completion effect empty job", forge.OutboxItem{Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{}`)}, false},
		{"reserved webhook dropped", forge.OutboxItem{Kind: forge.OutboxKindWebhookCall, ID: "w"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.dispatchOutbox(ctx, tc.item)
			if (err != nil) != tc.wantErr {
				t.Fatalf("dispatchOutbox = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}

	// An unknown kind is preserved with a typed error, never dropped.
	err := s.dispatchOutbox(ctx, forge.OutboxItem{Kind: "future-kind", ID: "u1"})
	var unknown *unknownOutboxKindError
	if !errors.As(err, &unknown) || unknown.kind != "future-kind" {
		t.Fatalf("unknown kind = %v, want unknownOutboxKindError", err)
	}
}

// TestForgeCheckIdentityAndGuardContracts covers the identity derivation and
// the fail-closed guard when the store lacks the versioned contract.
func TestForgeCheckIdentityAndGuardContracts(t *testing.T) {
	ctx := context.Background()

	// Payload-carried identity.
	key, version, legacy, ok := forgeCheckIdentity(forge.OutboxItem{}, forge.CheckPayload{LogicalKey: "lk", StateVersion: 4})
	if !ok || legacy || key != "lk" || version != 4 {
		t.Fatalf("payload identity = (%q,%d,%v,%v)", key, version, legacy, ok)
	}
	// Missing coordinates: no identity.
	if _, _, _, ok := forgeCheckIdentity(forge.OutboxItem{}, forge.CheckPayload{}); ok {
		t.Fatal("identity without coordinates was reported ok")
	}
	// Legacy derivation from run + name + status rank.
	legacyItem := forge.OutboxItem{ID: "i1"}
	legacyPayload := forge.CheckPayload{RunID: "run-1", Name: "build", Status: "completed"}
	key, version, legacy, ok = forgeCheckIdentity(legacyItem, legacyPayload)
	if !ok || !legacy || key == "" || version <= 0 {
		t.Fatalf("legacy identity = (%q,%d,%v,%v)", key, version, legacy, ok)
	}

	s := New("runner-tok")
	// A versioned row needs no explicit stamp.
	if err := s.markForgeCheckDelivered(ctx, forge.OutboxItem{}, forge.CheckPayload{LogicalKey: "lk", StateVersion: 1}); err != nil {
		t.Fatalf("versioned stamp = %v", err)
	}
	// A legacy row with no DB stamps the fs watermark.
	if err := s.markForgeCheckDelivered(ctx, legacyItem, legacyPayload); err != nil {
		t.Fatalf("fs legacy stamp = %v", err)
	}

	// A store without the versioned guard contract fails both paths closed.
	s.DB = fcPlainStore{newDBFakeStore()}
	if err := s.markForgeCheckDelivered(ctx, legacyItem, legacyPayload); err == nil {
		t.Fatal("legacy stamp without the store contract succeeded")
	}
	if _, err := s.forgeCheckDispatchable(ctx, legacyItem, legacyPayload); err == nil {
		t.Fatal("dispatch guard without the store contract succeeded")
	}
}

// TestFenceVersionedCheckArms covers the unversioned fast path and the
// superseded-inside-the-fence arm.
func TestFenceVersionedCheckArms(t *testing.T) {
	ctx := context.Background()
	s := New("runner-tok")

	// No run identity: publish immediately with a no-op release.
	publish, release, err := s.fenceVersionedCheck(ctx, forge.OutboxItem{}, forge.CheckPayload{})
	if !publish || err != nil || release == nil {
		t.Fatalf("unversioned fence = (publish=%v releaseNil=%v err=%v)", publish, release == nil, err)
	}
	release()

	// A superseded version inside the fence retires the row.
	item := forge.OutboxItem{ID: "i2", LogicalKey: "lk", StateVersion: 3}
	p := forge.CheckPayload{RunID: "run-1", Name: "build", LogicalKey: "lk", StateVersion: 3}
	if err := s.outbox.MarkDelivered("lk", 9); err != nil {
		t.Fatal(err)
	}
	publish, release, err = s.fenceVersionedCheck(ctx, item, p)
	if err != nil {
		t.Fatalf("fence error: %v", err)
	}
	if publish {
		t.Fatal("superseded version was scheduled for publication")
	}
	release()

	// A malformed legacy row with no derivable identity is published.
	noID := forge.OutboxItem{ID: "i3"}
	if publish, release, err := s.fenceVersionedCheck(ctx, noID, forge.CheckPayload{RunID: "run-1"}); err != nil || !publish {
		t.Fatalf("identity-less fence = (%v,%v)", publish, err)
	} else {
		release()
	}

	_ = strings.TrimSpace("")
}

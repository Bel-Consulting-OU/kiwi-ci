package fake_forge

import (
	"encoding/json"
	"testing"
)

// TestForgeDeliveryAndStatus: the hermetic forge emulator accepts a correctly
// signed event once, flags a duplicate delivery, refuses a bad signature, and
// records status callbacks the oracle can count.
func TestForgeDeliveryAndStatus(t *testing.T) {
	f := New(Config{Secret: "dogfood-secret"})
	f.OnEvent(func(Event) error { return nil })

	ev := Event{Type: EventPush, Repo: "df/repo", Commit: "abc", Ref: "refs/heads/main", Sender: "dogfood"}
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	sig := f.Sign(payload)
	res, err := f.Deliver("e1", ev, sig)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !res.Accepted {
		t.Fatalf("delivery rejected: %+v", res)
	}
	dup, err := f.Deliver("e1", ev, sig)
	if err != nil {
		t.Fatalf("duplicate Deliver: %v", err)
	}
	if !dup.Duplicate {
		t.Fatalf("re-delivery not marked duplicate: %+v", dup)
	}
	if f.AcceptedCount() != 1 {
		t.Fatalf("accepted count = %d, want 1", f.AcceptedCount())
	}
	if res, err := f.Deliver("e2", Event{Type: EventPR, Repo: "df/repo", Commit: "def", PR: 7, Sender: "dogfood"}, "nope"); err == nil && res.Accepted {
		t.Fatal("bad signature must be refused")
	}
	f.Status("df/repo", "abc", "success", "ci/unit")
	if len(f.Statuses()) != 1 {
		t.Fatalf("statuses = %+v", f.Statuses())
	}
}

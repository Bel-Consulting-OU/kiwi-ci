package queue

import "testing"

func TestDefaultMessageFallback(t *testing.T) {
	got := New(ReasonCode("SOMETHING_NEW"), "")
	if got.Message != "waiting to be scheduled" {
		t.Fatalf("fallback message = %q", got.Message)
	}
	if s := got.String(); s != "SOMETHING_NEW: waiting to be scheduled" {
		t.Fatalf("String = %q", s)
	}
	explicit := New(ReasonCode("SOMETHING_NEW"), "custom")
	if explicit.Message != "custom" {
		t.Fatalf("explicit message = %q", explicit.Message)
	}
}

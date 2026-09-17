package model

import "testing"

func TestStatusTerminal(t *testing.T) {
	terminal := []Status{StatusSuccess, StatusFailure, StatusCancelled, StatusSkipped, StatusBlocked}
	for _, s := range terminal {
		if !s.Terminal() {
			t.Errorf("%s must be terminal", s)
		}
	}
	active := []Status{StatusPending, StatusQueued, StatusWaitingApproval, StatusRunning, Status("unknown")}
	for _, s := range active {
		if s.Terminal() {
			t.Errorf("%s must not be terminal", s)
		}
	}
}

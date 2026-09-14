package queue

import "testing"

func TestQueueReasonCodes(t *testing.T) {
	codes := []ReasonCode{
		NoCompatibleRunner, RunnerCapacity, RegionUnavailable,
		WaitingDependency, WaitingApproval, EnvironmentLocked,
		RepoQuota, TeamQuota, ConcurrencyGroup,
	}
	seen := map[ReasonCode]bool{}
	for _, c := range codes {
		if c == None || c == "" {
			t.Fatalf("invalid code %q", c)
		}
		if seen[c] {
			t.Fatalf("duplicate code %q", c)
		}
		seen[c] = true
		if New(c, "").Message == "" {
			t.Fatalf("code %q has no default message", c)
		}
	}
}

func TestQueueReasonString(t *testing.T) {
	if got := New(WaitingDependency, "job b still running").String(); got != "WAITING_DEPENDENCY: job b still running" {
		t.Fatalf("String: %q", got)
	}
	if got := (QueueReason{Code: RepoQuota}).String(); got != "REPO_QUOTA" {
		t.Fatalf("String: %q", got)
	}
	if got := (QueueReason{Code: None}).String(); got != "" {
		t.Fatalf("String: %q", got)
	}
}

package storage

// T1-1/T1-4/T1-5 unit regressions: the lifecycle-aware classification, the
// raw-value quarantine hash, and the batch-size contract. These are the
// hermetic halves of the T1-6 regressions; the live-PostgreSQL halves live in
// postgres_repo_identity_repair_t1_it_test.go and
// postgres_repo_identity_repair_t1_cancel_it_test.go.

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestClassifyRepoIdentityLifecycle is the T1-1 planner regression: the SAME
// provable identity change is rewrite_terminal on a terminal row and
// active_requires_drain on ANY non-terminal row, with Desired always carrying
// the terminal action a --cancel-active pass would apply.
func TestClassifyRepoIdentityLifecycle(t *testing.T) {
	rewriteEvidence := func() (string, string, string) {
		return "github.com/acme/a", "https://github.com/acme/b.git", "acme/b"
	}
	quarantineEvidence := func() (string, string, string) {
		return "group/sub/project", "", ""
	}
	cases := []struct {
		name      string
		status    model.Status
		evidence  func() (string, string, string)
		wantAct   RepoIdentityRepairAction
		wantDesir RepoIdentityRepairAction
	}{
		{"rewrite terminal", model.StatusSuccess, rewriteEvidence, RepoIdentityRewriteTerminal, RepoIdentityRewriteTerminal},
		{"rewrite running", model.StatusRunning, rewriteEvidence, RepoIdentityActiveRequiresDrain, RepoIdentityRewriteTerminal},
		{"rewrite queued", model.StatusQueued, rewriteEvidence, RepoIdentityActiveRequiresDrain, RepoIdentityRewriteTerminal},
		{"rewrite pending", model.StatusPending, rewriteEvidence, RepoIdentityActiveRequiresDrain, RepoIdentityRewriteTerminal},
		{"rewrite waiting_approval", model.StatusWaitingApproval, rewriteEvidence, RepoIdentityActiveRequiresDrain, RepoIdentityRewriteTerminal},
		{"quarantine terminal", model.StatusFailure, quarantineEvidence, RepoIdentityQuarantineTerminal, RepoIdentityQuarantineTerminal},
		{"quarantine running", model.StatusRunning, quarantineEvidence, RepoIdentityActiveRequiresDrain, RepoIdentityQuarantineTerminal},
		{"quarantine queued", model.StatusQueued, quarantineEvidence, RepoIdentityActiveRequiresDrain, RepoIdentityQuarantineTerminal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored, url, full := tc.evidence()
			plan := ClassifyRepoIdentity(stored, url, full, tc.status)
			if plan.Action != tc.wantAct {
				t.Fatalf("ClassifyRepoIdentity(%q,%q,%q,%q).Action = %v, want %v", stored, url, full, tc.status, plan.Action, tc.wantAct)
			}
			if plan.Desired != tc.wantDesir {
				t.Fatalf("ClassifyRepoIdentity(%q,%q,%q,%q).Desired = %v, want %v", stored, url, full, tc.status, plan.Desired, tc.wantDesir)
			}
		})
	}
	// A keep is never active, whatever the lifecycle status.
	if got := ClassifyRepoIdentity("github.com/acme/a", "https://github.com/acme/a.git", "acme/a", model.StatusRunning); got.Action != RepoIdentityKeep || got.Desired != RepoIdentityKeep {
		t.Fatalf("canonical running row = %+v, want keep/keep", got)
	}
}

// TestQuarantinedRepoIdentityRawWhitespaceDistinct is the T1-4 regression at
// the helper level (the live-table half is in the IT file): hashing the RAW
// value keeps whitespace variants distinct, and classification still trims so
// the planner reaches the same branch for all of them.
func TestQuarantinedRepoIdentityRawWhitespaceDistinct(t *testing.T) {
	variants := []string{"group/sub/project", " group/sub/project", "group/sub/project ", "\tgroup/sub/project\n"}
	seen := map[string]string{}
	for _, v := range variants {
		q := QuarantinedRepoIdentity(v)
		if prev, ok := seen[q]; ok {
			t.Fatalf("raw whitespace variants %q and %q collapsed to one quarantine id %q", prev, v, q)
		}
		seen[q] = v
		if strings.Contains(q, strings.TrimSpace(v)) {
			t.Fatalf("quarantine id %q embeds the original", q)
		}
	}
	// The identity-only planner still trims: every whitespace variant of an
	// unprovable stored value quarantines to the RAW-value identity.
	for _, v := range variants {
		plan := PlanStoredRepoIdentity(v, "", "")
		if plan.Action != RepoIdentityQuarantine {
			t.Fatalf("PlanStoredRepoIdentity(%q) action = %v, want quarantine", v, plan.Action)
		}
		if plan.Explicit != QuarantinedRepoIdentity(v) {
			t.Fatalf("PlanStoredRepoIdentity(%q).Explicit = %q, want raw-value identity", v, plan.Explicit)
		}
	}
}

// TestClampRepoIdentityRepairBatchSize pins the T1-5 documented contract: the
// resolved batch size is clamped to [1, 2000], with small explicit values
// honored (test/diagnostic seam) and the operator-recommended range 500..2000.
func TestClampRepoIdentityRepairBatchSize(t *testing.T) {
	cases := map[int]int{
		-100:    1,
		0:       1,
		1:       1,
		2:       2,
		499:     499,
		500:     500,
		1000:    1000,
		2000:    2000,
		2001:    2000,
		1 << 20: 2000,
	}
	for in, want := range cases {
		if got := clampRepoIdentityRepairBatchSize(in); got != want {
			t.Fatalf("clampRepoIdentityRepairBatchSize(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestQuarantinedRepoIdentityIsRawSHA256 confirms the exact digest input.
func TestQuarantinedRepoIdentityIsRawSHA256(t *testing.T) {
	raw := " group/sub/project "
	q := QuarantinedRepoIdentity(raw)
	trimmed := auth.RepoAlias{FullName: "group/sub/project"}.Serialized()
	if strings.Contains(q, trimmed) {
		t.Fatalf("quarantine id %q embeds a trimmed/derived form", q)
	}
	if q == QuarantinedRepoIdentity(strings.TrimSpace(raw)) {
		t.Fatalf("quarantine id for %q equals the trimmed value's id; the hash is not raw", raw)
	}
}

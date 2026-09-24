package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestRepairRepoIdentitiesCancelActiveFlagParses proves the new
// --cancel-active option is part of the command surface: with it set and no
// --database-url the command fails on the REQUIRED url (not on an unknown
// flag), so the flag is genuinely parsed and forwarded.
func TestRepairRepoIdentitiesCancelActiveFlagParses(t *testing.T) {
	var out bytes.Buffer
	err := repairRepoIdentities(context.Background(), []string{"--cancel-active"}, &out)
	if err == nil || !strings.Contains(err.Error(), "--database-url is required") {
		t.Fatalf("repairRepoIdentities(--cancel-active) err = %v, want the missing-url error", err)
	}
}

// TestWriteRepoIdentityRepairReport pins the operator-facing listing: one line
// per rewritten/quarantined row plus the summary, with the report/apply verb
// distinguishing a dry run from an applied pass.
func TestWriteRepoIdentityRepairReport(t *testing.T) {
	res := storage.RepoIdentityRepairResult{
		Mode:                storage.RepoIdentityRepairReport,
		Scanned:             3,
		Rewritten:           1,
		Quarantined:         1,
		Unchanged:           0,
		ActiveRequiresDrain: 1,
		Entries: []storage.RepoIdentityRepairEntry{
			{Kind: "run", ID: "run-a", Stored: "group/sub/project", Repaired: "a1:Z3JvdXAvc3ViL3Byb2plY3Q", Action: storage.RepoIdentityRewrite, Reason: "legacy URL-less nested name"},
			{Kind: "job", ID: "job-b", Stored: "group/sub/project", Repaired: "quarantine.invalid/quarantined/Z3JvdXAvc3ViL3Byb2plY3Q", Action: storage.RepoIdentityQuarantine, Reason: "no clone URL or full name to prove host vs bare nested"},
			{Kind: "job", ID: "job-c", Stored: "group/sub/project", Repaired: "a1:Z3JvdXAvc3ViL3Byb2plY3Q", Action: storage.RepoIdentityActiveRequiresDrain, Reason: "non-terminal identity change requires a drain"},
		},
	}
	var out bytes.Buffer
	writeRepoIdentityRepairReport(&out, res)
	text := out.String()
	for _, want := range []string{
		`REWRITE_TERMINAL run run-a: "group/sub/project" -> "a1:Z3JvdXAvc3ViL3Byb2plY3Q"`,
		`QUARANTINE_TERMINAL job job-b: "group/sub/project" -> "quarantine.invalid/quarantined/Z3JvdXAvc3ViL3Byb2plY3Q"`,
		`ACTIVE_REQUIRES_DRAIN job job-c: "group/sub/project" -> "a1:Z3JvdXAvc3ViL3Byb2plY3Q"`,
		"scanned=3 rewritten=1 quarantined=1 unchanged=0 active_requires_drain=1 drained=0",
		"planned",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("report %q missing %q", text, want)
		}
	}

	res.Mode = storage.RepoIdentityRepairApply
	res.Drained = 1
	out.Reset()
	writeRepoIdentityRepairReport(&out, res)
	if !strings.Contains(out.String(), "applied") {
		t.Fatalf("apply report %q must say applied", out.String())
	}
}

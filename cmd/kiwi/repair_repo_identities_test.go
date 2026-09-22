package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestWriteRepoIdentityRepairReport pins the operator-facing listing: one line
// per rewritten/quarantined row plus the summary, with the report/apply verb
// distinguishing a dry run from an applied pass.
func TestWriteRepoIdentityRepairReport(t *testing.T) {
	res := storage.RepoIdentityRepairResult{
		Mode:        storage.RepoIdentityRepairReport,
		Scanned:     3,
		Rewritten:   1,
		Quarantined: 1,
		Unchanged:   1,
		Entries: []storage.RepoIdentityRepairEntry{
			{Kind: "run", ID: "run-a", Stored: "group/sub/project", Repaired: "a1:Z3JvdXAvc3ViL3Byb2plY3Q", Action: storage.RepoIdentityRewrite, Reason: "legacy URL-less nested name"},
			{Kind: "job", ID: "job-b", Stored: "group/sub/project", Repaired: "quarantine.invalid/quarantined/Z3JvdXAvc3ViL3Byb2plY3Q", Action: storage.RepoIdentityQuarantine, Reason: "no clone URL or full name to prove host vs bare nested"},
		},
	}
	var out bytes.Buffer
	writeRepoIdentityRepairReport(&out, res)
	text := out.String()
	for _, want := range []string{
		`REWRITE run run-a: "group/sub/project" -> "a1:Z3JvdXAvc3ViL3Byb2plY3Q"`,
		`QUARANTINE job job-b: "group/sub/project" -> "quarantine.invalid/quarantined/Z3JvdXAvc3ViL3Byb2plY3Q"`,
		"scanned=3 rewritten=1 quarantined=1 unchanged=1",
		"planned",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("report %q missing %q", text, want)
		}
	}

	res.Mode = storage.RepoIdentityRepairApply
	out.Reset()
	writeRepoIdentityRepairReport(&out, res)
	if !strings.Contains(out.String(), "applied") {
		t.Fatalf("apply report %q must say applied", out.String())
	}
}

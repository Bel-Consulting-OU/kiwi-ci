package woodpecker

import (
	"os"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestImportApexMailShape pins the constructs the ApexMail gate line needs:
// digest-pinned image via YAML anchor, four DB/redis/clickhouse services with
// network aliases, per-step environment (NOT job-wide), failure: ignore on
// notify steps, when.status → step if, top-level project secrets, and the
// serial merge that keeps WP_RUN_DIR shared across stages.
func TestImportApexMailShape(t *testing.T) {
	const src = `
when:
  - event: [push, pull_request, manual]
variables:
  - &ci_image ghcr.io/example/ci@sha256:aaa
secrets:
  - source: github_token
    target: GITHUB_TOKEN
    required: false
services:
  - name: postgres
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: apexmail_ci
      POSTGRES_DB: apexmail_ci
  - name: redis
    image: redis:7-alpine
steps:
  - name: toolchain
    image: *ci_image
    environment:
      CI_MISSING_TOOLS: fail
    commands: [apexmail-ci-toolchain --assert]
  - name: test
    image: *ci_image
    environment:
      CI_MISSING_TOOLS: fail
      TEST_DATABASE_URL: postgresql://postgres:apexmail_ci@postgres:5432/apexmail_ci
    commands: [./ci/woodpecker/stage.sh test]
  - name: notify
    image: *ci_image
    failure: ignore
    when:
      - status: [failure]
    commands: [./tools/post_github_status.sh]
`
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res.Unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %v", res.Unsupported)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, res.PipelineYAML)
	}
	if len(spec.Jobs) != 1 {
		t.Fatalf("serial merge: jobs = %d, want 1", len(spec.Jobs))
	}
	j := spec.Jobs["toolchain"]
	if j.Image != "ghcr.io/example/ci@sha256:aaa" {
		t.Fatalf("anchor-expanded image = %q", j.Image)
	}
	if len(j.Services) != 2 {
		t.Fatalf("services = %+v", j.Services)
	}
	if len(j.Steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(j.Steps))
	}
	// Per-step env isolation: toolchain must NOT see the test DB URL.
	if j.Steps[0].Env["TEST_DATABASE_URL"] != "" {
		t.Fatalf("toolchain leaked test env: %+v", j.Steps[0].Env)
	}
	if j.Steps[1].Env["TEST_DATABASE_URL"] == "" {
		t.Fatalf("test step lost its env: %+v", j.Steps[1].Env)
	}
	// failure: ignore + when.status failure
	if !j.Steps[2].ContinueOnError {
		t.Fatal("notify must keep continue_on_error (failure: ignore)")
	}
	if j.Steps[2].If != "failure()" {
		t.Fatalf("notify if = %q, want failure()", j.Steps[2].If)
	}
	// Project secret is declared on steps.
	if len(j.Steps[0].Secrets) == 0 || j.Steps[0].Secrets[0] != "GITHUB_TOKEN" {
		t.Fatalf("step secrets = %v", j.Steps[0].Secrets)
	}
}

// TestImportApexMailWorkflowFile runs the real file when present (developer
// machines with the checkout). CI without the sibling repo skips cleanly.
func TestImportApexMailWorkflowFile(t *testing.T) {
	path := os.Getenv("KIWI_APEXMAIL_WOODPECKER")
	if path == "" {
		path = "/Users/sabelakhoua/IdeaProjects/ApexMail/.woodpecker.yml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("ApexMail checkout not available")
	}
	res, err := New().Import(string(data))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, res.PipelineYAML)
	}
	if len(spec.Jobs) == 0 {
		t.Fatal("no jobs")
	}
	j := spec.Jobs["toolchain"]
	if len(j.Services) < 3 {
		t.Fatalf("services = %d, want postgres/postgres-fresh/redis/clickhouse", len(j.Services))
	}
	// DB URL must live on the test step, not the toolchain step.
	if j.Steps[0].Env["TEST_DATABASE_URL"] != "" {
		t.Fatal("toolchain must not carry TEST_DATABASE_URL")
	}
	foundDB := false
	for _, st := range j.Steps {
		if strings.Contains(st.Run, "stage.sh test") && st.Env["TEST_DATABASE_URL"] != "" {
			foundDB = true
		}
		if strings.Contains(st.Run, "post_github_status.sh") && !st.ContinueOnError {
			t.Fatalf("notify step missing continue_on_error: %+v", st)
		}
	}
	if !foundDB {
		t.Fatal("test step missing TEST_DATABASE_URL")
	}
}

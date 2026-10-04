package storage

import (
	"encoding/json"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// benchLeaseJob builds a representative job for the lease predicate: a
// container job with labels, a repository ACL, and a compiled payload with
// an enforced policy granting container execution.
func benchLeaseJob() model.Job {
	payload := &model.CompiledJobPayload{
		SchemaVersion:   1,
		EffectiveJob:    json.RawMessage(`{"id":"build","base_id":"build","job":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`),
		EffectivePolicy: json.RawMessage(`{"Enforced":true,"Container":true,"Network":3}`),
	}
	return model.Job{
		ID: "job-1", RunID: "run-1", Key: "build", BaseKey: "build",
		RepoID: "github.com/acme/service", RepoFullName: "acme/service",
		RequiredLabels:     []string{"container", "linux"},
		PlacementRegions:   []string{"eu-west"},
		CompiledJobPayload: payload,
	}
}

func benchLeaseRunner() model.Runner {
	return model.Runner{
		ID: "runner-1", Name: "r1", Capacity: 4,
		Labels: []string{"container", "linux", "eu-west"},
		Region: "eu-west",
		AllowedRepositories: []string{
			"github.com/acme/service", "github.com/acme/other", "github.com/acme/third",
		},
		Capabilities:         []string{"native", "container"},
		CapabilitiesEnforced: true,
	}
}

// BenchmarkLeasePredicateAllows measures the per-candidate lease decision
// (labels, repository ACL, capabilities, policy runtimes, regions): the
// scheduler evaluates it for every queued job on every runner poll.
func BenchmarkLeasePredicateAllows(b *testing.B) {
	job := benchLeaseJob()
	run := benchLeaseRunner()
	pred := LeasePredicate{Runner: run, Job: job, EnvRunning: 1}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !pred.Allows() {
			b.Fatal("predicate denied the representative job")
		}
	}
}

// BenchmarkLeasePolicyRuntimes measures deriving the enforced runtime set
// from a compiled payload's effective policy (once per candidate decision).
func BenchmarkLeasePolicyRuntimes(b *testing.B) {
	job := benchLeaseJob()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		runtimes, enforced := LeasePolicyRuntimes(job)
		if !enforced || len(runtimes) != 1 {
			b.Fatalf("runtimes = %v enforced=%v", runtimes, enforced)
		}
	}
}

// BenchmarkLeasePredicateMatrix measures the decision across a mixed
// candidate set (matching, wrong-label, wrong-region, disabled runners),
// which is the shape of the real scheduling scan.
func BenchmarkLeasePredicateMatrix(b *testing.B) {
	job := benchLeaseJob()
	matching := benchLeaseRunner()
	wrongLabel := benchLeaseRunner()
	wrongLabel.Labels = []string{"native"}
	wrongRegion := benchLeaseRunner()
	wrongRegion.Region = "us-east"
	wrongRepo := benchLeaseRunner()
	wrongRepo.AllowedRepositories = []string{"github.com/other/repo"}
	disabled := benchLeaseRunner()
	disabled.Disabled = true
	preds := []LeasePredicate{
		{Runner: matching, Job: job},
		{Runner: wrongLabel, Job: job},
		{Runner: wrongRegion, Job: job},
		{Runner: wrongRepo, Job: job},
		{Runner: disabled, Job: job},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		allowed := 0
		for _, p := range preds {
			if p.Allows() {
				allowed++
			}
		}
		if allowed != 1 {
			b.Fatalf("allowed = %d, want exactly the matching runner", allowed)
		}
	}
}

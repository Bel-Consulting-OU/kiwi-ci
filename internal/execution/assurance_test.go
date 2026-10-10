package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const pinnedImage = "alpine@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// assuranceEff builds a materialized execution directly from the facts the
// derivation reads, so each table row states exactly one execution shape.
func assuranceEff(runtime, network string, caps policy.Capabilities, mut func(cj *pipeline.CompiledJob, e *EffectiveExecution)) EffectiveExecution {
	cj := pipeline.CompiledJob{
		ID: "build",
		Job: pipeline.Job{
			Runtime: runtime,
			Image:   pinnedImage,
		},
	}
	e := EffectiveExecution{
		CompiledJob:   cj,
		Trusted:       true,
		PolicyPresent: true,
		Capabilities:  caps,
		Network:       pipeline.NetworkPolicyDefault,
	}
	if network != "" {
		e.CompiledJob.Job.Network = network
		e.RequestedNetwork = pipeline.NetworkPolicyNone
		if network == "none" {
			e.Network = pipeline.NetworkPolicyNone
		}
	}
	if mut != nil {
		mut(&e.CompiledJob, &e)
	}
	return e
}

// emptySecrets is the explicitly empty allowlist the untrusted floor and a
// narrowed trusted policy carry: deny every secret by construction.
func emptySecrets() policy.Capabilities {
	c := policy.DefaultUntrustedCapabilities()
	c.Secrets = map[string]bool{}
	c.OIDC = []string{}
	return c
}

func deployedJob(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
	cj.Job.Environment = pipeline.Environment{Name: "production"}
}

func TestAssuranceAndEffectsClassDecisionTable(t *testing.T) {
	trusted := policy.DefaultTrustedCapabilities()
	empty := emptySecrets()
	deployGranted := empty
	deployGranted.Deployments = true

	cases := []struct {
		name      string
		eff       EffectiveExecution
		wantLevel model.ExecutionAssurance
		wantClass model.ExternalEffectsClass
	}{
		{
			name:      "untrusted container network-none no-secrets pinned is pure and hermetic",
			eff:       assuranceEff("container", "none", empty, nil),
			wantLevel: model.AssuranceHermetic,
			wantClass: model.EffectsPure,
		},
		{
			name:      "trusted container network-allowed with unrestricted secrets is opaque at level 1",
			eff:       assuranceEff("container", "", trusted, nil),
			wantLevel: model.AssuranceIsolatedFilesystem,
			wantClass: model.EffectsOpaqueExternal,
		},
		{
			name:      "trusted container explicit empty secrets with granted deployment is kiwi mediated at level 4",
			eff:       assuranceEff("container", "", deployGranted, deployedJob),
			wantLevel: model.AssuranceKiwiMediatedAuthority,
			wantClass: model.EffectsKiwiMediated,
		},
		{
			name: "hermetic container network-none empty-secrets pinned main and service images",
			eff: assuranceEff("container", "none", empty, func(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
				cj.Job.Services = []pipeline.Service{{Name: "db", Image: pinnedImage}}
			}),
			wantLevel: model.AssuranceHermetic,
			wantClass: model.EffectsPure,
		},
		{
			name: "native trusted with bounded workspace stays at most level 1 and opaque",
			eff: assuranceEff("native", "", trusted, func(_ *pipeline.CompiledJob, e *EffectiveExecution) {
				e.WorkspaceQuotaLimit = DefaultUntrustedWorkspaceMaxBytes
			}),
			wantLevel: model.AssuranceIsolatedFilesystem,
			wantClass: model.EffectsOpaqueExternal,
		},
		{
			name:      "native trusted without a workspace bound is uncontrolled and opaque",
			eff:       assuranceEff("native", "", trusted, nil),
			wantLevel: model.AssuranceUncontrolled,
			wantClass: model.EffectsOpaqueExternal,
		},
		{
			name:      "network denied but declared deployment is not mediated is level 3",
			eff:       assuranceEff("container", "none", empty, deployedJob),
			wantLevel: model.AssuranceNetworkDenied,
			wantClass: model.EffectsKiwiMediated,
		},
		{
			name: "network denied but declared OIDC is denied by the audience allowlist is level 3",
			eff: assuranceEff("container", "none", empty, func(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
				cj.Job.Permissions.IDToken = true
			}),
			wantLevel: model.AssuranceNetworkDenied,
			wantClass: model.EffectsKiwiMediated,
		},
		{
			name: "network denied with unpinned images and no declared effects is level 4",
			eff: assuranceEff("container", "none", empty, func(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
				cj.Job.Image = "alpine:3.20"
			}),
			wantLevel: model.AssuranceKiwiMediatedAuthority,
			wantClass: model.EffectsPure,
		},
		{
			name: "services-only egress with empty secrets is kiwi mediated at level 4",
			eff: assuranceEff("container", "", empty, func(cj *pipeline.CompiledJob, e *EffectiveExecution) {
				cj.Job.Network = ""
				cj.Job.Sandbox.Network = pipeline.NetworkPolicyServicesOnly
				e.Network = pipeline.NetworkPolicyServicesOnly
			}),
			wantLevel: model.AssuranceKiwiMediatedAuthority,
			wantClass: model.EffectsKiwiMediated,
		},
		{
			name: "tart runtime with a pinned VM and network none is hermetic",
			eff: assuranceEff("tart", "none", empty, func(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
				cj.Job.Image = ""
				cj.Job.VM = pinnedImage
			}),
			wantLevel: model.AssuranceHermetic,
			wantClass: model.EffectsPure,
		},
		{
			name: "trusted non-empty secret allowlist is opaque at level 1",
			eff: assuranceEff("container", "none", func() policy.Capabilities {
				c := empty
				c.Secrets = map[string]bool{"TOKEN": true}
				return c
			}(), nil),
			wantLevel: model.AssuranceIsolatedFilesystem,
			wantClass: model.EffectsOpaqueExternal,
		},
		{
			name: "network allowed with declared OIDC granted is kiwi mediated at level 4",
			eff: assuranceEff("container", "", func() policy.Capabilities {
				c := empty
				c.OIDC = []string{"https://vault.example"}
				return c
			}(), func(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
				cj.Job.Permissions.IDToken = true
			}),
			wantLevel: model.AssuranceKiwiMediatedAuthority,
			wantClass: model.EffectsKiwiMediated,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			level := tc.eff.Assurance()
			class := tc.eff.EffectsClass()
			if level != tc.wantLevel {
				t.Fatalf("Assurance() = %d (%s), want %d (%s)", level, level.Name(), tc.wantLevel, tc.wantLevel.Name())
			}
			if class != tc.wantClass {
				t.Fatalf("EffectsClass() = %s, want %s", class, tc.wantClass)
			}
			if !level.Valid() || level.Name() == "" {
				t.Fatalf("level %d has no valid name", level)
			}
			if !class.Valid() {
				t.Fatalf("class %q not valid", class)
			}
		})
	}
}

// TestAssuranceDerivationIsTotal pins that every combination of the input
// facts maps to a defined level and class, and that repeated derivation is
// stable (pure, deterministic).
func TestAssuranceDerivationIsTotal(t *testing.T) {
	runtimes := []string{"", "native", "container", "tart"}
	networks := []string{"", "none"}
	secrets := []policy.Capabilities{
		func() policy.Capabilities { c := emptySecrets(); c.Secrets = nil; return c }(),
		emptySecrets(),
		func() policy.Capabilities { c := emptySecrets(); c.Secrets = map[string]bool{"X": true}; return c }(),
	}
	for _, runtime := range runtimes {
		for _, network := range networks {
			for _, caps := range secrets {
				for _, deploy := range []bool{false, true} {
					for _, oidc := range []bool{false, true} {
						for _, pinned := range []bool{false, true} {
							mutSecrets := caps
							e := assuranceEff(runtime, network, mutSecrets, func(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
								if deploy {
									deployedJob(cj, nil)
								}
								if oidc {
									cj.Job.Permissions.IDToken = true
								}
								if !pinned {
									cj.Job.Image = "alpine:3.20"
									cj.Job.VM = ""
								}
							})
							level := e.Assurance()
							class := e.EffectsClass()
							if !level.Valid() || level.Name() == "" {
								t.Fatalf("undefined level %d for runtime=%q network=%q", level, runtime, network)
							}
							if !class.Valid() {
								t.Fatalf("undefined class %q for runtime=%q network=%q", class, runtime, network)
							}
							if again := e.Assurance(); again != level {
								t.Fatalf("Assurance not deterministic: %d then %d", level, again)
							}
							if again := e.EffectsClass(); again != class {
								t.Fatalf("EffectsClass not deterministic: %s then %s", class, again)
							}
						}
					}
				}
			}
		}
	}
}

// TestMaterializeFromJobDerivesAssurance proves the job-level derivation
// reaches the same effective execution the runner materializes: a persisted
// job with a verified payload classifies as kiwi_mediated/hermetic for the
// pinned untrusted shape, and a job without a payload still classifies
// through the documented legacy path.
func TestMaterializeFromJobDerivesAssurance(t *testing.T) {
	text := "version: 1\njobs:\n  build:\n    runtime: container\n    image: " + pinnedImage + "\n    network: none\n    steps:\n      - run: echo hi\n"
	spec, err := pipeline.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	cj := g.Jobs["build"]
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	jobSum := sha256.Sum256(cjJSON)
	caps := emptySecrets()
	policyJSON, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	pd, err := pipeline.PipelineDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	payload := &model.CompiledJobPayload{
		SchemaVersion: 1, CompilerVersion: "test", PipelineDigest: pd,
		JobDigest:    hex.EncodeToString(jobSum[:]),
		EffectiveJob: json.RawMessage(cjJSON), EffectivePolicy: json.RawMessage(policyJSON),
	}
	job := model.Job{
		ID: "job-1", RunID: "run-1", Key: "build", Pipeline: text,
		Trusted: false, CompiledJobPayload: payload,
	}
	eff, ok := MaterializeFromJob(job)
	if !ok {
		t.Fatal("materialization failed for a bound payload")
	}
	if level := eff.Assurance(); level != model.AssuranceHermetic {
		t.Fatalf("assurance = %d (%s), want hermetic", level, level.Name())
	}
	if class := eff.EffectsClass(); class != model.EffectsPure {
		t.Fatalf("effects class = %s, want pure", class)
	}

	// Legacy path: no payload, the persisted job is authoritative (its
	// network field replaces the compiled one, so a real legacy record
	// carries "none" there exactly like the enqueue stamp).
	legacy := job
	legacy.CompiledJobPayload = nil
	legacy.Network = "none"
	effLegacy, ok := MaterializeFromJob(legacy)
	if !ok {
		t.Fatal("legacy materialization failed")
	}
	if level := effLegacy.Assurance(); level != model.AssuranceHermetic {
		t.Fatalf("legacy assurance = %d (%s), want hermetic", level, level.Name())
	}
	if class := effLegacy.EffectsClass(); class != model.EffectsPure {
		t.Fatalf("legacy effects class = %s, want pure", class)
	}

	// Unprovable records never materialize.
	if _, ok := MaterializeFromJob(model.Job{ID: "job-2", Key: "build"}); ok {
		t.Fatal("empty pipeline must not materialize")
	}
	broken := job
	broken.Pipeline = "not: [a, pipeline"
	if _, ok := MaterializeFromJob(broken); ok {
		t.Fatal("unparseable pipeline must not materialize")
	}
	mismatch := job
	mismatch.Key = "other"
	if _, ok := MaterializeFromJob(mismatch); ok {
		t.Fatal("payload that does not bind the key must not materialize")
	}
}

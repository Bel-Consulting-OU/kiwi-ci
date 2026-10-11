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
			name:      "untrusted container network-none no-secrets pinned is pure and sealed",
			eff:       assuranceEff("container", "none", empty, nil),
			wantLevel: model.AssuranceSealedPinnedNoNetwork,
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
			name: "sealed container network-none empty-secrets pinned main and service images",
			eff: assuranceEff("container", "none", empty, func(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
				cj.Job.Services = []pipeline.Service{{Name: "db", Image: pinnedImage}}
			}),
			wantLevel: model.AssuranceSealedPinnedNoNetwork,
			wantClass: model.EffectsPure,
		},
		{
			name: "native with a workspace quota is uncontrolled and opaque: quota does not isolate",
			eff: assuranceEff("native", "", trusted, func(_ *pipeline.CompiledJob, e *EffectiveExecution) {
				e.WorkspaceQuotaLimit = DefaultUntrustedWorkspaceMaxBytes
			}),
			wantLevel: model.AssuranceUncontrolled,
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
			// Tart cannot deny networking (vm-nat); policy none is intent
			// only. Proven enforcement therefore cannot claim sealed or
			// pure — this is the v6 network_access_denied contract.
			name: "tart runtime with a pinned VM and network-none policy is mediated, not sealed",
			eff: assuranceEff("tart", "none", empty, func(cj *pipeline.CompiledJob, _ *EffectiveExecution) {
				cj.Job.Image = ""
				cj.Job.VM = pinnedImage
			}),
			wantLevel: model.AssuranceKiwiMediatedAuthority,
			wantClass: model.EffectsKiwiMediated,
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
			// Proven enforcement (v6) requires the attempt's observed
			// receipt. The table cases describe what the EXECUTOR would
			// report for that effective shape; ApplyObservedControl is how
			// those observations become signed facts.
			f := tc.eff.Facts()
			var receipt *model.ExecutionControlReceipt
			switch tc.eff.runtimeFact() {
			case model.RuntimeFactContainer:
				net := model.ObservedNetworkContainerNamespace
				if tc.eff.networkModeFact() == model.NetworkModeFactNone {
					net = model.ObservedNetworkNone
				}
				receipt = &model.ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: net}
			case model.RuntimeFactTart:
				receipt = &model.ExecutionControlReceipt{Runtime: "tart", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkVMNAT}
			default:
				receipt = &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost}
			}
			if err := f.ApplyObservedControl(receipt); err != nil {
				t.Fatalf("ApplyObservedControl: %v", err)
			}
			level := model.DeriveAssuranceProfile(f)
			class := EffectsClassFromFacts(f, tc.eff.DeclaresOIDC(), tc.eff.DeclaresDeployment())
			if level != tc.wantLevel {
				t.Fatalf("Assurance() = %d (%s), want %d (%s) facts=%+v", level, level.Name(), tc.wantLevel, tc.wantLevel.Name(), f)
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

// TestFactsKeepQuotaOrthogonalToIsolation is the regression test for the
// audit's P1 fact-vector rule AND the quota-truthfulness split: a native
// execution with a requested workspace quota carries
// workspace_quota_configured=true and filesystem_isolated=false, and never
// classifies as isolated_filesystem. Enforcement is separate: without an
// observed hard-quota result the fact stays false; with one it becomes true
// and still never implies isolation.
func TestFactsKeepQuotaOrthogonalToIsolation(t *testing.T) {
	e := assuranceEff("native", "", emptySecrets(), func(_ *pipeline.CompiledJob, e *EffectiveExecution) {
		e.WorkspaceQuotaLimit = DefaultUntrustedWorkspaceMaxBytes
	})
	f := e.Facts()
	if !f.WorkspaceQuotaConfigured || f.WorkspaceQuotaEnforced || f.FilesystemIsolated {
		t.Fatalf("facts = %+v, want configured quota without enforcement or isolation", f)
	}
	if !f.Valid() {
		t.Fatalf("facts invalid: %+v", f)
	}
	if got := e.Assurance(); got != model.AssuranceUncontrolled {
		t.Fatalf("profile = %d (%s), want uncontrolled", got, got.Name())
	}
	// A proven hard quota upgrades only the enforcement fact.
	hard := &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost, WorkspaceQuotaEnforced: true}
	if err := f.ApplyObservedControl(hard); err != nil {
		t.Fatalf("ApplyObservedControl: %v", err)
	}
	if !f.WorkspaceQuotaEnforced || f.FilesystemIsolated {
		t.Fatalf("facts = %+v, want quota enforced without isolation", f)
	}
	// The container counterpart carries the same quota fact WITH isolation.
	c := assuranceEff("container", "", emptySecrets(), func(_ *pipeline.CompiledJob, e *EffectiveExecution) {
		e.WorkspaceQuotaLimit = DefaultUntrustedWorkspaceMaxBytes
	})
	cf := c.Facts()
	if !cf.WorkspaceQuotaConfigured || cf.WorkspaceQuotaEnforced || !cf.FilesystemIsolated {
		t.Fatalf("container facts = %+v, want configured quota, unproven enforcement, isolation", cf)
	}
	chook := &model.ExecutionControlReceipt{Runtime: "docker", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkContainerNamespace, WorkspaceQuotaEnforced: true}
	if err := cf.ApplyObservedControl(chook); err != nil {
		t.Fatalf("ApplyObservedControl container: %v", err)
	}
	if !cf.WorkspaceQuotaEnforced || !cf.FilesystemIsolated {
		t.Fatalf("container facts = %+v, want quota and isolation", cf)
	}
}

// TestQuotaTruthfulnessMatrix pins the P1 evidence contract:
// workspace_quota_enforced is derived ONLY from the attempt-level hard-quota
// result on the observed receipt, never from the requested limit.
func TestQuotaTruthfulnessMatrix(t *testing.T) {
	cases := []struct {
		name           string
		limit          int64
		receipt        *model.ExecutionControlReceipt
		wantConfigured bool
		wantEnforced   bool
	}{
		{
			name:           "quota requested + hard quota succeeds",
			limit:          DefaultUntrustedWorkspaceMaxBytes,
			receipt:        &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost, WorkspaceQuotaEnforced: true},
			wantConfigured: true,
			wantEnforced:   true,
		},
		{
			name:           "quota requested + fallback accounting only",
			limit:          DefaultUntrustedWorkspaceMaxBytes,
			receipt:        &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost, WorkspaceQuotaEnforced: false},
			wantConfigured: true,
			wantEnforced:   false,
		},
		{
			name:           "quota setup fails before execution (no receipt)",
			limit:          DefaultUntrustedWorkspaceMaxBytes,
			receipt:        nil,
			wantConfigured: true,
			wantEnforced:   false,
		},
		{
			name:           "no quota requested",
			limit:          0,
			receipt:        &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost},
			wantConfigured: false,
			wantEnforced:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := assuranceEff("native", "", emptySecrets(), func(_ *pipeline.CompiledJob, e *EffectiveExecution) {
				e.WorkspaceQuotaLimit = tc.limit
			})
			f := e.Facts()
			if f.WorkspaceQuotaEnforced {
				t.Fatalf("Facts() manufactured enforcement from the plan: %+v", f)
			}
			if err := f.ApplyObservedControl(tc.receipt); err != nil {
				t.Fatalf("ApplyObservedControl: %v", err)
			}
			if f.WorkspaceQuotaConfigured != tc.wantConfigured || f.WorkspaceQuotaEnforced != tc.wantEnforced {
				t.Fatalf("facts = %+v, want configured=%v enforced=%v", f, tc.wantConfigured, tc.wantEnforced)
			}
			if !f.Valid() {
				t.Fatalf("facts invalid: %+v", f)
			}
		})
	}
}

// TestQuotaEnforcedWithoutObservationIsRejected: a fact vector that claims a
// hard quota without an observed receipt (or with a receipt that did not see
// one) is internally contradictory and must not be signed or accepted.
func TestQuotaEnforcedWithoutObservationIsRejected(t *testing.T) {
	f := model.ExecutionFacts{Runtime: model.RuntimeFactNative, NetworkMode: model.NetworkModeFactDefault, WorkspaceQuotaEnforced: true}
	if f.Valid() {
		t.Fatal("quota enforced without a receipt must be invalid")
	}
	if err := f.ValidateObservedConsistency(); err == nil {
		t.Fatal("ValidateObservedConsistency accepted unobserved enforcement")
	}
	f.Observed = &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost}
	if f.Valid() {
		t.Fatal("quota enforced contradicted by a non-hard receipt must be invalid")
	}
	// The reverse: a receipt that observed a hard quota must not be dropped.
	f2 := model.ExecutionFacts{Runtime: model.RuntimeFactNative, NetworkMode: model.NetworkModeFactDefault}
	if err := f2.ApplyObservedControl(&model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost, WorkspaceQuotaEnforced: true}); err != nil {
		t.Fatalf("ApplyObservedControl: %v", err)
	}
	if !f2.WorkspaceQuotaEnforced {
		t.Fatalf("facts = %+v, want enforcement taken from the receipt", f2)
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
// job with a verified payload classifies as kiwi_mediated/sealed_pinned for the
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
	// Proven enforcement requires the executor receipt (v6).
	f := eff.Facts()
	if err := f.ApplyObservedControl(&model.ExecutionControlReceipt{
		Runtime: "docker", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkNone,
	}); err != nil {
		t.Fatalf("ApplyObservedControl: %v", err)
	}
	if level := model.DeriveAssuranceProfile(f); level != model.AssuranceSealedPinnedNoNetwork {
		t.Fatalf("assurance = %d (%s), want sealed_pinned_no_network", level, level.Name())
	}
	if class := EffectsClassFromFacts(f, eff.DeclaresOIDC(), eff.DeclaresDeployment()); class != model.EffectsPure {
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
	fl := effLegacy.Facts()
	if err := fl.ApplyObservedControl(&model.ExecutionControlReceipt{
		Runtime: "docker", SandboxStarted: true, NetworkEnforced: model.ObservedNetworkNone,
	}); err != nil {
		t.Fatalf("ApplyObservedControl legacy: %v", err)
	}
	if level := model.DeriveAssuranceProfile(fl); level != model.AssuranceSealedPinnedNoNetwork {
		t.Fatalf("legacy assurance = %d (%s), want sealed_pinned_no_network", level, level.Name())
	}
	if class := EffectsClassFromFacts(fl, effLegacy.DeclaresOIDC(), effLegacy.DeclaresDeployment()); class != model.EffectsPure {
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

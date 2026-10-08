package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/execution"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// This file pins the extraction parity: the runner's PRE-REFACTOR option
// derivation (kept here verbatim as the oracle) must equal
// OptionsFromExecution(MaterializeEffectiveExecution(...)) for representative
// inputs. The oracle is deliberately a frozen copy, not a call into the new
// code, so a behavior drift in the shared materializer fails this test.

func oldRunnerDerive(t *testing.T, verified pipeline.CompiledJob, payload *model.CompiledJobPayload, persisted model.Job, caps policy.Capabilities, policyOK bool) (pipeline.CompiledJob, Options, error) {
	t.Helper()
	cj := verified
	if payload != nil {
		if policyOK {
			if err := oldApplyEffectiveNetwork(&cj, caps); err != nil {
				return cj, Options{}, fmt.Errorf("compiled payload network admission: %w", err)
			}
		}
		oldApplyPersistedResourceRequests(&cj, persisted)
	} else {
		cj.Job.Network = persisted.Network
	}
	reqs, err := oldPayloadSandboxRequirements(payload)
	if err != nil {
		return cj, Options{}, err
	}
	oldApplyEffectiveSandbox(&cj, reqs)

	untrusted := !persisted.Trusted
	declaredDisk := oldWorkspaceMaxBytesForResources(cj.Job.Resources)
	if persisted.DiskRequest > 0 {
		declaredDisk = persisted.DiskRequest
	}
	return cj, Options{
		WorkspaceMaxBytes:         WorkspaceBoundBytes(declaredDisk, untrusted, DefaultUntrustedWorkspaceMaxBytes),
		Untrusted:                 untrusted,
		RequireImmutableImages:    !persisted.Trusted,
		RequireUntrustedDiskQuota: untrusted && !AllowUnquotaedUntrustedDisk(),
	}, nil
}

func oldPayloadSandboxRequirements(p *model.CompiledJobPayload) (execution.PolicySandbox, error) {
	var out execution.PolicySandbox
	if p == nil || p.EffectivePolicy == nil {
		return out, nil
	}
	raw, err := json.Marshal(p.EffectivePolicy)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}

func oldApplyEffectiveSandbox(cj *pipeline.CompiledJob, req execution.PolicySandbox) {
	cj.Job.Sandbox.Rootless = cj.Job.Sandbox.Rootless || req.Rootless
	cj.Job.Sandbox.ReadOnlyRootFS = cj.Job.Sandbox.ReadOnlyRootFS || req.ReadOnlyRootFS
	cj.Job.Sandbox.NonRoot = cj.Job.Sandbox.NonRoot || req.NonRoot
}

func oldApplyEffectiveNetwork(cj *pipeline.CompiledJob, caps policy.Capabilities) error {
	requested := oldRequestedNetworkPolicy(cj.Job)
	ceiling := caps.Network
	if ceiling == pipeline.NetworkPolicyDefault {
		ceiling = pipeline.NetworkPolicyInternet
	}
	if requested != pipeline.NetworkPolicyDefault && oldNetworkPolicyStrength(requested) > oldNetworkPolicyStrength(ceiling) {
		return &networkRefusal{requested: requested, ceiling: ceiling}
	}
	effective := pipeline.NetworkPolicyDefault
	if oldNetworkPolicyStrength(requested) < oldNetworkPolicyStrength(ceiling) {
		effective = requested
	} else if ceiling != pipeline.NetworkPolicyInternet {
		effective = ceiling
	}
	if effective != pipeline.NetworkPolicyDefault {
		cj.Job.Sandbox.Network = effective
	}
	return nil
}

type networkRefusal struct {
	requested, ceiling pipeline.NetworkPolicy
}

func (e *networkRefusal) Error() string {
	return "job requests network " + oldNetworkPolicyName(e.requested) + " which exceeds the compiled policy ceiling " + oldNetworkPolicyName(e.ceiling)
}

func oldRequestedNetworkPolicy(j pipeline.Job) pipeline.NetworkPolicy {
	if j.Network == "none" {
		return pipeline.NetworkPolicyNone
	}
	return j.Sandbox.Network
}

func oldNetworkPolicyStrength(p pipeline.NetworkPolicy) int {
	switch p {
	case pipeline.NetworkPolicyNone:
		return 0
	case pipeline.NetworkPolicyServicesOnly:
		return 1
	default:
		return 2
	}
}

func oldNetworkPolicyName(p pipeline.NetworkPolicy) string {
	switch p {
	case pipeline.NetworkPolicyNone:
		return "none"
	case pipeline.NetworkPolicyServicesOnly:
		return "services-only"
	case pipeline.NetworkPolicyInternet:
		return "internet"
	default:
		return "default"
	}
}

func oldApplyPersistedResourceRequests(cj *pipeline.CompiledJob, j model.Job) {
	if j.CPURequest > 0 {
		cj.Job.Resources.CPU = j.CPURequest
	}
	if j.MemoryRequest > 0 {
		cj.Job.Resources.Memory = pipeline.ByteSize(j.MemoryRequest)
	}
	if j.DiskRequest > 0 {
		cj.Job.Resources.Disk = pipeline.ByteSize(j.DiskRequest)
	}
	if j.PIDsRequest > 0 {
		cj.Job.Resources.PIDs = j.PIDsRequest
	}
}

func oldWorkspaceMaxBytesForResources(res pipeline.Resources) int64 {
	if res.Disk <= 0 {
		return 0
	}
	return int64(res.Disk)
}

const parityPipeline = "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"

// makeParityInput compiles text and builds the coherent payload (optional
// policy) plus the persisted job record.
func makeParityInput(t *testing.T, text string, policyJSON any, persisted model.Job) (pipeline.CompiledJob, *model.CompiledJobPayload) {
	t.Helper()
	spec, err := pipeline.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	pd, err := pipeline.PipelineDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	cj, ok := g.Jobs["build"]
	if !ok {
		t.Fatal("no build job")
	}
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cjJSON)
	payload := &model.CompiledJobPayload{
		SchemaVersion: 1, CompilerVersion: "test",
		PipelineDigest: pd, JobDigest: hex.EncodeToString(sum[:]),
		EffectiveJob: json.RawMessage(cjJSON),
	}
	if policyJSON != nil {
		b, err := json.Marshal(policyJSON)
		if err != nil {
			t.Fatal(err)
		}
		payload.EffectivePolicy = json.RawMessage(b)
	}
	return cj, payload
}

func TestMaterializeEffectiveExecutionParity(t *testing.T) {
	networkServicesOnly := policy.DefaultTrustedCapabilities()
	networkServicesOnly.Network = pipeline.NetworkPolicyServicesOnly
	networkNone := policy.DefaultTrustedCapabilities()
	networkNone.Network = pipeline.NetworkPolicyNone
	untrustedFloor := policy.DefaultUntrustedCapabilities()

	cases := []struct {
		name      string
		text      string
		policy    any
		persisted model.Job
		wantErr   bool
	}{
		{
			name:      "trusted no policy no resources",
			text:      parityPipeline,
			policy:    nil,
			persisted: model.Job{Trusted: true},
		},
		{
			name: "trusted policy services-only pulls default request down",
			text: "version: 1\njobs:\n  build:\n    sandbox:\n      network: internet\n    steps:\n      - run: echo hi\n",
			// requested internet exceeds services-only: refused
			policy:    &networkServicesOnly,
			persisted: model.Job{Trusted: true},
			wantErr:   true,
		},
		{
			name:      "trusted policy services-only with default request",
			text:      parityPipeline,
			policy:    &networkServicesOnly,
			persisted: model.Job{Trusted: true},
		},
		{
			name:   "untrusted floor with declared disk and persisted ceilings",
			text:   "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    resources:\n      cpu: 1\n      memory: 512Mi\n      disk: 1Gi\n      pids: 64\n    steps:\n      - run: echo hi\n",
			policy: &untrustedFloor,
			persisted: model.Job{
				Trusted:    false,
				CPURequest: 2, MemoryRequest: 3 << 30, DiskRequest: 4 << 30, PIDsRequest: 256,
				ServiceEnvelopeRequest: model.ResourceCapacity{CPU: 0.5, Memory: 1 << 30, PIDs: 32},
			},
		},
		{
			name:      "untrusted floor without disk gets the mandatory default",
			text:      "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    steps:\n      - run: echo hi\n",
			policy:    &untrustedFloor,
			persisted: model.Job{Trusted: false},
		},
		{
			name:      "sandbox requirements strengthen the job request",
			text:      "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    sandbox:\n      rootless: false\n      read_only_rootfs: false\n    steps:\n      - run: echo hi\n",
			policy:    &untrustedFloor,
			persisted: model.Job{Trusted: false},
		},
		{
			name:      "legacy payload nil uses the persisted network",
			text:      parityPipeline,
			policy:    nil,
			persisted: model.Job{Trusted: true, Network: "none"},
		},
		{
			name:      "trusted policy internet leaves an explicit none request",
			text:      "version: 1\njobs:\n  build:\n    network: none\n    steps:\n      - run: echo hi\n",
			policy:    func() *policy.Capabilities { c := policy.DefaultTrustedCapabilities(); return &c }(),
			persisted: model.Job{Trusted: true},
		},
		{
			name:      "policy network none with internet job request is refused",
			text:      "version: 1\njobs:\n  build:\n    sandbox:\n      network: internet\n    steps:\n      - run: echo hi\n",
			policy:    &networkNone,
			persisted: model.Job{Trusted: true},
			wantErr:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified, payload := makeParityInput(t, tc.text, tc.policy, tc.persisted)
			var caps policy.Capabilities
			policyOK := false
			if tc.policy != nil {
				var cerr error
				caps, policyOK, cerr = execution.EffectivePolicyCapabilities(payload, tc.persisted.Trusted)
				if cerr != nil {
					t.Fatalf("capability decode: %v", cerr)
				}
			}
			oldCJ, oldOpts, oldErr := oldRunnerDerive(t, verified, payload, tc.persisted, caps, policyOK)
			eff, newErr := execution.MaterializeEffectiveExecution(verified, payload, tc.persisted, caps)
			if (oldErr != nil) != (newErr != nil) {
				t.Fatalf("error parity: old=%v new=%v", oldErr, newErr)
			}
			if oldErr != nil {
				if oldErr.Error() != newErr.Error() {
					t.Fatalf("error text parity: old=%q new=%q", oldErr.Error(), newErr.Error())
				}
				return
			}
			if newErr != nil {
				t.Fatalf("new derivation failed: %v", newErr)
			}
			newOpts := OptionsFromExecution(Options{Workspace: "ws"}, eff)
			// The runner keeps the host-capability quota decision itself; the
			// parity oracle derives it from the same expression.
			newOpts.RequireUntrustedDiskQuota = eff.Untrusted && !AllowUnquotaedUntrustedDisk()
			oldOpts.Workspace = "ws"
			if !reflect.DeepEqual(oldOpts, newOpts) {
				t.Fatalf("options parity:\n old=%+v\n new=%+v", oldOpts, newOpts)
			}
			oldJSON, _ := json.Marshal(oldCJ)
			newJSON, _ := json.Marshal(eff.CompiledJob)
			if string(oldJSON) != string(newJSON) {
				t.Fatalf("compiled job parity:\n old=%s\n new=%s", oldJSON, newJSON)
			}
			if eff.ServiceEnvelope != tc.persisted.ServiceEnvelopeRequest {
				t.Fatalf("service envelope = %+v, want %+v", eff.ServiceEnvelope, tc.persisted.ServiceEnvelopeRequest)
			}
			if eff.WorkspaceQuotaLimit != oldOptionsQuotaLimit(tc.persisted) {
				t.Fatalf("workspace quota limit = %d, want %d", eff.WorkspaceQuotaLimit, oldOptionsQuotaLimit(tc.persisted))
			}
		})
	}
}

// oldOptionsQuotaLimit is the runner's workspaceQuotaLimitForTask derivation
// (persisted disk request first, then the untrusted default).
func oldOptionsQuotaLimit(j model.Job) int64 {
	return WorkspaceBoundBytes(j.DiskRequest, !j.Trusted, DefaultUntrustedWorkspaceMaxBytes)
}

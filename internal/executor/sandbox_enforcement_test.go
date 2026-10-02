package executor

// Sandbox-requirement enforcement regressions: a policy that demands non_root
// must be enforced by the runtime or the job must be refused.

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestContainerUserPlanHonorsNonRoot(t *testing.T) {
	rootful := (&ContainerBackend{NonRoot: true}).containerUserPlan()
	if rootful.User != "65534:65534" || !rootful.ProvisionWorkspace {
		t.Fatalf("rootful non_root plan = %+v, want 65534:65534 with workspace provisioning", rootful)
	}
	// Documented rootless semantics: userns-mapped container UID 0 satisfies
	// non_root without an unmapped subuid owning the bind-mounted workspace.
	rootless := (&ContainerBackend{Rootless: true, NonRoot: true}).containerUserPlan()
	if rootless.User != "0:0" || rootless.ProvisionWorkspace {
		t.Fatalf("rootless non_root plan = %+v, want userns 0:0 without provisioning", rootless)
	}
	// Existing hardening behavior is unchanged.
	readOnly := (&ContainerBackend{ReadOnlyRootFS: true}).containerUserPlan()
	if readOnly.User != "65534:65534" || !readOnly.ProvisionWorkspace {
		t.Fatalf("read_only plan = %+v, want 65534:65534 with provisioning", readOnly)
	}
}

func TestUnsupportedSandboxRequirementRefusesNonContainer(t *testing.T) {
	required := pipeline.Sandbox{NonRoot: true}
	for _, runtime := range []string{"native", "tart"} {
		err := unsupportedSandboxRequirement(runtime, required)
		if err == nil || !strings.Contains(err.Error(), "non_root") {
			t.Fatalf("%s non_root = %v, want a fail-closed refusal", runtime, err)
		}
	}
	if err := unsupportedSandboxRequirement("container", required); err != nil {
		t.Fatalf("container non_root = %v, want enforcement", err)
	}
	if err := unsupportedSandboxRequirement("native", pipeline.Sandbox{}); err != nil {
		t.Fatalf("no requirements = %v", err)
	}
}

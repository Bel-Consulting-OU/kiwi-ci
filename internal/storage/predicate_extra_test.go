package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

func predicateRunner() model.Runner {
	return model.Runner{ID: "runner", Capacity: 4, Labels: []string{"linux"}, Region: "eu"}
}

func predicateJob() model.Job {
	return model.Job{ID: "job", RunID: "run", Status: model.StatusQueued, RepoID: "github.com/acme/api"}
}

func TestLeasePredicateDenialBranches(t *testing.T) {
	base := func() LeasePredicate {
		return LeasePredicate{Runner: predicateRunner(), Job: predicateJob()}
	}
	if !base().Allows() {
		t.Fatal("baseline predicate must allow")
	}

	p := base()
	p.Job.RequiredLabels = []string{"gpu"}
	if p.Allows() {
		t.Error("missing required label must deny")
	}

	p = base()
	p.Job.PlacementRegions = []string{"us"}
	if p.Allows() {
		t.Error("region mismatch must deny")
	}
	p.Runner.Region = "us"
	if !p.Allows() {
		t.Error("matching region must allow")
	}

	p = base()
	p.Runner.Labels = nil
	p.Job.RequiredLabels = []string{"linux"}
	if p.Allows() {
		t.Error("runner without labels must deny label-requiring job")
	}

	p = base()
	p.Runner.Disabled = true
	if p.Allows() {
		t.Error("disabled runner must deny")
	}
	p = base()
	p.Runner.Draining = true
	if p.Allows() {
		t.Error("draining runner must deny")
	}
	p = base()
	p.Runner.Capacity = 0
	if p.Allows() {
		t.Error("zero-capacity runner must deny")
	}
	p = base()
	p.Runner.ActiveJobs = []string{"a", "b", "c", "d"}
	if p.Allows() {
		t.Error("full runner must deny")
	}
	p = base()
	p.Runner.Capabilities = []string{"container"}
	p.Job.CompiledJobPayload = &model.CompiledJobPayload{EffectiveJob: compiledRuntimeJSON(t, "tart")}
	if p.Allows() {
		t.Error("runtime not declared must deny")
	}
	p = base()
	p.PolicyEnforced = true
	p.PolicyRuntimes = nil
	if p.Allows() {
		t.Error("enforced empty policy grant must deny")
	}
	p = base()
	p.Job.Environment = "prod"
	p.Job.EnvironmentConcurrency = 1
	p.EnvRunning = 1
	if p.Allows() {
		t.Error("full environment must deny")
	}
	p.EnvRunning = 0
	if !p.Allows() {
		t.Error("free environment slot must allow")
	}
}

func compiledRuntimeJSON(t *testing.T, runtime string) json.RawMessage {
	t.Helper()
	c := pipeline.CompiledJob{}
	c.Job.Runtime = runtime
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return json.RawMessage(b)
}

func TestRuntimeAllowedNonVacuous(t *testing.T) {
	if !RuntimeAllowed([]string{"container", "native"}, false, "container") {
		t.Fatal("declared runtime must be allowed")
	}
	if RuntimeAllowed([]string{"container"}, false, "tart") {
		t.Fatal("undeclared runtime must be denied")
	}
	// Legacy (unenforced) semantics: an empty list is unrestricted.
	if !RuntimeAllowed(nil, false, "tart") {
		t.Fatal("legacy empty list must be unrestricted")
	}
	// The empty runtime defaults to native, so a legacy list must contain
	// native to admit it.
	if !RuntimeAllowed([]string{"container", "native"}, false, "") {
		t.Fatal("legacy list containing native must allow the default runtime")
	}
	if RuntimeAllowed([]string{"container"}, false, "") {
		t.Fatal("legacy list without native must deny the default runtime")
	}
	// Enforced semantics: the empty list is an authoritative deny-all, and
	// membership is required for every runtime.
	if RuntimeAllowed(nil, true, "native") || RuntimeAllowed(nil, true, "container") {
		t.Fatal("enforced empty list must deny every runtime")
	}
	if !RuntimeAllowed([]string{"native"}, true, "") || !RuntimeAllowed([]string{"native"}, true, "native") {
		t.Fatal("enforced native only must allow the default runtime")
	}
	if RuntimeAllowed([]string{"native"}, true, "container") {
		t.Fatal("enforced list must deny an undeclared runtime")
	}
}

// TestIntersectCapabilities pins the ONE capability intersection: ceiling
// order survives, duplicates collapse, and either empty side intersects to
// nothing (the authoritative deny-all shape).
func TestIntersectCapabilities(t *testing.T) {
	got := IntersectCapabilities([]string{"native", "container", "tart"}, []string{"tart", "native", "native"})
	if len(got) != 2 || got[0] != "native" || got[1] != "tart" {
		t.Fatalf("intersection = %v, want [native tart] in ceiling order", got)
	}
	if got := IntersectCapabilities([]string{"container"}, []string{"native"}); len(got) != 0 {
		t.Fatalf("disjoint intersection = %v, want empty", got)
	}
	if got := IntersectCapabilities(nil, []string{"native"}); got != nil {
		t.Fatalf("empty ceiling = %v, want nil", got)
	}
	if got := IntersectCapabilities([]string{"native"}, nil); got != nil {
		t.Fatalf("empty claim = %v, want nil", got)
	}
}

// TestNormalizeCapabilities pins the registration claim normalization: empty
// entries are dropped, duplicates collapse and order survives, so the
// persisted reported set is canonical and an all-empty claim reduces to the
// authoritative nil.
func TestNormalizeCapabilities(t *testing.T) {
	got := NormalizeCapabilities([]string{" native ", "", "container", "native", "  "})
	if len(got) != 2 || got[0] != "native" || got[1] != "container" {
		t.Fatalf("normalized = %v, want [native container]", got)
	}
	if got := NormalizeCapabilities([]string{"", "   "}); got != nil {
		t.Fatalf("empty claim = %v, want nil", got)
	}
	if got := NormalizeCapabilities(nil); got != nil {
		t.Fatalf("nil claim = %v, want nil", got)
	}
}

// TestResolveRunnerProfileRecomputesIntersection is the W3-A regression: a
// live profile resolution must NEVER overwrite the effective capability set
// with the profile's set. The reported hardware claim is the invariant, and a
// profile edit can only narrow it.
func TestResolveRunnerProfileRecomputesIntersection(t *testing.T) {
	r := predicateRunner()
	r.ReportedCapabilities = []string{"native"}
	r.Capabilities = []string{"native"}
	r.CapabilitiesEnforced = true
	got := ResolveRunnerProfile(r, model.RunnerProfile{Capabilities: []string{"native", "container"}, MaxCapacity: 2}, true)
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "native" {
		t.Fatalf("effective capabilities = %v, want the reported intersection [native]", got.Capabilities)
	}
	if !got.CapabilitiesEnforced {
		t.Fatal("a linked profile must enforce the recomputed set")
	}
	// A live profile WIDENING back to [native,container] must not restore
	// container: the runner's registration proved it does not provide it.
	got = ResolveRunnerProfile(got, model.RunnerProfile{Capabilities: []string{"native", "container"}, MaxCapacity: 2}, true)
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "native" {
		t.Fatalf("re-resolved capabilities = %v, want [native] after the profile widening", got.Capabilities)
	}
	if !RuntimeAllowed(got.Capabilities, got.CapabilitiesEnforced, "native") ||
		RuntimeAllowed(got.Capabilities, got.CapabilitiesEnforced, "container") {
		t.Fatalf("runtime decision over %v/%v is wrong", got.Capabilities, got.CapabilitiesEnforced)
	}
	// An empty profile ceiling denies every runtime even with a non-empty
	// hardware claim.
	deny := ResolveRunnerProfile(r, model.RunnerProfile{Capabilities: nil, MaxCapacity: 1}, true)
	if len(deny.Capabilities) != 0 || !deny.CapabilitiesEnforced ||
		RuntimeAllowed(deny.Capabilities, deny.CapabilitiesEnforced, "native") {
		t.Fatalf("empty profile must yield an enforced empty deny-all, got %v/%v", deny.Capabilities, deny.CapabilitiesEnforced)
	}
	// The recomputed slice is fresh: mutating the runner's reported claim
	// afterwards cannot change the already-resolved effective set.
	first := got.Capabilities
	r.ReportedCapabilities[0] = "mutated"
	if first[0] != "native" {
		t.Fatalf("intersection aliased the reported slice: %v", first)
	}
	// An unlinked resolution never touches the effective set: the runner is
	// returned unchanged (same capabilities and enforcement marker).
	plain := ResolveRunnerProfile(r, model.RunnerProfile{Capabilities: []string{"container"}, MaxCapacity: 9}, false)
	if len(plain.Capabilities) != 1 || plain.Capabilities[0] != "native" || plain.CapabilitiesEnforced != r.CapabilitiesEnforced {
		t.Fatalf("unlinked resolution mutated the runner: %+v", plain)
	}
}

func TestResolveRunnerProfileOverlaysLinkedProfile(t *testing.T) {
	r := predicateRunner()
	r.CostPerHour = 1
	r.PowerWatts = 2
	r.ReportedCapabilities = []string{"native", "container"}
	profile := model.RunnerProfile{
		Labels:       []string{"gpu"},
		Region:       "us",
		Repositories: []string{"github.com/acme/api"},
		Capabilities: []string{"container"},
		MaxCapacity:  8,
		CostPerHour:  3,
		PowerWatts:   4,
	}
	got := ResolveRunnerProfile(r, profile, true)
	if len(got.Labels) != 1 || got.Labels[0] != "gpu" || got.Region != "us" ||
		got.Capacity != 8 || got.CostPerHour != 3 || got.PowerWatts != 4 ||
		len(got.AllowedRepositories) != 1 || len(got.Capabilities) != 1 {
		t.Fatalf("linked overlay = %+v", got)
	}
	// The overlay copies slices: mutating the profile must not alias.
	profile.Labels[0] = "mutated"
	profile.Repositories[0] = "mutated"
	profile.Capabilities[0] = "mutated"
	if got.Labels[0] != "gpu" || got.AllowedRepositories[0] != "github.com/acme/api" || got.Capabilities[0] != "container" {
		t.Fatalf("overlay aliases profile slices: %+v", got)
	}
	if r.Labels[0] != "linux" || r.Capacity != 4 {
		t.Fatalf("overlay mutated the input runner: %+v", r)
	}
}

func TestEffectiveNeedsAuthority(t *testing.T) {
	j := predicateJob()
	j.Needs = []string{"a"}
	if got := effectiveNeeds("job", j, nil); len(got) != 1 || got[0] != "a" {
		t.Fatalf("needs fallback = %v", got)
	}
	deps := map[string][]string{"job": {}}
	got := effectiveNeeds("job", j, deps)
	if len(got) != 0 {
		t.Fatalf("explicit empty deps entry must win: %v", got)
	}
	// The result is a fresh slice: mutating it must not touch the map.
	deps = map[string][]string{"job": {"b"}}
	got = effectiveNeeds("job", j, deps)
	got[0] = "mutated"
	if deps["job"][0] != "b" {
		t.Fatalf("effectiveNeeds aliases the deps map: %v", deps)
	}
}

func TestLeaseClaimEnvKey(t *testing.T) {
	if got := (LeaseClaim{Environment: "prod"}).EnvKey(); got != "" {
		t.Fatalf("missing canonical repo id = %q, want empty", got)
	}
	if got := (LeaseClaim{CanonRepoID: "github.com/acme/api"}).EnvKey(); got != "" {
		t.Fatalf("missing environment = %q, want empty", got)
	}
	c := LeaseClaim{CanonRepoID: "github.com/acme/api", Environment: "prod"}
	if got, want := c.EnvKey(), "github.com/acme/api\x1fprod"; got != want {
		t.Fatalf("EnvKey = %q, want %q", got, want)
	}
	// The key is the canonical identity, never a clone URL: HTTPS and SSH
	// spellings of one repository must resolve to the same EnvKey.
	ssh := LeaseClaim{CanonRepoID: RepoIDFor("", "git@github.com:acme/api.git", "acme/api"), Environment: "prod"}
	if ssh.EnvKey() != c.EnvKey() {
		t.Fatalf("SSH EnvKey = %q, want the canonical HTTPS key %q", ssh.EnvKey(), c.EnvKey())
	}
}

func TestCompletionEffectIDsAreDeterministic(t *testing.T) {
	kinds := CompletionEffectKinds()
	if len(kinds) != 5 {
		t.Fatalf("CompletionEffectKinds = %v", kinds)
	}
	seen := map[string]bool{}
	for _, k := range kinds {
		id := CompletionEffectID("job-1", 7, k)
		if len(id) != 32 {
			t.Fatalf("effect id %q not 32 hex chars", id)
		}
		if seen[id] {
			t.Fatalf("duplicate effect id for kind %s", k)
		}
		seen[id] = true
		if again := CompletionEffectID("job-1", 7, k); again != id {
			t.Fatalf("effect id not deterministic: %q vs %q", id, again)
		}
		if other := CompletionEffectID("job-1", 8, k); other == id {
			t.Fatalf("generation must change the effect id for kind %s", k)
		}
		if other := CompletionEffectID("job-2", 7, k); other == id {
			t.Fatalf("job must change the effect id for kind %s", k)
		}
	}
}

func TestPendingSidecarValidationHelpers(t *testing.T) {
	jobID := "0123456789abcdef0123456789abcdef"
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := validatePendingSidecarKey(jobID, 1, "bin", ArtifactSidecarKindSBOM); err != nil {
		t.Fatalf("valid sbom key: %v", err)
	}
	if err := validatePendingSidecarKey(jobID, 1, "bin", ArtifactSidecarKindSigstore); err != nil {
		t.Fatalf("valid sigstore key: %v", err)
	}
	if err := validatePendingSidecarKey("bad", 1, "bin", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("invalid job id must fail")
	}
	if err := validatePendingSidecarKey(jobID, 1, "  ", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("empty artifact name must fail")
	}
	if err := validatePendingSidecarKey(jobID, 1, "bin", "pbom"); err == nil {
		t.Fatal("invalid kind must fail")
	}
	if err := validatePendingSidecarKey(jobID, -1, "bin", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("negative generation must fail")
	}
	if err := validatePendingSidecarDigest(digest); err != nil {
		t.Fatalf("valid digest: %v", err)
	}
	if err := validatePendingSidecarDigest(digest[:63]); err == nil {
		t.Fatal("short digest must fail")
	}
	if err := validatePendingSidecarDigest(digest[:63] + "G"); err == nil {
		t.Fatal("non-hex digest char must fail")
	}
	if err := validatePendingSidecarDigest(digest[:63] + "A"); err == nil {
		t.Fatal("uppercase digest char must fail")
	}
}

func TestResolveRunnerProfileUnlinkedReturnsRunner(t *testing.T) {
	r := predicateRunner()
	got := ResolveRunnerProfile(r, model.RunnerProfile{MaxCapacity: 99}, false)
	if got.Capacity != r.Capacity || got.Region != r.Region || got.Labels[0] != "linux" {
		t.Fatalf("unlinked profile must not overlay: %+v", got)
	}
}

func TestRepoFullNameFromURLForms(t *testing.T) {
	cases := map[string]string{
		"":                                     "",
		"https://github.com/acme/api.git":      "acme/api",
		"https://github.com/acme/nested/proj":  "acme/nested/proj",
		"https://user:tok@github.com/acme/api": "acme/api",
		"https:///acme/api":                    "",
		"https://[::1:bad":                     "",
		"git@github.com:acme/api.git":          "acme/api",
		"git@github.com:acme/api":              "acme/api",
		"git@github.com":                       "",
		"acme/api":                             "",
	}
	for in, want := range cases {
		if got := RepoFullNameFromURL(in); got != want {
			t.Errorf("RepoFullNameFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPolicyRuntimeAllowedEmptyJobRuntime(t *testing.T) {
	if !PolicyRuntimeAllowed(true, []string{"container"}, "") {
		t.Fatal("enforced grant with empty job runtime must allow")
	}
	if PolicyRuntimeAllowed(true, nil, "") {
		t.Fatal("enforced empty grant must deny")
	}
	if PolicyRuntimeAllowed(true, []string{"container"}, "tart") {
		t.Fatal("ungranted runtime must deny")
	}
	if !PolicyRuntimeAllowed(false, nil, "tart") {
		t.Fatal("non-enforced policy must allow")
	}
}

func enforcedPolicyJSON(t *testing.T, caps policy.Capabilities) []byte {
	t.Helper()
	b, err := json.Marshal(caps)
	if err != nil {
		t.Fatalf("marshal caps: %v", err)
	}
	return b
}

func TestLeasePolicyRuntimesPayloadEncodings(t *testing.T) {
	caps := policy.Capabilities{Enforced: true, NativeExecution: true, Container: true, Tart: true}
	b := enforcedPolicyJSON(t, caps)
	cases := []any{
		json.RawMessage(b),
		b,
		string(b),
		caps,
	}
	for i, enc := range cases {
		j := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: enc}}
		runtimes, enforced := LeasePolicyRuntimes(j)
		if !enforced {
			t.Fatalf("case %d: expected enforced", i)
		}
		if len(runtimes) != 3 || runtimes[0] != "native" || runtimes[1] != "container" || runtimes[2] != "tart" {
			t.Fatalf("case %d: runtimes = %v", i, runtimes)
		}
	}

	// A non-enforced capability set is not a policy grant.
	plain := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: json.RawMessage(enforcedPolicyJSON(t, policy.Capabilities{Container: true}))}}
	if runtimes, enforced := LeasePolicyRuntimes(plain); enforced || runtimes != nil {
		t.Fatalf("non-enforced caps = %v, %v", runtimes, enforced)
	}

	// Unmarshalable and unmarshal-failing payloads fail closed.
	bad := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: json.RawMessage(`{`)}}
	if runtimes, enforced := LeasePolicyRuntimes(bad); enforced || runtimes != nil {
		t.Fatalf("corrupt policy = %v, %v", runtimes, enforced)
	}
	unsupported := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: func() {}}}
	if runtimes, enforced := LeasePolicyRuntimes(unsupported); enforced || runtimes != nil {
		t.Fatalf("marshal failure = %v, %v", runtimes, enforced)
	}

	// No payload at all.
	if runtimes, enforced := LeasePolicyRuntimes(model.Job{}); enforced || runtimes != nil {
		t.Fatalf("missing payload = %v, %v", runtimes, enforced)
	}
}

func TestJobRuntimePayloadEncodings(t *testing.T) {
	compiled := pipeline.CompiledJob{}
	compiled.Job.Runtime = "container"
	b, err := json.Marshal(compiled)
	if err != nil {
		t.Fatalf("marshal compiled job: %v", err)
	}
	cases := []any{json.RawMessage(b), b, string(b), compiled}
	for i, enc := range cases {
		j := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: enc}}
		if got := JobRuntime(j); got != "container" {
			t.Fatalf("case %d: JobRuntime = %q, want container", i, got)
		}
	}

	for _, runtime := range []string{"tart", "native"} {
		c := pipeline.CompiledJob{}
		c.Job.Runtime = runtime
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		j := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: json.RawMessage(raw)}}
		if got := JobRuntime(j); got != runtime {
			t.Fatalf("JobRuntime = %q, want %q", got, runtime)
		}
	}

	unknown := pipeline.CompiledJob{}
	unknown.Job.Runtime = "unikernel"
	raw, err := json.Marshal(unknown)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := JobRuntime(model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: json.RawMessage(raw)}}); got != "" {
		t.Fatalf("unknown runtime = %q, want empty", got)
	}
	if got := JobRuntime(model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: json.RawMessage(`{`)}}); got != "" {
		t.Fatalf("corrupt payload runtime = %q, want empty", got)
	}
	if got := JobRuntime(model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: func() {}}}); got != "" {
		t.Fatalf("marshal failure runtime = %q, want empty", got)
	}
	if got := JobRuntime(model.Job{}); got != "" {
		t.Fatalf("missing payload runtime = %q, want empty", got)
	}
}

func TestRepoHostForms(t *testing.T) {
	cases := map[string]string{
		"":                                "",
		"https://github.com/acme/api.git": "github.com",
		"https://user:tok@gitlab.example.com/a/b": "gitlab.example.com",
		"ssh://git@github.com:2222/acme/api.git":  "github.com:2222",
		"https://github.com":                      "github.com",
		"git@github.com:acme/api.git":             "github.com",
		"github.com:acme/api":                     "github.com",
		"github.com/acme/api":                     "github.com",
		"github.com":                              "github.com",
	}
	for in, want := range cases {
		if got := RepoHost(in); got != want {
			t.Errorf("RepoHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuotaExceededErrorMessage(t *testing.T) {
	withReason := &QuotaExceededError{Reason: "REPO_QUOTA", Msg: "too many"}
	if got := withReason.Error(); got != "REPO_QUOTA: too many" {
		t.Fatalf("Error() = %q", got)
	}
	withoutReason := &QuotaExceededError{Msg: "too many"}
	if got := withoutReason.Error(); got != "too many" {
		t.Fatalf("Error() = %q", got)
	}
	if err := error(withReason); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatal("QuotaExceededError must unwrap to ErrQuotaExceeded")
	}
	if !errors.Is(fmt.Errorf("admission: %w", withReason), ErrQuotaExceeded) {
		t.Fatal("wrapped QuotaExceededError must match ErrQuotaExceeded")
	}
}

func TestRepoTeamKeySchemes(t *testing.T) {
	if got := repoTeamKey("https://github.com"); got != "github.com" {
		t.Fatalf("host-only URL team key = %q", got)
	}
	if got := repoTeamKey("https://github.com/acme"); got != "github.com/acme" {
		t.Fatalf("host/owner URL team key = %q", got)
	}
}

func TestRepoTeamKeyAndQuotaKeysDeduplicate(t *testing.T) {
	if got := QuotaKeys(""); got != nil {
		t.Fatalf("QuotaKeys(\"\") = %v, want nil", got)
	}
	if got := QuotaKeys("   "); got != nil {
		t.Fatalf("QuotaKeys(blank) = %v, want nil", got)
	}
	if got := QuotaKeys("acme/api"); len(got) != 1 || got[0] != "acme/api" {
		t.Fatalf("QuotaKeys(bare) = %v", got)
	}
	if got := RepoTeamKey("acme/api"); got != "" {
		t.Fatalf("RepoTeamKey(bare) = %q, want empty", got)
	}
	if got := RepoTeamKey("github.com/acme/api"); got != "github.com/acme" {
		t.Fatalf("RepoTeamKey(canonical) = %q", got)
	}
	if got := repoTeamKey("github.com/acme/api"); got != "github.com/acme" {
		t.Fatalf("canonical team key = %q", got)
	}
	if got := repoTeamKey("github.com.co/acme/api"); got != "github.com.co/acme" {
		t.Fatalf("dotted host team key = %q", got)
	}
}

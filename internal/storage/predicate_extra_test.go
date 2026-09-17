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
	if !RuntimeAllowed([]string{"container", "native"}, "container") {
		t.Fatal("declared runtime must be allowed")
	}
	if RuntimeAllowed([]string{"container"}, "tart") {
		t.Fatal("undeclared runtime must be denied")
	}
	if !RuntimeAllowed(nil, "tart") || !RuntimeAllowed([]string{"container"}, "") {
		t.Fatal("vacuous cases must allow")
	}
}

func TestResolveRunnerProfileOverlaysLinkedProfile(t *testing.T) {
	r := predicateRunner()
	r.CostPerHour = 1
	r.PowerWatts = 2
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
		t.Fatalf("missing repo URL = %q, want empty", got)
	}
	if got := (LeaseClaim{RepoURL: "https://github.com/acme/api"}).EnvKey(); got != "" {
		t.Fatalf("missing environment = %q, want empty", got)
	}
	c := LeaseClaim{RepoURL: "https://github.com/acme/api", Environment: "prod"}
	if got, want := c.EnvKey(), "https://github.com/acme/api\x1fprod"; got != want {
		t.Fatalf("EnvKey = %q, want %q", got, want)
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
	if err := validatePendingSidecarKey(jobID, "bin", ArtifactSidecarKindSBOM); err != nil {
		t.Fatalf("valid sbom key: %v", err)
	}
	if err := validatePendingSidecarKey(jobID, "bin", ArtifactSidecarKindSigstore); err != nil {
		t.Fatalf("valid sigstore key: %v", err)
	}
	if err := validatePendingSidecarKey("bad", "bin", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("invalid job id must fail")
	}
	if err := validatePendingSidecarKey(jobID, "  ", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("empty artifact name must fail")
	}
	if err := validatePendingSidecarKey(jobID, "bin", "pbom"); err == nil {
		t.Fatal("invalid kind must fail")
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

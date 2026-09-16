package pipeline

import (
	"fmt"
	"strings"
	"testing"
)

func oneStepJob(steps ...Step) Job {
	if len(steps) == 0 {
		steps = []Step{{Run: "echo hi"}}
	}
	return Job{Steps: steps}
}

func TestValidateLimitsDeclaredJobs(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	for i := 0; i < maxDeclaredJobs+1; i++ {
		s.Jobs[fmt.Sprintf("job%d", i)] = oneStepJob()
	}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "declares 1025 jobs") {
		t.Fatalf("want declared-jobs limit error, got %v", err)
	}
}

func TestValidateLimitsExpandedJobs(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	for i := 0; i < 9; i++ {
		vals := make([]any, maxMatrixCombos)
		for k := range vals {
			vals[k] = fmt.Sprintf("v%d", k)
		}
		s.Jobs[fmt.Sprintf("job%d", i)] = Job{
			Matrix: map[string][]any{"dim": vals},
			Steps:  []Step{{Run: "echo hi"}},
		}
	}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "expands to") {
		t.Fatalf("want expanded-jobs limit error, got %v", err)
	}
}

func TestValidateLimitsSteps(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	steps := make([]Step, maxStepsPerJob+1)
	for i := range steps {
		steps[i] = Step{Run: "echo hi"}
	}
	s.Jobs["x"] = Job{Steps: steps}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "513 steps") {
		t.Fatalf("want steps limit error, got %v", err)
	}
}

func TestValidateLimitsServices(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	svcs := make([]Service, maxServicesPerJob+1)
	for i := range svcs {
		svcs[i] = Service{Name: fmt.Sprintf("s%d", i), Image: "alpine"}
	}
	s.Jobs["x"] = Job{Services: svcs, Steps: []Step{{Run: "echo hi"}}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "33 services") {
		t.Fatalf("want services limit error, got %v", err)
	}
}

func TestValidateLimitsSecrets(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	names := make([]string, maxSecretsPerJob+1)
	for i := range names {
		names[i] = fmt.Sprintf("secret-%d", i)
	}
	s.Secrets = names
	s.Jobs["x"] = oneStepJob()
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "129 secret names") {
		t.Fatalf("want secrets limit error, got %v", err)
	}
}

func TestValidateLimitsEnvValueSize(t *testing.T) {
	_, err := Parse([]byte("version: 1\njobs:\n  x:\n    env:\n      BIG: \"" + strings.Repeat("a", maxEnvValueBytes+1) + "\"\n    steps:\n      - run: echo hi\n"))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want env value size error, got %v", err)
	}
}

func TestValidateLimitsCommandSize(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{
		"x": {Steps: []Step{{Run: strings.Repeat("a", maxCommandBytes+1)}}},
	}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "command exceeds") {
		t.Fatalf("want command size error, got %v", err)
	}
}

func TestValidateLimitsMatrixDims(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	m := map[string][]any{}
	for i := 0; i < maxMatrixDims+1; i++ {
		m[fmt.Sprintf("d%d", i)] = []any{"a", "b"}
	}
	s.Jobs["x"] = Job{Matrix: m, Steps: []Step{{Run: "echo hi"}}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "13 dimensions") {
		t.Fatalf("want matrix dims error, got %v", err)
	}
}

func TestValidateLimitsMatrixCombos(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	vals := make([]any, maxMatrixCombos+1)
	for i := range vals {
		vals[i] = fmt.Sprintf("v%d", i)
	}
	s.Jobs["x"] = Job{Matrix: map[string][]any{"dim": vals}, Steps: []Step{{Run: "echo hi"}}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "513 combinations") {
		t.Fatalf("want matrix combos error, got %v", err)
	}
}

func TestValidateLimitsArtifacts(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	arts := make([]Artifact, maxArtifactDefs+1)
	for i := range arts {
		arts[i] = Artifact{Name: fmt.Sprintf("a%d", i), Paths: []string{"out"}}
	}
	s.Jobs["x"] = Job{Artifacts: arts, Steps: []Step{{Run: "echo hi"}}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "129 artifacts") {
		t.Fatalf("want artifacts limit error, got %v", err)
	}
}

func TestValidateLimitsOutputs(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	out := map[string]string{}
	for i := 0; i < maxOutputKeys+1; i++ {
		out[fmt.Sprintf("out%d", i)] = "v"
	}
	s.Jobs["x"] = Job{Outputs: out, Steps: []Step{{Run: "echo hi"}}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "257 output keys") {
		t.Fatalf("want outputs limit error, got %v", err)
	}
}

func TestValidateStructuralTable(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{
			"bad job id",
			`version: 1
jobs:
  1bad:
    steps:
      - run: echo hi
`,
			`invalid job id "1bad"`,
		},
		{
			"duplicate step ids",
			`version: 1
jobs:
  x:
    steps:
      - id: a
        run: echo one
      - id: a
        run: echo two
`,
			`duplicate step id "a"`,
		},
		{
			"bad runner label",
			`version: 1
jobs:
  x:
    runner: ["bad label!"]
    steps:
      - run: echo hi
`,
			"invalid runner label",
		},
		{
			"absolute working_directory",
			`version: 1
jobs:
  x:
    steps:
      - run: echo hi
        working_directory: /tmp/work
`,
			"absolute path",
		},
		{
			"dotdot working_directory",
			`version: 1
jobs:
  x:
    steps:
      - run: echo hi
        working_directory: ../escape
`,
			".. component",
		},
		{
			"dotdot artifact path",
			`version: 1
jobs:
  x:
    artifacts:
      - name: out
        paths: ["../secrets"]
    steps:
      - run: echo hi
`,
			".. component",
		},
		{
			"absolute cache path",
			`version: 1
jobs:
  x:
    cache:
      - key: k
        paths: ["/abs"]
    steps:
      - run: echo hi
`,
			"absolute path",
		},
		{
			"zero timeout",
			`version: 1
jobs:
  x:
    timeout: 0s
    steps:
      - run: echo hi
`,
			"positive duration",
		},
		{
			"negative timeout",
			`version: 1
jobs:
  x:
    timeout: -5s
    steps:
      - run: echo hi
`,
			"positive duration",
		},
		{
			"zero backoff",
			`version: 1
jobs:
  x:
    retry:
      max: 1
      backoff: 0s
    steps:
      - run: echo hi
`,
			"positive duration",
		},
		{
			"bad retry class",
			`version: 1
jobs:
  x:
    retry:
      max: 1
      on: [bogus]
    steps:
      - run: echo hi
`,
			"invalid retry class",
		},
		{
			"duplicate artifact names",
			`version: 1
jobs:
  x:
    artifacts:
      - name: out
        paths: [out]
      - name: out
        paths: [out2]
    steps:
      - run: echo hi
`,
			`declares artifact "out" more than once`,
		},
		{
			"download without producer",
			`version: 1
jobs:
  build:
    steps:
      - run: make
  test:
    downloads:
      - from: other
        name: nope
    steps:
      - run: echo hi
`,
			"downloads from unknown job",
		},
		{
			"download not a dependency",
			`version: 1
jobs:
  build:
    steps:
      - run: make
  test:
    downloads:
      - from: build
        name: nope
    steps:
      - run: echo hi
`,
			"not a declared dependency",
		},
		{
			"matrix empty dimension",
			`version: 1
jobs:
  x:
    matrix:
      GO: []
    steps:
      - run: echo hi
`,
			`matrix dimension "GO" has no values`,
		},
		{
			"matrix non-scalar value",
			`version: 1
jobs:
  x:
    matrix:
      GO:
        - [a, b]
    steps:
      - run: echo hi
`,
			"non-scalar value",
		},
		{
			"unresolved interpolation missing close",
			`version: 1
jobs:
  x:
    steps:
      - run: echo ${{ matrix.GO
`,
			"missing closing }}",
		},
		{
			"unknown interpolation context",
			`version: 1
jobs:
  x:
    steps:
      - run: echo ${{ foo.bar }}
`,
			`unknown interpolation context "foo"`,
		},
		{
			"native with image",
			`version: 1
jobs:
  x:
    runtime: native
    image: alpine
    steps:
      - run: echo hi
`,
			"native runtime must not set image or vm",
		},
		{
			"tart without vm",
			`version: 1
jobs:
  x:
    runtime: tart
    steps:
      - run: echo hi
`,
			"tart runtime requires a vm",
		},
		{
			"duplicate dependency",
			`version: 1
jobs:
  a:
    steps:
      - run: echo hi
  b:
    needs: [a, a]
    steps:
      - run: echo hi
`,
			"more than once",
		},
		{
			"bad environment name",
			`version: 1
jobs:
  x:
    environment:
      name: "bad name!"
    steps:
      - run: echo hi
`,
			"invalid environment name",
		},
		{
			"bad service alias",
			`version: 1
jobs:
  x:
    services:
      - name: "bad name!"
        image: alpine
    steps:
      - run: echo hi
`,
			"invalid service alias",
		},
		{
			"bad output identifier",
			`version: 1
jobs:
  x:
    outputs:
      1bad: "value"
    steps:
      - run: echo hi
`,
			`invalid output identifier "1bad"`,
		},
		{
			"bad shell",
			`version: 1
jobs:
  x:
    shell: tcsh
    steps:
      - run: echo hi
`,
			`unsupported shell "tcsh"`,
		},
		{
			"duplicate secret within step",
			`version: 1
jobs:
  x:
    steps:
      - run: echo hi
        secrets: [a, a]
`,
			`lists secret "a" more than once`,
		},
		{
			"zero retention",
			`version: 1
jobs:
  x:
    artifacts:
      - name: out
        paths: [out]
        retention: "0s"
    steps:
      - run: echo hi
`,
			"must be positive",
		},
		{
			"garbage retention",
			`version: 1
jobs:
  x:
    artifacts:
      - name: out
        paths: [out]
        retention: "soon"
    steps:
      - run: echo hi
`,
			"invalid retention",
		},
		{
			"negative retry max",
			`version: 1
jobs:
  x:
    retry:
      max: -1
    steps:
      - run: echo hi
`,
			"max must not be negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateAcceptsForeverRetention(t *testing.T) {
	_, err := Parse([]byte(`version: 1
jobs:
  x:
    artifacts:
      - name: out
        paths: [out]
        retention: "forever"
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatalf("forever retention must be accepted: %v", err)
	}
}

func TestValidateMatrixContextsAccepted(t *testing.T) {
	_, err := Parse([]byte(`version: 1
jobs:
  x:
    matrix:
      GO: ["1.23", "1.24"]
    steps:
      - run: echo ${{ matrix.GO }} ${{ env.PATH }} ${{ github.sha }} ${{ secrets.TOKEN }} ${{ inputs.flavor }} ${{ vars.V }} ${{ runner.os }}
`))
	if err != nil {
		t.Fatalf("known interpolation contexts must be accepted: %v", err)
	}
}

func TestValidateLimitsEnvVars(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	env := map[string]string{}
	for i := 0; i < maxEnvVarsPerJob+1; i++ {
		env[fmt.Sprintf("V%d", i)] = "v"
	}
	s.Jobs["x"] = Job{Env: env, Steps: []Step{{Run: "echo hi"}}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "1025 env vars") {
		t.Fatalf("want env vars limit error, got %v", err)
	}
}

func TestSaturatingMulNoOverflow(t *testing.T) {
	cases := []struct {
		name      string
		n, factor int
		limit     int
		want      int
	}{
		{"exact fit", 512, 1, maxMatrixCombos, 512},
		{"over limit by one", 513, 1, maxMatrixCombos, maxMatrixCombos + 1},
		{"int32 product overflow", 1 << 30, 1 << 30, maxMatrixCombos, maxMatrixCombos + 1},
		{"int64 product overflow", 1 << 62, 8, maxMatrixCombos, maxMatrixCombos + 1},
		{"factor alone over limit", 1, maxMatrixCombos + 1, maxMatrixCombos, maxMatrixCombos + 1},
		{"zero factor", 5, 0, maxMatrixCombos, 0},
		{"zero n", 0, 5, maxMatrixCombos, 0},
		{"shard product saturates at expanded limit", maxMatrixCombos, maxShardsPerJob, maxExpandedJobs, maxExpandedJobs + 1},
		{"shard product within limit", 4, maxShardsPerJob, maxExpandedJobs, maxExpandedJobs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := saturatingMul(tc.n, tc.factor, tc.limit); got != tc.want {
				t.Fatalf("saturatingMul(%d, %d, %d) = %d, want %d (no wrap)", tc.n, tc.factor, tc.limit, got, tc.want)
			}
		})
	}
}

func TestMatrixComboCountNeverWraps(t *testing.T) {
	// A product that would overflow int32 (100000*100000 = 10^10) must
	// saturate at maxMatrixCombos+1 instead of wrapping to a small or
	// negative number.
	big := make([]any, 100000)
	m := map[string][]any{
		"a": big,
		"b": big,
	}
	if got := matrixComboCount(m); got != maxMatrixCombos+1 {
		t.Fatalf("matrixComboCount = %d, want saturated %d", got, maxMatrixCombos+1)
	}
	s := &Spec{Version: 1, Jobs: map[string]Job{
		"x": {Matrix: m, Steps: []Step{{Run: "echo hi"}}},
	}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "513 combinations") {
		t.Fatalf("overflowed matrix must be rejected with the limit error, got %v", err)
	}
}

func TestValidateLimitsExpansionMultiplicationNeverWraps(t *testing.T) {
	// combos x shards and the running total must saturate, never wrap.
	s := &Spec{Version: 1, Jobs: map[string]Job{}}
	vals := make([]any, maxMatrixCombos)
	for i := range vals {
		vals[i] = fmt.Sprintf("v%d", i)
	}
	// 512 combos x 1024 shards per job overflows nothing but exceeds the
	// expanded-jobs limit as a saturated count.
	s.Jobs["x"] = Job{Matrix: map[string][]any{"dim": vals}, Tests: TestConfig{Shards: maxShardsPerJob}, Steps: []Step{{Run: "echo hi"}}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), "expands to") {
		t.Fatalf("combos x shards overflow must surface as the limit error, got %v", err)
	}
}

func TestSecretNameGrammarRejectsPunctuation(t *testing.T) {
	for _, name := range []string{"foo-bar", "foo.bar", "foo/bar", "foo bar", "9foo", "-foo", "a!b"} {
		_, err := Parse([]byte("version: 1\nsecrets: [" + name + "]\njobs:\n  x:\n    steps:\n      - run: echo hi\n"))
		if err == nil {
			t.Fatalf("secret name %q accepted", name)
		}
		if !strings.Contains(err.Error(), "must match") || !strings.Contains(err.Error(), name) {
			t.Fatalf("secret name %q error = %v, want grammar rejection naming the secret", name, err)
		}
	}
	// Step-level declarations get the same treatment.
	_, err := Parse([]byte("version: 1\njobs:\n  x:\n    steps:\n      - run: echo hi\n        secrets: [foo-bar]\n"))
	if err == nil || !strings.Contains(err.Error(), `invalid secret name "foo-bar"`) {
		t.Fatalf("step secret punctuation error = %v", err)
	}
}

func TestSecretNameGrammarAcceptsEnvSafeNames(t *testing.T) {
	s, err := Parse([]byte("version: 1\nsecrets: [foo_bar, Foo_1, _lead]\njobs:\n  x:\n    steps:\n      - run: echo hi\n        secrets: [foo_bar]\n"))
	if err != nil {
		t.Fatalf("env-safe secret names must be accepted: %v", err)
	}
	if len(s.Secrets) != 3 {
		t.Fatalf("secrets = %v", s.Secrets)
	}
}

func TestSecretNameCollisionsImpossible(t *testing.T) {
	// foo_bar, foo-bar and foo.bar all project to KIWI_SECRET_FOO_BAR; only
	// the canonical form is admitted, so accepted names can never collide.
	accepted := []string{"foo_bar", "Foo_Bar", "FOO_BAR_1", "_x"}
	for _, name := range accepted {
		if _, err := Parse([]byte("version: 1\nsecrets: [" + name + "]\njobs:\n  x:\n    steps:\n      - run: echo hi\n")); err != nil {
			t.Fatalf("canonical secret name %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"foo-bar", "foo.bar", "foo bar"} {
		if _, err := Parse([]byte("version: 1\nsecrets: [" + name + "]\njobs:\n  x:\n    steps:\n      - run: echo hi\n")); err == nil {
			t.Fatalf("punctuated secret name %q accepted (would collide under env projection)", name)
		}
	}
}

package pipeline

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestCompileExpandsTestShards(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  test:
    tests:
      shards: 3
    steps:
      - run: echo shard ${{ matrix.test_shard }}
  wrap:
    needs: [test]
    steps:
      - run: echo wrap
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Jobs) != 4 {
		t.Fatalf("compiled %d jobs, want 4 (3 shard variants + wrap)", len(g.Jobs))
	}
	for i := 0; i < 3; i++ {
		id := "test[test_shard=" + strconv.Itoa(i) + "]"
		cj, ok := g.Jobs[id]
		if !ok {
			t.Fatalf("missing compiled job %q (have %v)", id, jobIDs(g))
		}
		if cj.BaseID != "test" {
			t.Errorf("%s BaseID = %q, want test", id, cj.BaseID)
		}
		if cj.Job.Tests.Shards != 3 {
			t.Errorf("%s Job.Tests.Shards = %d, want 3 (declared shards stay on each variant)", id, cj.Job.Tests.Shards)
		}
		if got := cj.Matrix["test_shard"]; got != strconv.Itoa(i) {
			t.Errorf("%s matrix test_shard = %q, want %d", id, got, i)
		}
		if got := cj.Job.Env["KIWI_TEST_SHARD_TOTAL"]; got != "3" {
			t.Errorf("%s KIWI_TEST_SHARD_TOTAL = %q, want 3", id, got)
		}
		if got := cj.Job.Env["KIWI_TEST_SHARD_INDEX"]; got != strconv.Itoa(i) {
			t.Errorf("%s KIWI_TEST_SHARD_INDEX = %q, want %d", id, got, i)
		}
		if got := cj.Job.Env["KIWI_MATRIX_TEST_SHARD"]; got != strconv.Itoa(i) {
			t.Errorf("%s KIWI_MATRIX_TEST_SHARD = %q, want %d", id, got, i)
		}
		if want := "echo shard " + strconv.Itoa(i); cj.Job.Steps[0].Run != want {
			t.Errorf("%s step = %q, want %q (matrix.test_shard must interpolate)", id, cj.Job.Steps[0].Run, want)
		}
	}
	wrap := g.Jobs["wrap"]
	want := []string{"test[test_shard=0]", "test[test_shard=1]", "test[test_shard=2]"}
	sort.Strings(wrap.Needs)
	if !reflect.DeepEqual(wrap.Needs, want) {
		t.Errorf("wrap needs = %v, want all shard variants %v", wrap.Needs, want)
	}
}

func TestCompileShardsWithMatrix(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  test:
    matrix:
      GO: ["1.23", "1.24"]
    tests:
      shards: 2
    steps:
      - run: echo ${{ matrix.GO }}.${{ matrix.test_shard }}
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Jobs) != 4 {
		t.Fatalf("compiled %d jobs, want 4 (2 matrix x 2 shards)", len(g.Jobs))
	}
	for _, goV := range []string{"1.23", "1.24"} {
		for i := 0; i < 2; i++ {
			id := "test[GO=" + goV + ",test_shard=" + strconv.Itoa(i) + "]"
			cj, ok := g.Jobs[id]
			if !ok {
				t.Fatalf("missing compiled job %q (have %v)", id, jobIDs(g))
			}
			if want := "echo " + goV + "." + strconv.Itoa(i); cj.Job.Steps[0].Run != want {
				t.Errorf("%s step = %q, want %q", id, cj.Job.Steps[0].Run, want)
			}
			if got := cj.Job.Env["KIWI_TEST_SHARD_TOTAL"]; got != "2" {
				t.Errorf("%s KIWI_TEST_SHARD_TOTAL = %q, want 2", id, got)
			}
			if got := cj.Job.Env["KIWI_TEST_SHARD_INDEX"]; got != strconv.Itoa(i) {
				t.Errorf("%s KIWI_TEST_SHARD_INDEX = %q, want %d", id, got, i)
			}
			if got := cj.Job.Env["KIWI_MATRIX_GO"]; got != goV {
				t.Errorf("%s KIWI_MATRIX_GO = %q, want %s", id, got, goV)
			}
		}
	}
}

func TestCompileShardsDeterministic(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  test:
    matrix:
      GO: ["1.23", "1.24"]
    tests:
      shards: 4
    steps:
      - run: go test ./...
`))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileWithInputs(s, map[string]string{"unused": "v"})
	if err != nil {
		t.Fatal(err)
	}
	a, b := jobIDs(first), jobIDs(second)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("shard expansion is not deterministic: %v vs %v", a, b)
	}
	want := []string{"test[GO=1.23,test_shard=0]", "test[GO=1.23,test_shard=1]", "test[GO=1.23,test_shard=2]", "test[GO=1.23,test_shard=3]",
		"test[GO=1.24,test_shard=0]", "test[GO=1.24,test_shard=1]", "test[GO=1.24,test_shard=2]", "test[GO=1.24,test_shard=3]"}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("compiled IDs = %v, want %v", a, want)
	}
}

func TestCompileShardsEnvOverridesUserEnv(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  test:
    tests:
      shards: 2
    env:
      KIWI_TEST_SHARD_TOTAL: user-value
      KIWI_TEST_SHARD_INDEX: user-value
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	cj := g.Jobs["test[test_shard=1]"]
	if got := cj.Job.Env["KIWI_TEST_SHARD_TOTAL"]; got != "2" {
		t.Errorf("KIWI_TEST_SHARD_TOTAL = %q, want compile-time 2 to win over user env", got)
	}
	if got := cj.Job.Env["KIWI_TEST_SHARD_INDEX"]; got != "1" {
		t.Errorf("KIWI_TEST_SHARD_INDEX = %q, want compile-time 1 to win over user env", got)
	}
}

func TestCompileSingleShardIsNotExpanded(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  test:
    tests:
      shards: 1
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	cj, ok := g.Jobs["test"]
	if !ok {
		t.Fatalf("shards: 1 must not expand the job, have %v", jobIDs(g))
	}
	if _, set := cj.Job.Env["KIWI_TEST_SHARD_TOTAL"]; set {
		t.Error("shards: 1 must not inject the shard env contract")
	}
}

func TestValidateRejectsShardRange(t *testing.T) {
	negative := &Spec{Version: 1, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "echo hi"}}, Tests: TestConfig{Shards: -1}}}}
	if err := Validate(negative); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Errorf("negative shards error = %v, want negative error", err)
	}
	tooMany := &Spec{Version: 1, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "echo hi"}}, Tests: TestConfig{Shards: maxShardsPerJob + 1}}}}
	if err := Validate(tooMany); err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
		t.Errorf("oversized shards error = %v, want limit error", err)
	}
	atLimit := &Spec{Version: 1, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "echo hi"}}, Tests: TestConfig{Shards: maxShardsPerJob}}}}
	if err := Validate(atLimit); err != nil {
		t.Errorf("shards at the %d limit must validate: %v", maxShardsPerJob, err)
	}
}

func TestValidateRejectsReservedShardMatrixKey(t *testing.T) {
	_, err := Parse([]byte(`version: 1
jobs:
  x:
    matrix:
      test_shard: [a, b]
    tests:
      shards: 2
    steps:
      - run: echo hi
`))
	if err == nil || !strings.Contains(err.Error(), "reserved for tests.shards") {
		t.Fatalf("reserved matrix key error = %v, want reserved dimension error", err)
	}
	_, err = Parse([]byte(`version: 1
jobs:
  x:
    matrix:
      test_shard: [a, b]
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Errorf("test_shard without tests.shards must stay a normal matrix key: %v", err)
	}
}

func TestValidateManifestPathConfinement(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		wantErr  string
	}{
		{"absolute", "/etc/tests.txt", "absolute path"},
		{"parent traversal", "../tests.txt", ".. component"},
		{"nested traversal", "a/../../tests.txt", ".. component"},
		{"windows abs", "C:\\tests.txt", "absolute path"},
		{"relative ok", "testdata/manifest.txt", ""},
		{"dot ok", "./manifest.txt", ""},
		{"empty ok", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Spec{Version: 1, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "echo hi"}}, Tests: TestConfig{Manifest: tc.manifest}}}}
			err := Validate(s)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("manifest %q rejected: %v", tc.manifest, err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("manifest %q error = %v, want %q", tc.manifest, err, tc.wantErr)
			}
		})
	}
}

func TestValidateLimitsCountsShardExpansion(t *testing.T) {
	mk := func(jobs int) *Spec {
		s := &Spec{Version: 1, Jobs: map[string]Job{}}
		for i := 0; i < jobs; i++ {
			s.Jobs["job"+strconv.Itoa(i)] = Job{
				Steps: []Step{{Run: "echo hi"}},
				Tests: TestConfig{Shards: maxShardsPerJob},
			}
		}
		return s
	}
	if err := Validate(mk(4)); err != nil {
		t.Errorf("4 jobs x %d shards must fit the expanded-jobs limit: %v", maxShardsPerJob, err)
	}
	if err := Validate(mk(5)); err == nil || !strings.Contains(err.Error(), "expands to") {
		t.Errorf("5 jobs x %d shards error = %v, want expanded-jobs limit error", maxShardsPerJob, err)
	}
}

func TestCompileShardsAtLimit(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "echo hi"}}, Tests: TestConfig{Shards: maxShardsPerJob}}}}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Jobs) != maxShardsPerJob {
		t.Fatalf("compiled %d jobs, want %d", len(g.Jobs), maxShardsPerJob)
	}
	for i := 0; i < maxShardsPerJob; i++ {
		if _, ok := g.Jobs["x[test_shard="+strconv.Itoa(i)+"]"]; !ok {
			t.Fatalf("missing variant x[test_shard=%d]", i)
		}
	}
}

func jobIDs(g *Graph) []string {
	ids := make([]string, 0, len(g.Jobs))
	for id := range g.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

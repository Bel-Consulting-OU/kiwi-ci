package pipeline

import "testing"

func TestParseAndCompileMatrix(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  test:
    matrix:
      GO: ["1.23", "1.24"]
      DB: [sqlite, postgres]
    cache:
      - key: "deps-${{ matrix.GO }}"
        paths: [.cache]
    steps:
      - name: unit
        run: echo ${{ matrix.GO }} ${{ matrix.DB }}
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Jobs) != 4 {
		t.Fatalf("expected 4 jobs, got %d", len(g.Jobs))
	}
	for _, j := range g.Jobs {
		if j.Job.Cache[0].Key == "deps-${{ matrix.GO }}" {
			t.Fatal("cache key was not interpolated")
		}
		if j.Job.Steps[0].Run == "echo ${{ matrix.GO }} ${{ matrix.DB }}" {
			t.Fatal("step was not interpolated")
		}
	}
}

func TestRejectCycle(t *testing.T) {
	_, err := Parse([]byte(`version: 1
jobs:
  a:
    needs: [b]
    steps: [{run: "true"}]
  b:
    needs: [a]
    steps: [{run: "true"}]
`))
	if err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestConditions(t *testing.T) {
	ok, err := Eval("", EvalContext{})
	if err != nil || !ok {
		t.Fatalf("empty condition must run: %v %v", ok, err)
	}
	ok, err = Eval("success()", EvalContext{})
	if err != nil || !ok {
		t.Fatalf("success() must be true before failure")
	}
}

func TestPathsMatch(t *testing.T) {
	if !PathsMatch([]string{"services/api/main.go"}, []string{"services/**"}, nil) {
		t.Fatal("** include did not match")
	}
	if PathsMatch([]string{"docs/readme.md"}, []string{"services/**"}, nil) {
		t.Fatal("unrelated path matched")
	}
	if PathsMatch([]string{"services/api/generated/x.go"}, []string{"services/**"}, []string{"**/generated/**"}) {
		t.Fatal("exclude should win")
	}
}

func TestBlockScalar(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  x:
    steps:
      - run: |
          echo one
          echo two
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Jobs["x"].Steps[0].Run; got != "echo one\necho two\n" {
		t.Fatalf("unexpected block: %q", got)
	}
}

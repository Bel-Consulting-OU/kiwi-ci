package pipeline

import (
	"testing"
)

func inputsSpecFixture(t *testing.T) *Spec {
	t.Helper()
	s, err := Parse([]byte(`version: 1
inputs:
  who:
    default: world
  count:
    default: 3
    type: integer
  flag:
    type: boolean
    default: "false"
  tier:
    type: enum
    options: [dev, prod]
    default: dev
jobs:
  a:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidateRunInputsContract(t *testing.T) {
	spec := inputsSpecFixture(t)

	got, err := ValidateRunInputs(spec, nil)
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if got["who"] != "world" || got["count"] != "3" || got["flag"] != "false" || got["tier"] != "dev" {
		t.Fatalf("defaults = %v", got)
	}

	got, err = ValidateRunInputs(spec, map[string]string{"who": "kiwi", "count": "7", "flag": "true", "tier": "prod"})
	if err != nil {
		t.Fatalf("provided: %v", err)
	}
	if got["who"] != "kiwi" || got["count"] != "7" || got["flag"] != "true" || got["tier"] != "prod" {
		t.Fatalf("provided = %v", got)
	}

	for name, in := range map[string]map[string]string{
		"unknown name": {"ghost": "1"},
		"bad integer":  {"count": "many"},
		"bad boolean":  {"flag": "yes"},
		"bad enum":     {"tier": "staging"},
	} {
		if _, err := ValidateRunInputs(spec, in); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	req, err := Parse([]byte("version: 1\ninputs:\n  needed:\n    required: true\njobs:\n  a:\n    steps:\n      - run: echo hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRunInputs(req, nil); err == nil {
		t.Fatal("required input missing accepted")
	}
	if _, err := ValidateRunInputs(req, map[string]string{"needed": "x"}); err != nil {
		t.Fatalf("required provided: %v", err)
	}

	if _, err := ValidateRunInputs(nil, nil); err == nil {
		t.Fatal("nil spec accepted")
	}
}

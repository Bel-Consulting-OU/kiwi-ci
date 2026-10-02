package pipeline

// Retry-policy admission regressions: finite caps (including the MaxInt
// overflow domain) and explicit-zero presence semantics.

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func retryDoc(jobExtra string) string {
	return "version: 1\ndefaults:\n  retry:\n    max: 5\njobs:\n  a:\n" + jobExtra + "    steps:\n      - run: r\n"
}

func TestRetryCapsEnforcedAtAdmission(t *testing.T) {
	// Boundary values are accepted.
	boundary := retryDoc(fmt.Sprintf("    retry:\n      max: %d\n    infra_retries: %d\n    services:\n      - name: db\n        image: img\n        retries: %d\n",
		MaxStepRetries, MaxInfraRetries, MaxServiceRetries))
	if _, err := Parse([]byte(boundary)); err != nil {
		t.Fatalf("boundary retry policy rejected: %v", err)
	}

	cases := map[string]string{
		"step retry over cap":      "version: 1\njobs:\n  a:\n    steps:\n      - run: r\n        retry:\n          max: " + fmt.Sprint(MaxStepRetries+1) + "\n",
		"job retry over cap":       retryDoc(fmt.Sprintf("    retry:\n      max: %d\n", MaxStepRetries+1)),
		"defaults retry over cap":  "version: 1\ndefaults:\n  retry:\n    max: " + fmt.Sprint(MaxStepRetries+1) + "\njobs:\n  a:\n    steps:\n      - run: r\n",
		"maxint retry":             retryDoc(fmt.Sprintf("    retry:\n      max: %d\n", math.MaxInt)),
		"service retries over cap": retryDoc(fmt.Sprintf("    services:\n      - name: db\n        image: img\n        retries: %d\n", MaxServiceRetries+1)),
		"infra retries over cap":   retryDoc(fmt.Sprintf("    infra_retries: %d\n", MaxInfraRetries+1)),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("%s = %v, want a cap rejection", name, err)
		}
	}
}

func TestRetryExplicitZeroPresence(t *testing.T) {
	doc := "version: 1\ndefaults:\n  retry:\n    max: 5\njobs:\n  a:\n    retry:\n      max: 0\n    infra_retries: 0\n    services:\n      - name: db\n        image: img\n        retries: 0\n    steps:\n      - run: r\n        retry:\n          max: 0\n"
	spec, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	j := spec.Jobs["a"]
	if !j.Retry.MaxSet || j.Retry.Max != 0 {
		t.Fatalf("job retry = %+v, want explicit max 0", j.Retry)
	}
	if !j.InfraRetriesSet || j.InfraRetries != 0 {
		t.Fatalf("infra retries = %d set=%t, want explicit 0", j.InfraRetries, j.InfraRetriesSet)
	}
	if len(j.Services) != 1 || !j.Services[0].RetriesSet || j.Services[0].Retries != 0 {
		t.Fatalf("service retries = %+v, want explicit 0", j.Services)
	}
	if len(j.Steps) != 1 || !j.Steps[0].Retry.MaxSet || j.Steps[0].Retry.Max != 0 {
		t.Fatalf("step retry = %+v, want explicit max 0", j.Steps)
	}

	// Absent fields stay unset (they inherit).
	absent, err := Parse([]byte("version: 1\njobs:\n  a:\n    steps:\n      - run: r\n"))
	if err != nil {
		t.Fatal(err)
	}
	aj := absent.Jobs["a"]
	if aj.Retry.MaxSet || aj.InfraRetriesSet || aj.Steps[0].Retry.MaxSet {
		t.Fatalf("absent retry fields marked set: %+v", aj)
	}
}

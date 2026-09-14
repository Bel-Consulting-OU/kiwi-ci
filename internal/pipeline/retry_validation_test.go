package pipeline

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestValidateRejectsCancelledRetryClass(t *testing.T) {
	for _, on := range []string{"[cancelled]", "[failure, cancelled]"} {
		doc := "version: 1\njobs:\n  x:\n    retry:\n      max: 1\n      on: " + on + "\n    steps:\n      - run: echo hi\n"
		_, err := Parse([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "invalid retry class") || !strings.Contains(err.Error(), "cancelled") {
			t.Errorf("retry.on %s error = %v, want invalid retry class naming cancelled", on, err)
		}
	}
	// The class check is case-insensitive, so an upper-case spelling is
	// still rejected (reporting the author's spelling).
	doc := "version: 1\njobs:\n  x:\n    retry:\n      max: 1\n      on: [CANCELLED]\n    steps:\n      - run: echo hi\n"
	if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "invalid retry class") || !strings.Contains(err.Error(), "CANCELLED") {
		t.Errorf("retry.on [CANCELLED] error = %v, want invalid retry class", err)
	}
}

func TestValidateAcceptsRetryClasses(t *testing.T) {
	doc := `version: 1
jobs:
  x:
    retry:
      max: 1
      on: [failure, infra, timeout, cache, artifact, command, any]
    steps:
      - run: echo hi
`
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatalf("executor retry classes must validate: %v", err)
	}
}

func TestSchemaRetryEnumMatchesValidationAllowlist(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal(SchemaJSON, &root); err != nil {
		t.Fatal(err)
	}
	defs, _ := root["$defs"].(map[string]any)
	retry, _ := defs["retry"].(map[string]any)
	props, _ := retry["properties"].(map[string]any)
	on, _ := props["on"].(map[string]any)
	items, _ := on["items"].(map[string]any)
	enum, _ := items["enum"].([]any)
	got := map[string]bool{}
	for _, e := range enum {
		if s, ok := e.(string); ok {
			got[s] = true
		}
	}
	if !reflect.DeepEqual(got, retryClasses) {
		t.Errorf("schema retry.on enum %v diverges from validation allowlist %v", got, retryClasses)
	}
	if got["cancelled"] {
		t.Error(`schema retry.on enum still admits "cancelled"; the executor never retries cancellations`)
	}
}

package importer

import (
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestSanitizeID(t *testing.T) {
	taken := map[string]bool{}
	cases := map[string]string{
		"build":              "build",
		"Build Docker image": "Build-Docker-image",
		"1-up":               "job-1-up",
		"":                   "job",
		"   spaced  name   ": "spaced-name",
	}
	for in, want := range cases {
		if got := SanitizeID(in, taken); got != want {
			t.Errorf("SanitizeID(%q) = %q, want %q", in, got, want)
		}
	}
	// Collisions get numeric suffixes.
	taken = map[string]bool{}
	if got := SanitizeID("build", taken); got != "build" {
		t.Fatalf("first = %q", got)
	}
	if got := SanitizeID("build", taken); got != "build-2" {
		t.Fatalf("second = %q, want build-2", got)
	}
}

func TestSanitizeIDBoundaryLengths(t *testing.T) {
	for _, tc := range []struct {
		n       int
		wantLen int
	}{
		{0, 3}, {127, 127}, {128, 128}, {129, 128}, {200, 128},
	} {
		got := SanitizeID(strings.Repeat("a", tc.n), map[string]bool{})
		if len(got) != tc.wantLen {
			t.Fatalf("SanitizeID(%d chars) len = %d, want %d (%q)", tc.n, len(got), tc.wantLen, got)
		}
		if !idRegexp.MatchString(got) {
			t.Fatalf("SanitizeID(%d chars) = %q does not match the id grammar", tc.n, got)
		}
	}
	// Collisions at and beyond the truncation boundary keep the final id
	// inside the grammar: the suffix is carved out of the base, never
	// appended past 128 characters.
	for _, n := range []int{124, 126, 127, 128, 129, 200} {
		taken := map[string]bool{}
		ids := make([]string, 0, 3)
		for _, tail := range []string{"-x", "-y", "-z"} {
			ids = append(ids, SanitizeID(strings.Repeat("b", n)+tail, taken))
		}
		for i, id := range ids {
			if len(id) > 128 || !idRegexp.MatchString(id) {
				t.Fatalf("n=%d id[%d] = %q (len %d) violates the grammar", n, i, id, len(id))
			}
			for j := 0; j < i; j++ {
				if id == ids[j] {
					t.Fatalf("n=%d duplicate id %q", n, id)
				}
			}
		}
	}
}

func TestConfidenceScoring(t *testing.T) {
	if c := Confidence(10, 0, 0); c != 1 {
		t.Fatalf("clean import confidence = %v, want 1", c)
	}
	if c := Confidence(10, 1, 0); c <= 0 || c >= 1 {
		t.Fatalf("partial import confidence = %v, want in (0,1)", c)
	}
	// Unsupported weighs double TODOs.
	a := Confidence(10, 1, 0)
	b := Confidence(10, 0, 2)
	if a != b {
		t.Fatalf("unsupported weighting differs from TODO weighting: %v vs %v", a, b)
	}
}

func TestMarshalSpecRoundTripsDurations(t *testing.T) {
	spec := &pipeline.Spec{Version: 1, Name: "roundtrip", Jobs: map[string]pipeline.Job{
		"test": {
			Runtime: "container",
			Image:   "golang:1.23",
			Timeout: pipeline.Duration{Duration: 15 * time.Minute, Set: true},
			Retry:   pipeline.Retry{Max: 2, Backoff: pipeline.Duration{Duration: 5 * time.Second, Set: true}},
			Matrix:  map[string][]any{"GO": {"1.22", "1.23"}},
			Steps:   []pipeline.Step{{Name: "run", Run: "true", Timeout: pipeline.Duration{Duration: time.Minute, Set: true}}},
		},
	}}
	out, err := MarshalSpec(spec)
	if err != nil {
		t.Fatalf("MarshalSpec: %v", err)
	}
	got, err := pipeline.Parse([]byte(out))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, out)
	}
	j := got.Jobs["test"]
	if j.Timeout.Duration != 15*time.Minute || !j.Timeout.Set {
		t.Fatalf("timeout = %v (set=%v)", j.Timeout.Duration, j.Timeout.Set)
	}
	if j.Retry.Backoff.Duration != 5*time.Second {
		t.Fatalf("retry backoff = %v", j.Retry.Backoff.Duration)
	}
	if j.Steps[0].Timeout.Duration != time.Minute {
		t.Fatalf("step timeout = %v", j.Steps[0].Timeout.Duration)
	}
	if strings.Contains(out, "duration:") {
		t.Fatalf("raw duration mapping leaked into output:\n%s", out)
	}
}

package pipeline

import "testing"

func TestArtifactInputsPartition(t *testing.T) {
	in := []ArtifactInput{
		{From: "a", Name: "x", If: ""},
		{From: "a", Name: "y", If: "success()"},
		{From: "a", Name: "z", If: "always()"},
		{From: "a", Name: "w", If: "failure()"},
		{From: "a", Name: "v", If: "cancelled()"},
	}
	setup, fail := ArtifactInputsPartition(in)
	if len(setup) != 3 {
		t.Fatalf("setup = %d (%v)", len(setup), setup)
	}
	if len(fail) != 2 {
		t.Fatalf("fail = %d (%v)", len(fail), fail)
	}
	for _, d := range setup {
		if d.If == "failure()" || d.If == "cancelled()" {
			t.Fatalf("setup contains gated %q", d.If)
		}
	}
}

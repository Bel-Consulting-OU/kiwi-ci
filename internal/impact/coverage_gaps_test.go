package impact

import "testing"

func TestGlobSubsumesBranches(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"src/**", "src/pkg/**", true},
		{"src/**", "src/**", true},
		{"src", "src/**", false},
		{"src", "src/pkg/**", true},
		{"src/**", "src", false},
		{"src/**", "other/**", false},
		{"src/*", "src/pkg/**", false},
	}
	for _, c := range cases {
		if got := globSubsumes(c.a, c.b); got != c.want {
			t.Errorf("globSubsumes(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestPathsOverlapViaSubsumption(t *testing.T) {
	if !pathsOverlap([]string{"src/**"}, []string{"src/pkg/**"}) {
		t.Fatal("prefix glob must subsume a narrower glob")
	}
	if pathsOverlap([]string{"src/**"}, []string{"other/**"}) {
		t.Fatal("unrelated globs must not overlap")
	}
	if pathsOverlap(nil, []string{"src"}) {
		t.Fatal("empty pattern list must not overlap")
	}
}

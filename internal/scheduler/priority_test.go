package scheduler

import (
	"testing"

	"github.com/kiwici/kiwi/internal/model"
	"github.com/kiwici/kiwi/internal/pipeline"
)

func TestDownstreamDepth(t *testing.T) {
	// a -> b -> c -> d, and e -> c (two paths into c); f is isolated.
	g := &pipeline.Graph{Jobs: map[string]pipeline.CompiledJob{
		"a": {ID: "a"},
		"b": {ID: "b", Needs: []string{"a"}},
		"c": {ID: "c", Needs: []string{"b"}},
		"d": {ID: "d", Needs: []string{"c"}},
		"e": {ID: "e", Needs: []string{"c"}},
		"f": {ID: "f"},
	}}
	cases := map[string]int{
		"a": 3, // a unblocks b -> c -> (d|e)
		"b": 2,
		"c": 1,
		"d": 0,
		"e": 0,
		"f": 0,
	}
	for key, want := range cases {
		if got := DownstreamDepth(g, key); got != want {
			t.Errorf("DownstreamDepth(%q) = %d, want %d", key, got, want)
		}
	}
}

func TestCollectNeedsOutputs(t *testing.T) {
	jobs := map[string]model.Job{
		"a": {ID: "a", Key: "build", BaseKey: "build", Outputs: map[string]string{"x": "1"}},
		"b": {ID: "b", Key: "build[os=mac]", BaseKey: "build", Outputs: map[string]string{"x": "2"}},
		"c": {ID: "c", Key: "lint", BaseKey: "lint", Outputs: map[string]string{"y": "3"}},
		"d": {ID: "d", Key: "noop", BaseKey: "noop"},
	}
	j := model.Job{ID: "e", Needs: []string{"a", "b", "c", "d"}}
	got := CollectNeedsOutputs(j, jobs)
	// build expands to two matrix cells: exposed only per job key. lint has
	// a single cell and its key equals its base key: one entry. noop has no
	// outputs: absent entirely.
	if len(got) != 3 {
		t.Fatalf("needs outputs = %d entries, want 3 (build, build[os=mac], lint)", len(got))
	}
	if got["build"]["x"] != "1" {
		t.Errorf("build outputs = %v", got["build"])
	}
	if got["build[os=mac]"]["x"] != "2" {
		t.Errorf("build[os=mac] outputs = %v", got["build[os=mac]"])
	}
	if got["lint"]["y"] != "3" {
		t.Errorf("lint outputs = %v", got["lint"])
	}
	if _, ok := got["noop"]; ok {
		t.Error("dep with no outputs must not appear in needs outputs")
	}
}

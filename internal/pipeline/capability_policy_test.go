package pipeline

import (
	"strings"
	"testing"
)

// Native capability policy for the Woodpecker-doable surface: clone,
// workspace and volumes are first-class Kiwi execution fields (not adapter
// TODOs). These tests pin the admission rules.

func TestValidateCloneWorkspaceVolumes(t *testing.T) {
	base := func() *Spec {
		return &Spec{
			Version: 1,
			Jobs: map[string]Job{
				"build": {
					Steps: []Step{{Run: "true"}},
				},
			},
		}
	}

	t.Run("default clone is valid", func(t *testing.T) {
		if err := Validate(base()); err != nil {
			t.Fatalf("default clone = %v", err)
		}
	})

	t.Run("clone skip/depth/submodules/lfs/sparse accepted", func(t *testing.T) {
		s := base()
		s.Jobs["build"] = Job{
			Clone: Clone{Skip: true, Depth: 1, Submodules: true, LFS: true, SparsePaths: []string{"src", "docs"}},
			Steps: []Step{{Run: "true"}},
		}
		if err := Validate(s); err != nil {
			t.Fatalf("full clone policy = %v", err)
		}
	})

	t.Run("negative depth refused", func(t *testing.T) {
		s := base()
		j := s.Jobs["build"]
		j.Clone.Depth = -1
		s.Jobs["build"] = j
		if err := Validate(s); err == nil || !strings.Contains(err.Error(), "clone.depth") {
			t.Fatalf("negative depth = %v, want clone.depth refusal", err)
		}
	})

	t.Run("depth over ceiling refused", func(t *testing.T) {
		s := base()
		j := s.Jobs["build"]
		j.Clone.Depth = MaxCloneDepth + 1
		s.Jobs["build"] = j
		if err := Validate(s); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("huge depth = %v, want ceiling refusal", err)
		}
	})

	t.Run("sparse path escape refused", func(t *testing.T) {
		s := base()
		j := s.Jobs["build"]
		j.Clone.SparsePaths = []string{"../etc"}
		s.Jobs["build"] = j
		if err := Validate(s); err == nil {
			t.Fatal("sparse .. must be refused")
		}
	})

	t.Run("workspace base and path accepted", func(t *testing.T) {
		s := base()
		s.Jobs["build"] = Job{
			Workspace: Workspace{Base: "repo", Path: "sub/dir"},
			Steps:     []Step{{Run: "true"}},
		}
		if err := Validate(s); err != nil {
			t.Fatalf("workspace = %v", err)
		}
	})

	t.Run("workspace absolute or escape refused", func(t *testing.T) {
		for _, w := range []Workspace{
			{Base: "/etc"},
			{Base: "../outside"},
			{Path: "/abs"},
			{Path: ".."},
		} {
			s := base()
			s.Jobs["build"] = Job{Workspace: w, Steps: []Step{{Run: "true"}}}
			if err := Validate(s); err == nil {
				t.Fatalf("workspace %+v must be refused", w)
			}
		}
	})

	t.Run("named volume accepted", func(t *testing.T) {
		s := base()
		s.Jobs["build"] = Job{
			Volumes: []Volume{{Name: "data", Path: "/data"}, {Name: "cache", Path: "/cache", ReadOnly: true}},
			Steps:   []Step{{Run: "true"}},
		}
		if err := Validate(s); err != nil {
			t.Fatalf("named volumes = %v", err)
		}
	})

	t.Run("host_path volume accepted at pipeline validation", func(t *testing.T) {
		// Trust gating is enqueue/executor policy; pipeline validation only
		// checks shape so a trusted job can declare the capability.
		s := base()
		s.Jobs["build"] = Job{
			Volumes: []Volume{{Name: "host", Path: "/mnt/x", HostPath: "/var/run/x"}},
			Steps:   []Step{{Run: "true"}},
		}
		if err := Validate(s); err != nil {
			t.Fatalf("host_path shape = %v", err)
		}
	})

	t.Run("bad volumes refused", func(t *testing.T) {
		cases := []struct {
			name string
			vol  Volume
		}{
			{"missing name", Volume{Path: "/data"}},
			{"bad name", Volume{Name: "-bad", Path: "/data"}},
			{"duplicate name", Volume{Name: "data", Path: "/data"}},
			{"relative mount", Volume{Name: "data", Path: "data"}},
			{"mount escape", Volume{Name: "data", Path: "/data/../etc"}},
			{"relative host", Volume{Name: "data", Path: "/data", HostPath: "rel"}},
			{"host escape", Volume{Name: "data", Path: "/data", HostPath: "/var/../etc/passwd"}},
		}
		for _, tc := range cases {
			s := base()
			vols := []Volume{tc.vol}
			if tc.name == "duplicate name" {
				vols = []Volume{{Name: "data", Path: "/data"}, tc.vol}
			}
			s.Jobs["build"] = Job{Volumes: vols, Steps: []Step{{Run: "true"}}}
			err := Validate(s)
			if tc.name == "duplicate name" {
				// first volume is well-formed; second is the duplicate
				if err == nil {
					t.Fatalf("%s must be refused", tc.name)
				}
				continue
			}
			if err == nil {
				t.Fatalf("%s must be refused", tc.name)
			}
		}
	})

	t.Run("volume count ceiling", func(t *testing.T) {
		s := base()
		vols := make([]Volume, MaxVolumesPerJob+1)
		for i := range vols {
			vols[i] = Volume{Name: "v" + string(rune('a'+i%26)) + string(rune('0'+i/26)), Path: "/m"}
		}
		s.Jobs["build"] = Job{Volumes: vols, Steps: []Step{{Run: "true"}}}
		if err := Validate(s); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("volume ceiling = %v", err)
		}
	})

	t.Run("sandbox privileged is a valid declaration", func(t *testing.T) {
		s := base()
		s.Jobs["build"] = Job{
			Runtime: "container",
			Image:   "golang:1.23",
			Sandbox: Sandbox{Privileged: true},
			Steps:   []Step{{Run: "true"}},
		}
		if err := Validate(s); err != nil {
			t.Fatalf("privileged declaration = %v", err)
		}
	})
}

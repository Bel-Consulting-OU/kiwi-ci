package executor

import (
	"reflect"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestContainerResourceArgs(t *testing.T) {
	cases := []struct {
		name string
		job  pipeline.Job
		want []string
	}{
		{"zero requests produce no flags", pipeline.Job{}, nil},
		{"cpu only", pipeline.Job{Resources: pipeline.Resources{CPU: 1.5}}, []string{"--cpus", "1.5"}},
		{"memory only", pipeline.Job{Resources: pipeline.Resources{Memory: 512 << 20}}, []string{"--memory", "536870912"}},
		{"pids only", pipeline.Job{Resources: pipeline.Resources{PIDs: 1024}}, []string{"--pids-limit", "1024"}},
		{"all three", pipeline.Job{Resources: pipeline.Resources{CPU: 2, Memory: 1 << 30, PIDs: 4096}}, []string{"--cpus", "2", "--memory", "1073741824", "--pids-limit", "4096"}},
		{"disk request has no docker flag", pipeline.Job{Resources: pipeline.Resources{Disk: 1 << 30}}, nil},
		{"negative/unknown values produce nothing", pipeline.Job{Resources: pipeline.Resources{CPU: -1, Memory: -1, PIDs: -1}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := containerResourceArgs(tc.job)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("containerResourceArgs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTartResourceFlags(t *testing.T) {
	const helpWithFlags = "Usage: tart run [options] <vm>\n  --cpu <number>\n  --memory <MB>\n"
	const helpWithoutFlags = "Usage: tart run [options] <vm>\n"
	cases := []struct {
		name     string
		res      pipeline.Resources
		help     string
		flags    []string
		advisory int
	}{
		{"zero requests", pipeline.Resources{}, helpWithFlags, nil, 0},
		{"cpu and memory honored", pipeline.Resources{CPU: 4, Memory: 2 << 30}, helpWithFlags, []string{"--cpu", "4", "--memory", "2048"}, 0},
		{"unsupported cli flags fall back to advisory", pipeline.Resources{CPU: 4, Memory: 2 << 30}, helpWithoutFlags, nil, 2},
		{"disk is always advisory", pipeline.Resources{Disk: 1 << 30}, helpWithFlags, nil, 1},
		{"cpu only", pipeline.Resources{CPU: 2}, helpWithFlags, []string{"--cpu", "2"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags, advisory := tartResourceFlags(tc.res, tc.help)
			if !reflect.DeepEqual(flags, tc.flags) {
				t.Fatalf("flags = %v, want %v", flags, tc.flags)
			}
			if len(advisory) != tc.advisory {
				t.Fatalf("advisory = %v, want %d lines", advisory, tc.advisory)
			}
		})
	}
}

func TestNativeResourceAdvisory(t *testing.T) {
	cases := []struct {
		name string
		res  pipeline.Resources
		want int
	}{
		{"zero requests", pipeline.Resources{}, 0},
		{"all four requests reported", pipeline.Resources{CPU: 2, Memory: 1 << 30, Disk: 1 << 30, PIDs: 512}, 4},
		{"single request", pipeline.Resources{PIDs: 128}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := nativeResourceAdvisory(tc.res)
			if len(lines) != tc.want {
				t.Fatalf("nativeResourceAdvisory = %v, want %d lines", lines, tc.want)
			}
			for _, l := range lines {
				if len(l) == 0 {
					t.Fatalf("empty advisory line in %v", lines)
				}
			}
		})
	}
}

package dogfood

import "fmt"

// ComponentKind is the closed vocabulary of system-under-test components a
// dogfood topology can include. The harness refuses a topology that names a
// kind it cannot bring up, rather than silently testing a subset.
type ComponentKind string

const (
	ComponentServer      ComponentKind = "server"
	ComponentPostgres    ComponentKind = "postgres"
	ComponentObjectStore ComponentKind = "objectstore"
	ComponentRunner      ComponentKind = "runner"
)

// Component is one instance of a topology component. Name is unique within
// the topology; Labels isolate the instance into the invocation namespace.
type Component struct {
	Kind   ComponentKind `json:"kind"`
	Name   string        `json:"name"`
	Labels []string      `json:"labels,omitempty"`
}

// Topology is the declared shape of the system under test. The topology is
// descriptor data: the harness reads it to decide what to launch and what
// recovery/authority surfaces the oracle may consult. A scenario pins a
// topology so a result says exactly which shape produced it.
type Topology struct {
	Name       string      `json:"name"`
	Components []Component `json:"components"`
}

// Local returns the single-process local topology: one server and one
// runner in the same invocation. This is the DF-BOOT-001 shape: bootstrap
// and restart must work with no external services.
func Local(ns Namespace) Topology {
	return Topology{
		Name: "local",
		Components: []Component{
			{Kind: ComponentServer, Name: "server", Labels: ns.RunnerLabels},
			{Kind: ComponentRunner, Name: "runner-1", Labels: ns.RunnerLabels},
		},
	}
}

// Distributed returns the full distributed topology: server + postgres +
// object store + two runners. This is the shape that exercises lease
// reassignment (two runners), authoritative durable state (postgres), and
// artifact/evidence storage (object store).
func Distributed(ns Namespace) Topology {
	return Topology{
		Name: "distributed",
		Components: []Component{
			{Kind: ComponentServer, Name: "server", Labels: ns.RunnerLabels},
			{Kind: ComponentPostgres, Name: "postgres", Labels: ns.RunnerLabels},
			{Kind: ComponentObjectStore, Name: "objectstore", Labels: ns.RunnerLabels},
			{Kind: ComponentRunner, Name: "runner-1", Labels: ns.RunnerLabels},
			{Kind: ComponentRunner, Name: "runner-2", Labels: ns.RunnerLabels},
		},
	}
}

// Kinds returns the set of component kinds present in the topology.
func (t Topology) Kinds() map[ComponentKind]int {
	out := make(map[ComponentKind]int)
	for _, c := range t.Components {
		out[c.Kind]++
	}
	return out
}

// RunnerNames returns the names of the topology's runner components in
// declaration order. Lease scenarios need the roster to know who the
// "current" runner is after a reassignment.
func (t Topology) RunnerNames() []string {
	var out []string
	for _, c := range t.Components {
		if c.Kind == ComponentRunner {
			out = append(out, c.Name)
		}
	}
	return out
}

// Validate checks the topology is a well-formed shape the harness can
// launch: every component has a name, kinds are known, and the shape is
// internally coherent (a runner-bearing topology has a server; the
// distributed shape has its durable stores).
func (t Topology) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("dogfood: topology has no name")
	}
	seen := make(map[string]bool)
	kinds := t.Kinds()
	for _, c := range t.Components {
		if c.Name == "" {
			return fmt.Errorf("dogfood: topology %s has an unnamed %s component", t.Name, c.Kind)
		}
		if seen[c.Name] {
			return fmt.Errorf("dogfood: topology %s repeats component name %q", t.Name, c.Name)
		}
		seen[c.Name] = true
		switch c.Kind {
		case ComponentServer, ComponentPostgres, ComponentObjectStore, ComponentRunner:
		default:
			return fmt.Errorf("dogfood: topology %s names unknown component kind %q", t.Name, c.Kind)
		}
	}
	if kinds[ComponentRunner] > 0 && kinds[ComponentServer] == 0 {
		return fmt.Errorf("dogfood: topology %s has runners but no server", t.Name)
	}
	if t.Name == "distributed" {
		if kinds[ComponentPostgres] == 0 || kinds[ComponentObjectStore] == 0 || kinds[ComponentRunner] < 2 {
			return fmt.Errorf("dogfood: distributed topology requires postgres, objectstore and at least 2 runners")
		}
	}
	return nil
}

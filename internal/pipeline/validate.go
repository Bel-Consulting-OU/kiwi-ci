package pipeline

import (
	"fmt"
	"sort"
	"strings"
)

func Validate(s *Spec) error {
	if s == nil {
		return fmt.Errorf("nil pipeline")
	}
	for id, j := range s.Jobs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("job id cannot be empty")
		}
		if len(j.Steps) == 0 {
			return fmt.Errorf("job %q has no steps", id)
		}
		for _, dep := range j.Needs {
			if _, ok := s.Jobs[dep]; !ok {
				return fmt.Errorf("job %q needs unknown job %q", id, dep)
			}
			if dep == id {
				return fmt.Errorf("job %q depends on itself", id)
			}
		}
		for i, st := range j.Steps {
			if strings.TrimSpace(st.Run) == "" {
				return fmt.Errorf("job %q step %d has empty run command", id, i+1)
			}
		}
		switch j.Runtime {
		case "", "native", "container", "tart":
		default:
			return fmt.Errorf("job %q has unsupported runtime %q", id, j.Runtime)
		}
	}
	if cyc := findCycle(s.Jobs); len(cyc) > 0 {
		return fmt.Errorf("dependency cycle: %s", strings.Join(cyc, " -> "))
	}
	return nil
}

func findCycle(jobs map[string]Job) []string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	state := map[string]int{}
	stack := []string{}
	var visit func(string) []string
	visit = func(n string) []string {
		state[n] = gray
		stack = append(stack, n)
		for _, d := range jobs[n].Needs {
			if state[d] == gray {
				pos := 0
				for i, v := range stack {
					if v == d {
						pos = i
						break
					}
				}
				return append(append([]string{}, stack[pos:]...), d)
			}
			if state[d] == white {
				if c := visit(d); len(c) > 0 {
					return c
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[n] = black
		return nil
	}
	keys := make([]string, 0, len(jobs))
	for k := range jobs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if state[k] == white {
			if c := visit(k); len(c) > 0 {
				return c
			}
		}
	}
	return nil
}

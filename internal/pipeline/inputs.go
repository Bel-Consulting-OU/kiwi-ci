package pipeline

import (
	"fmt"
	"strconv"
)

// ValidateRunInputs validates the caller-provided input values against the
// spec's declared inputs and returns the effective set: defaults are applied
// for absent optional inputs, required inputs must be present, and typed
// inputs are checked (boolean, integer, enum). Unknown names are rejected so
// a typo can never silently drop a value.
//
// This is the single input contract shared by the control plane's enqueue
// (which extracts values from run metadata) and `kiwi run` (which extracts
// them from --input flags), so local and remote dispatch can never diverge.
func ValidateRunInputs(spec *Spec, provided map[string]string) (map[string]string, error) {
	if spec == nil {
		return nil, fmt.Errorf("nil pipeline")
	}
	for name := range provided {
		if _, ok := spec.Inputs[name]; !ok {
			return nil, fmt.Errorf("unknown input %q", name)
		}
	}
	out := map[string]string{}
	for name, in := range spec.Inputs {
		typ := in.Type
		if typ == "" {
			typ = "string"
		}
		v, has := provided[name]
		if !has {
			if in.Required {
				return nil, fmt.Errorf("required input %q not provided", name)
			}
			if in.Default == nil {
				continue
			}
			v = fmt.Sprint(in.Default)
		}
		switch typ {
		case "", "string":
		case "boolean":
			if v != "true" && v != "false" {
				return nil, fmt.Errorf("input %q must be a boolean, got %q", name, v)
			}
		case "integer":
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return nil, fmt.Errorf("input %q must be an integer, got %q", name, v)
			}
		case "enum":
			found := false
			for _, o := range in.Options {
				if o == v {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("input %q must be one of %v, got %q", name, in.Options, v)
			}
		default:
			return nil, fmt.Errorf("input %q has unknown type %q", name, typ)
		}
		out[name] = v
	}
	return out, nil
}

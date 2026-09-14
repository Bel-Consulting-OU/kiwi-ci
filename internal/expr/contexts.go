// Package expr implements Kiwi's expression and interpolation engine.
//
// Expressions are parsed once into an AST (Parse) and evaluated against a
// Context. Text interpolation (EvalString) replaces every ${{ ... }} hole in
// a string; EvalBool evaluates a single expression as a boolean condition.
//
// The grammar inside a hole is deliberately small and side-effect free:
// function calls, string and number literals, dotted context paths, the
// comparison operators == and !=, the logical operators &&, || and !, and
// parentheses. There are no user-defined functions and no mutation, so
// evaluation is deterministic: the same expression and context always yield
// the same result.
package expr

import (
	"fmt"
	"strings"
)

// Context carries every value an expression may read. All lookups are
// read-only; evaluation never mutates the Context.
//
// Scalar contexts:
//   - status: the job/run status ("success", "failure", ...)
//   - event:  the event name ("push", "pull_request", ...)
//   - branch: the branch being built
//   - ref:    the full git ref ("refs/heads/main")
//   - sha:    the commit SHA
//   - repo:   the repository URL; repo.full_name is the "owner/name" form
//   - git:    git.branch, git.ref, git.sha mirror branch, ref, sha
//
// Map contexts resolve dotted paths as keys joined by ".":
//   - matrix.GO            -> Matrix["GO"]
//   - inputs.flavor        -> Inputs["flavor"]
//   - needs.build.outputs.bin -> Needs["build.outputs.bin"]
//   - steps.build.outputs.x   -> Steps["build.outputs.x"]
//   - runner.os, job.id, env.VAR, kiwi.run_id, extra.anything
//
// A missing key in a map context is an evaluation error (the caller may use
// it to tell "not resolved" apart from "resolved to the empty string").
//
// Workspace is the working directory hashFiles() globs against. hashFiles
// fails at evaluation time when it is empty.
type Context struct {
	Status    string
	Matrix    map[string]string
	Inputs    map[string]string
	Needs     map[string]string
	Steps     map[string]string
	Runner    map[string]string
	Job       map[string]string
	Env       map[string]string
	Event     string
	Branch    string
	Ref       string
	SHA       string
	Repo      string
	RepoFull  string
	Kiwi      map[string]string
	Extra     map[string]string
	Workspace string
}

// scalarContexts are contexts that resolve as a bare identifier. Dotted
// access is only valid for the fixed fields listed in fixedFields.
var scalarContexts = map[string]bool{
	"status": true,
	"event":  true,
	"branch": true,
	"ref":    true,
	"sha":    true,
	"repo":   true,
}

// mapContexts resolve every dotted path as a key in the corresponding map.
// A bare identifier is not allowed for them: they need a field.
var mapContexts = map[string]bool{
	"matrix": true,
	"inputs": true,
	"needs":  true,
	"steps":  true,
	"runner": true,
	"job":    true,
	"env":    true,
	"kiwi":   true,
	"extra":  true,
}

// fixedFields is the whitelist of dotted fields for fixed-shape contexts:
// these contexts expose a small known set of fields and nothing else. The
// key is the context name, the value the allowed single field names.
var fixedFields = map[string]map[string]bool{
	"repo":  {"full_name": true},
	"event": {"name": true},
	"git":   {"branch": true, "ref": true, "sha": true},
}

// validatePath checks a context path at parse time. Unknown contexts and
// unknown fields are compile errors so typos surface before a pipeline runs.
func validatePath(root string, fields []string) error {
	if mapContexts[root] {
		if len(fields) == 0 {
			return fmt.Errorf("context %q requires a field (e.g. %s.<name>)", root, root)
		}
		return nil
	}
	if allowed, ok := fixedFields[root]; ok {
		if len(fields) == 0 {
			if scalarContexts[root] {
				return nil
			}
			return fmt.Errorf("context %q requires a field", root)
		}
		if len(fields) == 1 && allowed[fields[0]] {
			return nil
		}
		return fmt.Errorf("context %q has no field %q", root, strings.Join(fields, "."))
	}
	if scalarContexts[root] {
		if len(fields) == 0 {
			return nil
		}
		return fmt.Errorf("context %q has no field %q", root, strings.Join(fields, "."))
	}
	return fmt.Errorf("unknown context %q", root)
}

// lookup resolves a validated path against the context. It returns an error
// when a map key is absent; scalar contexts simply return their value, which
// may be empty.
func lookup(c Context, root string, fields []string) (string, error) {
	if len(fields) == 0 {
		switch root {
		case "status":
			return c.Status, nil
		case "event":
			return c.Event, nil
		case "branch":
			return c.Branch, nil
		case "ref":
			return c.Ref, nil
		case "sha":
			return c.SHA, nil
		case "repo":
			return c.Repo, nil
		}
	}
	switch root {
	case "repo":
		if len(fields) == 1 && fields[0] == "full_name" {
			return c.RepoFull, nil
		}
	case "event":
		if len(fields) == 1 && fields[0] == "name" {
			return c.Event, nil
		}
	case "git":
		switch fields[0] {
		case "branch":
			return c.Branch, nil
		case "ref":
			return c.Ref, nil
		case "sha":
			return c.SHA, nil
		}
	case "matrix":
		return mapLookup(c.Matrix, root, fields)
	case "inputs":
		return mapLookup(c.Inputs, root, fields)
	case "needs":
		return mapLookup(c.Needs, root, fields)
	case "steps":
		return mapLookup(c.Steps, root, fields)
	case "runner":
		return mapLookup(c.Runner, root, fields)
	case "job":
		return mapLookup(c.Job, root, fields)
	case "env":
		return mapLookup(c.Env, root, fields)
	case "kiwi":
		return mapLookup(c.Kiwi, root, fields)
	case "extra":
		return mapLookup(c.Extra, root, fields)
	}
	return "", fmt.Errorf("unknown context %q", root)
}

func mapLookup(m map[string]string, root string, fields []string) (string, error) {
	key := strings.Join(fields, ".")
	if v, ok := m[key]; ok {
		return v, nil
	}
	return "", fmt.Errorf("key %q not found in context %q", key, root)
}

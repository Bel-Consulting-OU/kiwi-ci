package pipeline

import (
	"fmt"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

type EvalContext struct {
	Status model.Status
	Env    map[string]string
	Event  string
	Branch string
}

func Eval(expr string, c EvalContext) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "true" {
		return true, nil
	}
	if expr == "false" {
		return false, nil
	}
	for hasOuterParens(expr) {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	if parts := splitLogical(expr, "||"); len(parts) > 1 {
		for _, p := range parts {
			ok, err := Eval(p, c)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	if parts := splitLogical(expr, "&&"); len(parts) > 1 {
		for _, p := range parts {
			ok, err := Eval(p, c)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	}
	if strings.HasPrefix(expr, "!") {
		ok, err := Eval(strings.TrimSpace(strings.TrimPrefix(expr, "!")), c)
		return !ok, err
	}
	switch expr {
	case "success()":
		return c.Status != model.StatusFailure && c.Status != model.StatusCancelled && c.Status != model.StatusBlocked, nil
	case "always()":
		return true, nil
	case "failure()":
		return c.Status == model.StatusFailure || c.Status == model.StatusBlocked, nil
	case "cancelled()":
		return c.Status == model.StatusCancelled, nil
	}
	if left, op, right, ok := comparison(expr); ok {
		actual, err := resolveConditionValue(left, c)
		if err != nil {
			return false, err
		}
		expected := trimLiteral(right)
		if op == "==" {
			return actual == expected, nil
		}
		return actual != expected, nil
	}
	return false, fmt.Errorf("unsupported condition %q", expr)
}

func comparison(expr string) (left, op, right string, ok bool) {
	for _, candidate := range []string{"!=", "=="} {
		if i := indexTopLevel(expr, candidate); i >= 0 {
			return strings.TrimSpace(expr[:i]), candidate, strings.TrimSpace(expr[i+len(candidate):]), true
		}
	}
	return "", "", "", false
}

func resolveConditionValue(v string, c EvalContext) (string, error) {
	v = strings.TrimSpace(v)
	switch v {
	case "event":
		return c.Event, nil
	case "branch":
		return c.Branch, nil
	case "status":
		return string(c.Status), nil
	}
	if strings.HasPrefix(v, "env.") {
		return c.Env[strings.TrimPrefix(v, "env.")], nil
	}
	if isQuoted(v) {
		return trimLiteral(v), nil
	}
	return "", fmt.Errorf("unsupported condition value %q", v)
}

func trimLiteral(v string) string {
	v = strings.TrimSpace(v)
	if isQuoted(v) {
		return v[1 : len(v)-1]
	}
	return v
}
func isQuoted(v string) bool {
	return len(v) >= 2 && ((v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '"' && v[len(v)-1] == '"'))
}

func splitLogical(s, op string) []string {
	var out []string
	start := 0
	for {
		i := indexTopLevelFrom(s, op, start)
		if i < 0 {
			break
		}
		out = append(out, strings.TrimSpace(s[start:i]))
		start = i + len(op)
	}
	if len(out) == 0 {
		return []string{s}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}
func indexTopLevel(s, needle string) int { return indexTopLevelFrom(s, needle, 0) }
func indexTopLevelFrom(s, needle string, from int) int {
	depth := 0
	var quote byte
	escaped := false
	for i := 0; i+len(needle) <= len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if quote != 0 {
			if quote == '"' && ch == '\\' {
				escaped = true
			} else if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if i >= from && depth == 0 && strings.HasPrefix(s[i:], needle) {
			return i
		}
	}
	return -1
}
func hasOuterParens(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return false
	}
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 && i != len(s)-1 {
				return false
			}
		}
	}
	return depth == 0
}

// ConditionAllows reports whether a job whose dependencies reached the given
// status may run. This is the single unified gate used by the control plane,
// the SQL scheduler, and the executor (audit item 7). An empty condition
// behaves like success(): a job without an explicit condition is blocked when
// a dependency failed, matching GitHub Actions semantics and Kiwi's DAG
// guarantees. Evaluation errors yield false.
func ConditionAllows(expr string, status model.Status) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		expr = "success()"
	}
	ok, err := Eval(expr, EvalContext{Status: status})
	return err == nil && ok
}

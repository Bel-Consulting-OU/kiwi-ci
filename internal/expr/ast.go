package expr

import "sort"

// Expr is a parsed expression. Expressions are immutable and safe to
// evaluate repeatedly against different contexts.
type Expr interface {
	// String returns the expression source as parsed (without the ${{ }}).
	String() string
	// Eval evaluates the expression to a string. Boolean expressions
	// (comparisons and logical combinations) yield "true" or "false".
	Eval(c Context) (string, error)
	// EvalBool evaluates the expression as a boolean condition. Non-boolean
	// values are interpreted with GitHub Actions truthiness: "true" is true,
	// "false" and "" are false, anything else is an evaluation error.
	EvalBool(c Context) (bool, error)
	// Contexts returns the context roots the expression reads (deduplicated,
	// sorted). Callers that only resolve some contexts use this to leave
	// holes referencing other contexts untouched.
	Contexts() []string
}

// base holds the source of an expression node.
type base struct {
	src string
}

func (b base) String() string { return b.src }

// literal is a quoted string literal.
type literal struct {
	base
	val string
}

func (n *literal) Eval(Context) (string, error) { return n.val, nil }

func (n *literal) EvalBool(Context) (bool, error) {
	return truthy(n.val)
}

func (n *literal) Contexts() []string { return nil }

// number is a numeric literal. Numbers compare as their canonical source
// text, so 1.0 and 1.00 are distinct strings (comparison is string-based,
// matching GitHub Actions expression semantics).
type number struct {
	base
	val string
}

func (n *number) Eval(Context) (string, error) { return n.val, nil }

func (n *number) EvalBool(Context) (bool, error) {
	return truthy(n.val)
}

func (n *number) Contexts() []string { return nil }

// path is a context reference: a root context name plus dotted fields.
type path struct {
	base
	root   string
	fields []string
}

func (n *path) Eval(c Context) (string, error) {
	return lookup(c, n.root, n.fields)
}

func (n *path) EvalBool(c Context) (bool, error) {
	v, err := lookup(c, n.root, n.fields)
	if err != nil {
		return false, err
	}
	return truthy(v)
}

func (n *path) Contexts() []string { return []string{n.root} }

// call is a builtin function invocation.
type call struct {
	base
	name string
	args []Expr
}

func (n *call) Contexts() []string { return contextUnion(n.args) }

// contextUnion collects the context roots referenced by any of the given
// expressions, deduplicated and sorted.
func contextUnion(exprs []Expr) []string {
	set := map[string]bool{}
	for _, e := range exprs {
		for _, r := range e.Contexts() {
			set[r] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// not negates a boolean expression.
type not struct {
	base
	inner Expr
}

func (n *not) Eval(c Context) (string, error) {
	v, err := n.inner.EvalBool(c)
	if err != nil {
		return "", err
	}
	return boolString(v), nil
}

func (n *not) EvalBool(c Context) (bool, error) {
	v, err := n.inner.EvalBool(c)
	if err != nil {
		return false, err
	}
	return !v, nil
}

func (n *not) Contexts() []string { return n.inner.Contexts() }

// cmp compares two values with == or !=.
type cmp struct {
	base
	op          string
	left, right Expr
}

func (n *cmp) Contexts() []string { return contextUnion([]Expr{n.left, n.right}) }

func (n *cmp) Eval(c Context) (string, error) {
	if isBool(n.left) || isBool(n.right) {
		v, err := n.EvalBool(c)
		if err != nil {
			return "", err
		}
		return boolString(v), nil
	}
	l, err := n.left.Eval(c)
	if err != nil {
		return "", err
	}
	r, err := n.right.Eval(c)
	if err != nil {
		return "", err
	}
	if n.op == "==" {
		return boolString(l == r), nil
	}
	return boolString(l != r), nil
}

func (n *cmp) EvalBool(c Context) (bool, error) {
	// When either operand is a boolean-valued expression the comparison is
	// boolean: the other side is coerced with truthiness. Otherwise values
	// compare as strings.
	if isBool(n.left) || isBool(n.right) {
		l, err := boolValue(n.left, c)
		if err != nil {
			return false, err
		}
		r, err := boolValue(n.right, c)
		if err != nil {
			return false, err
		}
		if n.op == "==" {
			return l == r, nil
		}
		return l != r, nil
	}
	l, err := n.left.Eval(c)
	if err != nil {
		return false, err
	}
	r, err := n.right.Eval(c)
	if err != nil {
		return false, err
	}
	if n.op == "==" {
		return l == r, nil
	}
	return l != r, nil
}

// isBool reports whether an expression yields a boolean value natively
// (comparisons, logical combinations and the boolean builtins).
func isBool(e Expr) bool {
	switch v := e.(type) {
	case *cmp, *and, *or, *not:
		return true
	case *call:
		switch v.name {
		case "success", "failure", "cancelled", "always", "contains", "startsWith", "endsWith":
			return true
		}
	}
	return false
}

// boolValue evaluates a node as a boolean: natively for boolean-valued
// nodes, via truthiness for everything else.
func boolValue(e Expr, c Context) (bool, error) {
	if isBool(e) {
		return e.EvalBool(c)
	}
	v, err := e.Eval(c)
	if err != nil {
		return false, err
	}
	return truthy(v)
}

// and and or combine boolean expressions with short-circuit evaluation.
type and struct {
	base
	left, right Expr
}

func (n *and) Contexts() []string { return contextUnion([]Expr{n.left, n.right}) }

func (n *and) Eval(c Context) (string, error) {
	v, err := n.EvalBool(c)
	if err != nil {
		return "", err
	}
	return boolString(v), nil
}

func (n *and) EvalBool(c Context) (bool, error) {
	l, err := n.left.EvalBool(c)
	if err != nil {
		return false, err
	}
	if !l {
		return false, nil
	}
	return n.right.EvalBool(c)
}

type or struct {
	base
	left, right Expr
}

func (n *or) Contexts() []string { return contextUnion([]Expr{n.left, n.right}) }

func (n *or) Eval(c Context) (string, error) {
	v, err := n.EvalBool(c)
	if err != nil {
		return "", err
	}
	return boolString(v), nil
}

func (n *or) EvalBool(c Context) (bool, error) {
	l, err := n.left.EvalBool(c)
	if err != nil {
		return false, err
	}
	if l {
		return true, nil
	}
	return n.right.EvalBool(c)
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// truthy maps a string value to a boolean using GitHub Actions truthiness.
func truthy(v string) (bool, error) {
	switch v {
	case "true":
		return true, nil
	case "false", "":
		return false, nil
	}
	return false, &ValueError{Value: v}
}

// ValueError reports a string that cannot be interpreted as a boolean.
type ValueError struct {
	Value string
}

func (e *ValueError) Error() string {
	return "cannot interpret " + strconvQuote(e.Value) + " as a boolean"
}

func strconvQuote(s string) string {
	return `"` + s + `"`
}

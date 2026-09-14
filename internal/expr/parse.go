package expr

import (
	"fmt"
	"strings"
)

// Hard limits protecting the parser and evaluator from pathological input.
const (
	// maxDepth bounds expression nesting (parentheses and nested calls).
	maxDepth = 64
	// maxTokens bounds the number of lexical tokens in one expression.
	maxTokens = 4096
	// maxExprBytes bounds the byte length of one expression (one hole body).
	maxExprBytes = 64 * 1024
)

// Parse parses one expression (the body of a ${{ ... }} hole, without the
// braces) into an AST. Unknown contexts, unknown fields, unknown functions
// and arity violations are compile errors. Parse validates the hard limits:
// length, token count and nesting depth.
func Parse(s string) (Expr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty expression")
	}
	if len(s) > maxExprBytes {
		return nil, fmt.Errorf("expression exceeds %d byte limit", maxExprBytes)
	}
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	e, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected token %s", p.peek())
	}
	return e, nil
}

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokNumber
	tokString
	tokLParen
	tokRParen
	tokComma
	tokDot
	tokAnd
	tokOr
	tokNot
	tokEq
	tokNeq
)

type token struct {
	kind tokKind
	text string
}

func (t token) String() string {
	if t.kind == tokEOF {
		return "end of expression"
	}
	if t.text != "" {
		return fmt.Sprintf("%q", t.text)
	}
	switch t.kind {
	case tokLParen:
		return "'('"
	case tokRParen:
		return "')'"
	case tokComma:
		return "','"
	case tokDot:
		return "'.'"
	case tokAnd:
		return "'&&'"
	case tokOr:
		return "'||'"
	case tokNot:
		return "'!'"
	case tokEq:
		return "'=='"
	case tokNeq:
		return "'!='"
	}
	return "token"
}

func lex(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{kind: tokLParen, text: "("})
			i++
		case c == ')':
			toks = append(toks, token{kind: tokRParen, text: ")"})
			i++
		case c == ',':
			toks = append(toks, token{kind: tokComma, text: ","})
			i++
		case c == '.':
			toks = append(toks, token{kind: tokDot, text: "."})
			i++
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			toks = append(toks, token{kind: tokAnd, text: "&&"})
			i += 2
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			toks = append(toks, token{kind: tokOr, text: "||"})
			i += 2
		case c == '=' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{kind: tokEq, text: "=="})
			i += 2
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{kind: tokNeq, text: "!="})
			i += 2
		case c == '!':
			toks = append(toks, token{kind: tokNot, text: "!"})
			i++
		case c == '\'' || c == '"':
			val, next, err := lexString(s, i, c)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tokString, text: val})
			i = next
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j < len(s) && s[j] == '.' {
				j++
				for j < len(s) && s[j] >= '0' && s[j] <= '9' {
					j++
				}
			}
			toks = append(toks, token{kind: tokNumber, text: s[i:j]})
			i = j
		case c == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j < len(s) && s[j] == '.' {
				j++
				for j < len(s) && s[j] >= '0' && s[j] <= '9' {
					j++
				}
			}
			toks = append(toks, token{kind: tokNumber, text: s[i:j]})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			toks = append(toks, token{kind: tokIdent, text: s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q", string(c))
		}
		if len(toks) > maxTokens {
			return nil, fmt.Errorf("expression exceeds %d token limit", maxTokens)
		}
	}
	toks = append(toks, token{kind: tokEOF})
	return toks, nil
}

func lexString(s string, start int, quote byte) (string, int, error) {
	var b strings.Builder
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		if c == quote {
			return b.String(), i + 1, nil
		}
		if c == '\\' {
			if i+1 >= len(s) {
				return "", 0, fmt.Errorf("unterminated string literal")
			}
			next := s[i+1]
			switch next {
			case '\\', '\'', '"':
				b.WriteByte(next)
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				return "", 0, fmt.Errorf("invalid escape sequence \\%c", next)
			}
			i++
			continue
		}
		b.WriteByte(c)
	}
	return "", 0, fmt.Errorf("unterminated string literal")
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '-'
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token {
	t := p.toks[p.pos]
	p.pos++
	return t
}

func (p *parser) parseOr(depth int) (Expr, error) {
	left, err := p.parseAnd(depth)
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokOr {
		p.next()
		right, err := p.parseAnd(depth)
		if err != nil {
			return nil, err
		}
		left = &or{base: base{src: left.String() + " || " + right.String()}, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd(depth int) (Expr, error) {
	left, err := p.parseUnary(depth)
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokAnd {
		p.next()
		right, err := p.parseUnary(depth)
		if err != nil {
			return nil, err
		}
		left = &and{base: base{src: left.String() + " && " + right.String()}, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary(depth int) (Expr, error) {
	if p.peek().kind == tokNot {
		p.next()
		inner, err := p.parseUnary(depth)
		if err != nil {
			return nil, err
		}
		return &not{base: base{src: "!" + inner.String()}, inner: inner}, nil
	}
	return p.parseComparison(depth)
}

func (p *parser) parseComparison(depth int) (Expr, error) {
	left, err := p.parsePrimary(depth)
	if err != nil {
		return nil, err
	}
	switch p.peek().kind {
	case tokEq, tokNeq:
		op := p.next()
		right, err := p.parsePrimary(depth)
		if err != nil {
			return nil, err
		}
		return &cmp{
			base:  base{src: left.String() + " " + op.text + " " + right.String()},
			op:    op.text,
			left:  left,
			right: right,
		}, nil
	}
	return left, nil
}

func (p *parser) parsePrimary(depth int) (Expr, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("expression exceeds maximum depth %d", maxDepth)
	}
	t := p.peek()
	switch t.kind {
	case tokNumber:
		p.next()
		return &number{base: base{src: t.text}, val: t.text}, nil
	case tokString:
		p.next()
		return &literal{base: base{src: t.text}, val: t.text}, nil
	case tokLParen:
		p.next()
		inner, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("missing closing ')'")
		}
		p.next()
		return inner, nil
	case tokIdent:
		return p.parseIdent(depth)
	case tokEOF:
		return nil, fmt.Errorf("unexpected end of expression")
	}
	return nil, fmt.Errorf("unexpected token %s", t)
}

// parseIdent parses either a function call (ident followed by '('), the
// boolean literals true/false, or a dotted context path
// (ident ('.' identOrNumber)*).
func (p *parser) parseIdent(depth int) (Expr, error) {
	root := p.next().text
	if p.peek().kind == tokLParen {
		return p.parseCall(root, depth)
	}
	if p.peek().kind != tokDot {
		if root == "true" || root == "false" {
			return &literal{base: base{src: root}, val: root}, nil
		}
	}
	fields := []string{}
	src := root
	for p.peek().kind == tokDot {
		p.next()
		seg := p.peek()
		switch seg.kind {
		case tokIdent, tokNumber:
			p.next()
		default:
			return nil, fmt.Errorf("expected field name after '.', got %s", seg)
		}
		fields = append(fields, seg.text)
		src += "." + seg.text
	}
	if err := validatePath(root, fields); err != nil {
		return nil, err
	}
	return &path{base: base{src: src}, root: root, fields: fields}, nil
}

// parseCall parses a builtin function invocation and validates the function
// name and arity at compile time.
func (p *parser) parseCall(name string, depth int) (Expr, error) {
	p.next() // consume '('
	args := []Expr{}
	if p.peek().kind != tokRParen {
		for {
			arg, err := p.parseOr(depth + 1)
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
			if p.peek().kind != tokComma {
				break
			}
			p.next()
		}
	}
	if p.peek().kind != tokRParen {
		return nil, fmt.Errorf("missing closing ')' in %s()", name)
	}
	p.next()
	if err := validateCall(name, len(args)); err != nil {
		return nil, err
	}
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, a.String())
	}
	src := name + "(" + strings.Join(parts, ", ") + ")"
	return &call{base: base{src: src}, name: name, args: args}, nil
}

var builtinArities = map[string][]int{
	"success":    {0},
	"failure":    {0},
	"cancelled":  {0},
	"always":     {0},
	"contains":   {2},
	"startsWith": {2},
	"endsWith":   {2},
	"fromJSON":   {1},
	"toJSON":     {1},
	"hashFiles":  {1, 2, 3, 4, 5, 6, 7, 8},
}

func validateCall(name string, nargs int) error {
	arities, ok := builtinArities[name]
	if !ok {
		return fmt.Errorf("unknown function %q", name)
	}
	for _, a := range arities {
		if nargs == a {
			return nil
		}
	}
	return fmt.Errorf("function %q expects %s, got %d argument(s)", name, arityString(arities), nargs)
}

func arityString(arities []int) string {
	if len(arities) == 1 {
		return fmt.Sprintf("%d", arities[0])
	}
	parts := make([]string, len(arities)-1)
	for i, a := range arities[:len(arities)-1] {
		parts[i] = fmt.Sprintf("%d", a)
	}
	return strings.Join(parts, ", ") + " or " + fmt.Sprintf("%d", arities[len(arities)-1])
}

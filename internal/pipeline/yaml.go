package pipeline

// This file intentionally implements the small, predictable YAML subset Kiwi
// needs for pipeline files. Keeping the bootstrap parser in-tree means the Kiwi
// binary has zero runtime or module dependencies. It supports indentation maps,
// sequences, inline arrays/maps, quoted and plain scalars, comments, and |/> block
// strings. It deliberately rejects aliases, tags, merge keys and other YAML features
// that are a frequent source of surprising CI configuration behavior.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type yamlLine struct {
	indent int
	text   string
	raw    string
	line   int
}

func parseYAML(data []byte, out any) error {
	lines, err := lexYAML(string(data))
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("empty pipeline")
	}
	v, next, err := parseYAMLBlock(lines, 0, lines[0].indent)
	if err != nil {
		return err
	}
	if next != len(lines) {
		return fmt.Errorf("yaml: unexpected content near line %d", lines[next].line)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode pipeline: %w", err)
	}
	return nil
}

func lexYAML(s string) ([]yamlLine, error) {
	rawLines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	out := make([]yamlLine, 0, len(rawLines))
	for i, raw := range rawLines {
		if strings.ContainsRune(raw, '\t') {
			return nil, fmt.Errorf("yaml line %d: tabs are not allowed for indentation", i+1)
		}
		trimRight := strings.TrimRightFunc(raw, unicode.IsSpace)
		if strings.TrimSpace(trimRight) == "" {
			continue
		}
		indent := len(trimRight) - len(strings.TrimLeft(trimRight, " "))
		text := stripYAMLComment(strings.TrimLeft(trimRight, " "))
		if strings.TrimSpace(text) == "" {
			continue
		}
		out = append(out, yamlLine{indent: indent, text: strings.TrimSpace(text), raw: trimRight, line: i + 1})
	}
	return out, nil
}

func stripYAMLComment(s string) string {
	var quote rune
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if r == '\'' || r == '"' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			}
			continue
		}
		if r == '#' && quote == 0 && (i == 0 || unicode.IsSpace(rune(s[i-1]))) {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func parseYAMLBlock(lines []yamlLine, i, indent int) (any, int, error) {
	if i >= len(lines) {
		return nil, i, nil
	}
	if lines[i].indent != indent {
		return nil, i, fmt.Errorf("yaml line %d: unexpected indentation", lines[i].line)
	}
	if strings.HasPrefix(lines[i].text, "- ") || lines[i].text == "-" {
		return parseYAMLSeq(lines, i, indent)
	}
	return parseYAMLMap(lines, i, indent)
}

func parseYAMLMap(lines []yamlLine, i, indent int) (any, int, error) {
	m := map[string]any{}
	for i < len(lines) {
		ln := lines[i]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, i, fmt.Errorf("yaml line %d: unexpected indentation", ln.line)
		}
		if strings.HasPrefix(ln.text, "- ") || ln.text == "-" {
			break
		}
		key, rest, ok := splitYAMLKey(ln.text)
		if !ok {
			return nil, i, fmt.Errorf("yaml line %d: expected key: value", ln.line)
		}
		if _, exists := m[key]; exists {
			return nil, i, fmt.Errorf("yaml line %d: duplicate key %q", ln.line, key)
		}
		i++
		if rest == "|" || rest == ">" {
			v, ni := parseBlockString(lines, i, indent, rest == ">")
			m[key] = v
			i = ni
			continue
		}
		if rest != "" {
			v, err := parseYAMLScalar(rest)
			if err != nil {
				return nil, i, fmt.Errorf("yaml line %d: %w", ln.line, err)
			}
			m[key] = v
			continue
		}
		if i < len(lines) && lines[i].indent > indent {
			childIndent := lines[i].indent
			v, ni, err := parseYAMLBlock(lines, i, childIndent)
			if err != nil {
				return nil, i, err
			}
			m[key] = v
			i = ni
		} else {
			m[key] = nil
		}
	}
	return m, i, nil
}

func parseYAMLSeq(lines []yamlLine, i, indent int) (any, int, error) {
	var a []any
	for i < len(lines) {
		ln := lines[i]
		if ln.indent < indent {
			break
		}
		if ln.indent != indent || !(strings.HasPrefix(ln.text, "- ") || ln.text == "-") {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(ln.text, "-"))
		i++
		if rest == "" {
			if i >= len(lines) || lines[i].indent <= indent {
				a = append(a, nil)
				continue
			}
			v, ni, err := parseYAMLBlock(lines, i, lines[i].indent)
			if err != nil {
				return nil, i, err
			}
			a = append(a, v)
			i = ni
			continue
		}
		if key, first, ok := splitYAMLKey(rest); ok {
			item := map[string]any{}
			if first == "|" || first == ">" {
				v, ni := parseBlockString(lines, i, indent, first == ">")
				item[key] = v
				i = ni
			} else if first != "" {
				v, err := parseYAMLScalar(first)
				if err != nil {
					return nil, i, fmt.Errorf("yaml line %d: %w", ln.line, err)
				}
				item[key] = v
			} else if i < len(lines) && lines[i].indent > indent {
				v, ni, err := parseYAMLBlock(lines, i, lines[i].indent)
				if err != nil {
					return nil, i, err
				}
				item[key] = v
				i = ni
			} else {
				item[key] = nil
			}
			// Consume sibling mapping keys belonging to this list item.
			if i < len(lines) && lines[i].indent > indent && !(strings.HasPrefix(lines[i].text, "- ") || lines[i].text == "-") {
				childIndent := lines[i].indent
				v, ni, err := parseYAMLMap(lines, i, childIndent)
				if err != nil {
					return nil, i, err
				}
				for k, vv := range v.(map[string]any) {
					if _, dup := item[k]; dup {
						return nil, i, fmt.Errorf("yaml line %d: duplicate key %q", lines[i].line, k)
					}
					item[k] = vv
				}
				i = ni
			}
			a = append(a, item)
			continue
		}
		v, err := parseYAMLScalar(rest)
		if err != nil {
			return nil, i, fmt.Errorf("yaml line %d: %w", ln.line, err)
		}
		a = append(a, v)
	}
	return a, i, nil
}

func parseBlockString(lines []yamlLine, i, parentIndent int, folded bool) (string, int) {
	if i >= len(lines) || lines[i].indent <= parentIndent {
		return "", i
	}
	base := lines[i].indent
	var parts []string
	for i < len(lines) && lines[i].indent > parentIndent {
		ln := lines[i]
		text := ln.raw
		if len(text) >= base {
			text = text[base:]
		}
		parts = append(parts, text)
		i++
	}
	sep := "\n"
	if folded {
		sep = " "
	}
	return strings.Join(parts, sep) + "\n", i
}

func splitYAMLKey(s string) (string, string, bool) {
	var quote rune
	depth := 0
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if r == '\'' || r == '"' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			}
			continue
		}
		if quote != 0 {
			continue
		}
		switch r {
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		case ':':
			if depth == 0 {
				key := strings.TrimSpace(s[:i])
				if key == "" {
					return "", "", false
				}
				if (strings.HasPrefix(key, "\"") && strings.HasSuffix(key, "\"")) || (strings.HasPrefix(key, "'") && strings.HasSuffix(key, "'")) {
					if v, err := parseYAMLScalar(key); err == nil {
						key = fmt.Sprint(v)
					}
				}
				return key, strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

func parseYAMLScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("unterminated inline array")
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		parts, err := splitYAMLInline(inner)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			v, err := parseYAMLScalar(p)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	if strings.HasPrefix(s, "{") {
		if !strings.HasSuffix(s, "}") {
			return nil, fmt.Errorf("unterminated inline map")
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		m := map[string]any{}
		if inner == "" {
			return m, nil
		}
		parts, err := splitYAMLInline(inner)
		if err != nil {
			return nil, err
		}
		for _, p := range parts {
			k, v, ok := splitYAMLKey(p)
			if !ok {
				return nil, fmt.Errorf("invalid inline map item %q", p)
			}
			vv, err := parseYAMLScalar(v)
			if err != nil {
				return nil, err
			}
			m[k] = vv
		}
		return m, nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var v string
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return nil, err
		}
		return v, nil
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	switch strings.ToLower(s) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null", "~":
		return nil, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && strings.ContainsAny(s, ".eE") {
		return f, nil
	}
	return s, nil
}

func splitYAMLInline(s string) ([]string, error) {
	var out []string
	var quote rune
	depth := 0
	start := 0
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if r == '\'' || r == '"' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			}
			continue
		}
		if quote != 0 {
			continue
		}
		switch r {
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if quote != 0 || depth != 0 {
		return nil, fmt.Errorf("malformed inline value")
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out, nil
}

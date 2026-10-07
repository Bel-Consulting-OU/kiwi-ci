package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

// Load reads a kiwi.toml file and returns a Config carrying defaults for
// every field the file does not mention. Parsing supports the TOML subset
// the schema needs: [section] headers, key = value assignments with
// string/int/float/bool scalars, and # comments. Unknown sections, unknown
// keys, duplicate keys and malformed values are all rejected so typos
// surface at startup instead of silently configuring nothing.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := cfg.applyTOML(data, path); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyTOML decodes data into the receiver. The schema is derived from the
// toml tags on Config and its section structs, so new fields are picked up
// automatically and stay strict.
func (c *Config) applyTOML(data []byte, path string) error {
	root := reflect.ValueOf(c).Elem()
	seen := map[string]map[string]bool{}
	var cur reflect.Value
	var curName string

	for i, raw := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		stripped, serr := stripComment(raw)
		if serr != nil {
			return fmt.Errorf("%s:%d: %v", path, lineNo, serr)
		}
		line := strings.TrimSpace(stripped)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return fmt.Errorf("%s:%d: malformed section header", path, lineNo)
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" || strings.ContainsAny(name, "[] \t.\"") {
				return fmt.Errorf("%s:%d: invalid section name %q", path, lineNo, name)
			}
			field := fieldByTag(root, name)
			if !field.IsValid() {
				return fmt.Errorf("%s:%d: unknown section [%s]", path, lineNo, name)
			}
			cur, curName = field, name
			if seen[curName] == nil {
				seen[curName] = map[string]bool{}
			}
			continue
		}
		if !cur.IsValid() {
			return fmt.Errorf("%s:%d: key %q outside any section", path, lineNo, line)
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return fmt.Errorf("%s:%d: expected key = value, got %q", path, lineNo, line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" || val == "" {
			return fmt.Errorf("%s:%d: empty key or value", path, lineNo)
		}
		if seen[curName][key] {
			return fmt.Errorf("%s:%d: duplicate key %q in section [%s]", path, lineNo, key, curName)
		}
		field := fieldByTag(cur, key)
		if !field.IsValid() {
			return fmt.Errorf("%s:%d: unknown key %q in section [%s]", path, lineNo, key, curName)
		}
		scalar, err := parseScalar(val)
		if err != nil {
			return fmt.Errorf("%s:%d: %s: %v", path, lineNo, key, err)
		}
		if err := assign(field, scalar); err != nil {
			return fmt.Errorf("%s:%d: [%s] %s: %v", path, lineNo, curName, key, err)
		}
		seen[curName][key] = true
	}
	return nil
}

// fieldByTag finds the field of the struct value v whose toml tag equals
// name. Returns the zero Value when absent.
func fieldByTag(v reflect.Value, name string) reflect.Value {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get("toml") == name {
			return v.Field(i)
		}
	}
	return reflect.Value{}
}

// stripComment removes a # comment outside of quoted strings. It is
// escape-aware: inside a basic ("...") string a backslash escapes the next
// character, so \" does not toggle the in-string state (and \\ before "
// keeps the quote opening the string), while '#' stays a literal inside
// any quoted string. An unterminated quote at end of line is an error: the
// old behavior accepted `key = "unterminated # x` and swallowed the rest of
// the line, silently truncating the value.
func stripComment(s string) (string, error) {
	var quote byte
	for i := 0; i < len(s); i++ {
		if quote == '"' && s[i] == '\\' && i+1 < len(s) {
			// Inside a basic string, a backslash escapes the next
			// character: an escaped quote must not toggle the string
			// state.
			i++
			continue
		}
		switch s[i] {
		case '"', '\'':
			if quote == 0 {
				quote = s[i]
			} else if quote == s[i] {
				quote = 0
			}
		case '#':
			if quote == 0 {
				return s[:i], nil
			}
		}
	}
	if quote != 0 {
		return "", fmt.Errorf("unterminated quoted string")
	}
	return s, nil
}

// basicStringClose returns the index of the closing quote of the basic
// ("...") string whose opening quote is s[0]. It is escape-aware: a
// backslash escapes the next byte, so \" never closes the string and \\"
// closes after the escaped backslash. An unterminated string is an error.
// Error messages never echo the scalar: it may carry a secret.
func basicStringClose(s string) (int, error) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i, nil
		}
	}
	return 0, fmt.Errorf("unterminated quoted string")
}

// parseScalar parses a TOML scalar of the supported kinds: quoted string
// (basic "..." or literal '...'), bool, integer, float, or an inline array of
// quoted strings ("[...]"). Quoted strings are strict: the matching closing
// quote must be the FINAL byte of the scalar, so `"abc"junk`, `"abc" junk`,
// an interior unescaped quote and a lone `"` are all rejected (the old
// prefix/suffix check accepted `"a"b"` and panicked on a single `"`).
// Literal strings take no escapes, so an interior `'` is the same class of
// error.
func parseScalar(s string) (any, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	if strings.HasPrefix(s, "[") {
		return parseStringArray(s)
	}
	if strings.HasPrefix(s, `"`) {
		close, err := basicStringClose(s)
		if err != nil {
			return nil, err
		}
		if close != len(s)-1 {
			return nil, fmt.Errorf("unexpected characters after the closing quote")
		}
		return unquote(s[1:close])
	}
	if strings.HasPrefix(s, `'`) {
		close := strings.IndexByte(s[1:], '\'')
		if close < 0 {
			return nil, fmt.Errorf("unterminated literal string")
		}
		close++ // index into s
		if close != len(s)-1 {
			return nil, fmt.Errorf("unexpected characters after the closing quote")
		}
		return s[1:close], nil
	}
	if strings.ContainsAny(s, ".eE") {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, nil
		}
		return nil, fmt.Errorf("invalid value %q (want quoted string, int, float or bool)", s)
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	return nil, fmt.Errorf("invalid value %q (want quoted string, int, float or bool)", s)
}

// parseStringArray parses an inline TOML array of quoted strings, the form
// used by list-valued keys such as secret_broker.fallback_on. Values are
// elements only; the caller validates them. A single trailing comma and an
// empty array are accepted; unquoted or empty elements are rejected so a
// typo (for example fallback_on = [not_found]) cannot be silently ignored.
func parseStringArray(s string) (any, error) {
	if !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("unterminated array")
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	out := []string{}
	if inner == "" {
		return out, nil
	}
	parts, err := splitArrayElements(inner)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		v, err := parseScalar(part)
		if err != nil {
			return nil, fmt.Errorf("array element: %v", err)
		}
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("array elements must be quoted strings")
		}
		out = append(out, str)
	}
	return out, nil
}

// splitArrayElements splits an inline-array body on commas outside quoted
// strings. It is escape-aware for basic ("...") strings, accepts one trailing
// comma, and rejects empty elements.
func splitArrayElements(s string) ([]string, error) {
	var parts []string
	start := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote == '"' && c == '\\' && i+1 < len(s) {
			i++
			continue
		}
		switch c {
		case '"', '\'':
			if quote == 0 {
				quote = c
			} else if quote == c {
				quote = 0
			}
		case ',':
			if quote == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted string in array")
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	// A single trailing comma is allowed; drop only that empty tail.
	if last := len(parts) - 1; parts[last] == "" {
		parts = parts[:last]
	}
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("empty array element")
		}
	}
	return parts, nil
}

// unquote decodes the escapes of a TOML basic string.
func unquote(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			return "", fmt.Errorf("trailing backslash")
		}
		switch s[i] {
		case '"', '\\', '/':
			b.WriteByte(s[i])
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'f':
			b.WriteByte('\f')
		case 'b':
			b.WriteByte('\b')
		case 'u':
			if i+4 >= len(s) {
				return "", fmt.Errorf("truncated \\u escape")
			}
			n, err := strconv.ParseUint(s[i+1:i+5], 16, 32)
			if err != nil {
				return "", fmt.Errorf("invalid \\u escape: %v", err)
			}
			b.WriteRune(rune(n))
			i += 4
		default:
			return "", fmt.Errorf("unknown escape \\%c", s[i])
		}
	}
	return b.String(), nil
}

// assign writes the parsed scalar into the destination field, rejecting
// type mismatches (e.g. a string value for an int field).
func assign(dst reflect.Value, v any) error {
	if !dst.CanSet() {
		return fmt.Errorf("field is not settable")
	}
	switch dst.Kind() {
	case reflect.String:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("expected a string, got %T", v)
		}
		dst.SetString(s)
	case reflect.Int, reflect.Int64:
		i, ok := v.(int64)
		if !ok {
			return fmt.Errorf("expected an integer, got %T", v)
		}
		dst.SetInt(i)
	case reflect.Float64:
		switch n := v.(type) {
		case float64:
			dst.SetFloat(n)
		case int64:
			dst.SetFloat(float64(n))
		default:
			return fmt.Errorf("expected a number, got %T", v)
		}
	case reflect.Bool:
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("expected a bool, got %T", v)
		}
		dst.SetBool(b)
	case reflect.Slice:
		if dst.Type().Elem().Kind() != reflect.String {
			return fmt.Errorf("unsupported slice element type %s", dst.Type().Elem().Kind())
		}
		ss, ok := v.([]string)
		if !ok {
			return fmt.Errorf("expected a list of strings, got %T", v)
		}
		dst.Set(reflect.ValueOf(ss).Convert(dst.Type()))
	default:
		return fmt.Errorf("unsupported field type %s", dst.Kind())
	}
	return nil
}

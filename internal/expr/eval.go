package expr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// hashFiles hashing bounds: a total content budget (streamed, error on
// overflow) and a matched-file count cap, both hard bounds against
// workspace-exhausting cache keys.
const (
	hashFilesMaxBytes = 64 << 20
	hashFilesMaxFiles = 4096
)

// EvalString interpolates a text containing ${{ ... }} holes. Text outside
// holes is copied verbatim; each hole is parsed and evaluated against the
// context, and the resulting string replaces the hole. Parse errors (unknown
// context or field, malformed syntax, limit violations) and evaluation
// errors (missing keys, hashFiles failures, invalid JSON) are returned.
// A string without holes is returned unchanged.
func EvalString(s string, c Context) (string, error) {
	holes, err := Holes(s)
	if err != nil {
		return "", err
	}
	if len(holes) == 0 {
		return s, nil
	}
	var b strings.Builder
	last := 0
	for _, h := range holes {
		e, err := Parse(h.Body)
		if err != nil {
			return "", fmt.Errorf("${{ %s }}: %w", h.Body, err)
		}
		v, err := e.Eval(c)
		if err != nil {
			return "", err
		}
		b.WriteString(s[last:h.Start])
		b.WriteString(v)
		last = h.End
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

// EvalBool parses and evaluates a single expression as a boolean condition.
// The input must be one expression, not text with holes.
func EvalBool(s string, c Context) (bool, error) {
	e, err := Parse(s)
	if err != nil {
		return false, err
	}
	return e.EvalBool(c)
}

// Hole is one ${{ ... }} hole found in a text. Start and End are byte
// offsets of the full hole ("${{" through "}}") in the source string.
type Hole struct {
	Start int
	End   int
	Body  string
}

// Holes scans a text for interpolation holes. The scan is quote-aware so
// "}}" inside a string literal does not terminate the hole. An unterminated
// hole is an error.
func Holes(s string) ([]Hole, error) {
	var holes []Hole
	i := 0
	for {
		j := strings.Index(s[i:], "${{")
		if j < 0 {
			return holes, nil
		}
		start := i + j
		bodyStart := start + 3
		end := -1
		var quote byte
		escaped := false
		for k := bodyStart; k < len(s); k++ {
			ch := s[k]
			if quote != 0 {
				if escaped {
					escaped = false
				} else if ch == '\\' {
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
			if ch == '}' && k+1 < len(s) && s[k+1] == '}' {
				end = k
				break
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("unterminated ${{ ... }}: missing closing }}")
		}
		holes = append(holes, Hole{Start: start, End: end + 2, Body: s[bodyStart:end]})
		i = end + 2
	}
}

func (n *call) Eval(c Context) (string, error) {
	switch n.name {
	case "success", "failure", "cancelled", "always", "contains", "startsWith", "endsWith":
		v, err := n.EvalBool(c)
		if err != nil {
			return "", err
		}
		return boolString(v), nil
	case "fromJSON", "toJSON":
		return jsonFunc(n.name, n.args[0], c)
	case "hashFiles":
		return hashFilesFunc(c, n.args)
	}
	return "", fmt.Errorf("unknown function %q", n.name)
}

func (n *call) EvalBool(c Context) (bool, error) {
	switch n.name {
	case "success":
		st := c.Status
		return st != "failure" && st != "cancelled" && st != "blocked", nil
	case "failure":
		st := c.Status
		return st == "failure" || st == "blocked", nil
	case "cancelled":
		return c.Status == "cancelled", nil
	case "always":
		return true, nil
	case "contains", "startsWith", "endsWith":
		a, err := n.args[0].Eval(c)
		if err != nil {
			return false, err
		}
		b, err := n.args[1].Eval(c)
		if err != nil {
			return false, err
		}
		switch n.name {
		case "contains":
			return strings.Contains(a, b), nil
		case "startsWith":
			return strings.HasPrefix(a, b), nil
		default:
			return strings.HasSuffix(a, b), nil
		}
	case "fromJSON", "toJSON", "hashFiles":
		v, err := n.Eval(c)
		if err != nil {
			return false, err
		}
		return truthy(v)
	}
	return false, fmt.Errorf("unknown function %q", n.name)
}

// jsonFunc parses a JSON string and re-emits it in compact form. Both
// fromJSON and toJSON share this behavior; the difference is naming parity
// with GitHub Actions. Parse errors are evaluation errors.
func jsonFunc(name string, arg Expr, c Context) (string, error) {
	v, err := arg.Eval(c)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(strings.NewReader(v))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if dec.More() {
		return "", fmt.Errorf("%s: unexpected trailing data", name)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return string(b), nil
}

// hashFilesFunc hashes the sorted set of files matched by the given globs,
// relative to Context.Workspace. Globs may be comma-separated inside a
// single argument (the GitHub Actions convention) or passed as separate
// arguments. The hash covers each matched file's workspace-relative path and
// content, mirroring cache.Key, and returns the first 12 hex characters of
// the SHA-256 digest, like GitHub Actions. An empty workspace, a bad glob or
// an unreadable file is an evaluation error. The result is deterministic.
//
// Confinement bounds: every pattern is canonicalized (Abs + Clean) and
// absolute patterns or patterns with ".." components are rejected; every
// glob match must resolve beneath the workspace (matches that escape it
// through symlinks are rejected); matches are deduplicated; at most
// hashFilesMaxFiles files and hashFilesMaxBytes total content are hashed,
// streamed through a shared budget that errors on overflow.
func hashFilesFunc(c Context, args []Expr) (string, error) {
	if strings.TrimSpace(c.Workspace) == "" {
		return "", fmt.Errorf("hashFiles: workspace is not set")
	}
	root, err := safefs.OpenWorkspaceRoot(c.Workspace)
	if err != nil {
		return "", fmt.Errorf("hashFiles: workspace %q: %w", c.Workspace, err)
	}
	defer root.Close()
	workspace := root.Canonical
	var globs []string
	for _, a := range args {
		v, err := a.Eval(c)
		if err != nil {
			return "", err
		}
		for _, g := range strings.Split(v, ",") {
			if g = strings.TrimSpace(g); g != "" {
				globs = append(globs, g)
			}
		}
	}
	var files []string
	seen := map[string]bool{}
	for _, g := range globs {
		if filepath.IsAbs(g) || strings.HasPrefix(g, "/") {
			return "", fmt.Errorf("hashFiles: absolute pattern %q is not allowed", g)
		}
		for _, part := range strings.FieldsFunc(g, func(r rune) bool { return r == '/' || r == '\\' }) {
			if part == ".." {
				return "", fmt.Errorf("hashFiles: pattern %q contains a .. component", g)
			}
		}
		full := filepath.Clean(filepath.Join(workspace, g))
		matches, err := filepath.Glob(full)
		if err != nil {
			return "", fmt.Errorf("hashFiles: invalid glob %q: %w", g, err)
		}
		for _, f := range matches {
			if seen[f] {
				continue
			}
			seen[f] = true
			files = append(files, f)
		}
	}
	if len(files) > hashFilesMaxFiles {
		return "", fmt.Errorf("hashFiles: %d files matched, limit is %d", len(files), hashFilesMaxFiles)
	}
	sort.Strings(files)
	h := sha256.New()
	remaining := int64(hashFilesMaxBytes)
	for _, f := range files {
		rel, err := filepath.Rel(workspace, f)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("hashFiles: match %q escapes the workspace", f)
		}
		fh, err := root.OpenRel(filepath.ToSlash(rel))
		if err != nil {
			if errors.Is(err, safefs.ErrSymlinkParent) || errors.Is(err, safefs.ErrNotRegular) {
				return "", fmt.Errorf("hashFiles: match %q escapes the workspace", f)
			}
			return "", fmt.Errorf("hashFiles: %w", err)
		}
		io.WriteString(h, rel)
		n, err := io.Copy(h, io.LimitReader(fh, remaining+1))
		fh.Close()
		if err != nil {
			return "", fmt.Errorf("hashFiles: %w", err)
		}
		if n > remaining {
			return "", fmt.Errorf("hashFiles: total size exceeds the %d byte budget", int64(hashFilesMaxBytes))
		}
		remaining -= n
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

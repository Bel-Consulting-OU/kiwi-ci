package secrets

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Provider interface {
	Get(context.Context, string) (string, error)
}

type Chain []Provider

func (c Chain) Get(ctx context.Context, name string) (string, error) {
	var errs []error
	for _, p := range c {
		v, err := p.Get(ctx, name)
		if err == nil && v != "" {
			return v, nil
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return "", fmt.Errorf("secret %q not found: %w", name, errors.Join(errs...))
}

type EnvProvider struct{ Prefix string }

func (p EnvProvider) Get(_ context.Context, name string) (string, error) {
	key := p.Prefix + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	if v, ok := os.LookupEnv(key); ok {
		return v, nil
	}
	return "", fmt.Errorf("%s unset", key)
}

type MacKeychainProvider struct{ Service string }

// goos is a test-only seam over runtime.GOOS. Production behavior is
// unchanged; it lets the darwin guard be exercised from a darwin test run.
var goos = runtime.GOOS

func (p MacKeychainProvider) Get(ctx context.Context, name string) (string, error) {
	if goos != "darwin" {
		return "", fmt.Errorf("macOS keychain unavailable")
	}
	service := p.Service
	if service == "" {
		service = "kiwi-ci"
	}
	b, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", service, "-a", name, "-w").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

type MapProvider map[string]string

func (m MapProvider) Get(_ context.Context, name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return v, nil
}

const (
	maskReplacement  = "***"
	maskMinSecretLen = 3
	maskMaxSecretLen = 8192
	maskMaxSecrets   = MaxSecretNames
)

// MaxSecretNames is the shared capacity agreement for one execution's
// secret set: pipeline admission caps a job's declared secret names at this
// value and the Masker's capacity equals it, so a job that passes
// admission can never silently lose secrets to masking. The pipeline
// admission layer (maxSecretsPerJob in internal/pipeline) is already
// aligned at 128; it should import this constant in a later round so the
// two can never drift again.
const MaxSecretNames = 128

var (
	// ErrMaskerCapacity is returned by AddStrict when the masker already
	// holds Capacity() secrets and the caller asked for strict admission.
	ErrMaskerCapacity = errors.New("secrets: masker capacity exhausted")
	// ErrMaskValueInvalid is returned by AddStrict when a secret value is
	// shorter than 3 bytes or longer than 8192 bytes (the masking window).
	ErrMaskValueInvalid = errors.New("secrets: secret value outside supported length")
	// ErrTainted is returned by TaintCheck when an output value contains a
	// registered secret (raw or derived form).
	ErrTainted = errors.New("secrets: output contains a registered secret")
)

type Masker struct {
	mu            sync.RWMutex
	values        []string
	rawReplacer   *strings.Replacer
	multiReplacer *strings.Replacer
	multiForms    []string
}

// Add registers a secret for masking. Secrets shorter than 3 or longer than
// 8192 bytes are ignored, as are additions beyond the masker capacity
// (MaxSecretNames). Kept for source compatibility; execution paths that
// must not silently lose secrets use AddStrict.
func (m *Masker) Add(v string) {
	_ = m.AddStrict(v)
}

// AddStrict registers a secret for masking and fails closed when the value
// is outside the masking window (ErrMaskValueInvalid) or the masker already
// holds Capacity() secrets (ErrMaskerCapacity). A successful call masks the
// value (and its derived forms) exactly once.
func (m *Masker) AddStrict(v string) error {
	if len(v) < maskMinSecretLen || len(v) > maskMaxSecretLen {
		return ErrMaskValueInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.values) >= maskMaxSecrets {
		return ErrMaskerCapacity
	}
	m.values = append(m.values, v)
	sort.Slice(m.values, func(i, j int) bool { return len(m.values[i]) > len(m.values[j]) })
	m.rawReplacer = newMaskReplacer(m.values)
	m.multiForms = maskForms(m.values)
	m.multiReplacer = newMaskReplacer(m.multiForms)
	return nil
}

// Capacity reports the maximum number of secret values the masker holds
// (MaxSecretNames, matching the pipeline admission cap).
func (m *Masker) Capacity() int { return maskMaxSecrets }

// Len reports the number of registered secrets.
func (m *Masker) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.values)
}

// ContainsSecret reports whether s contains a registered secret value or
// any of its derived forms (URL-escaped, base64/base32 in their standard and
// URL alphabets, lower- and upper-case hex, JSON-quoted, shell-quoted,
// multiline fragments). It is the taint predicate: a string reporting true
// must not leave the trust boundary unmasked.
//
// Matching is ASCII-whitespace-insensitive: a derived form split across line
// wraps (MIME/base64(1) 76-column output) or indented with spaces is still
// detected, because ASCII whitespace is stripped from the candidate before
// the second, wrapped-form comparison.
func (m *Masker) ContainsSecret(s string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, f := range m.multiForms {
		if strings.Contains(s, f) {
			return true
		}
	}
	if stripped := stripASCIIWhitespace(s); stripped != s {
		for _, f := range m.multiForms {
			if strings.Contains(stripped, f) {
				return true
			}
		}
	}
	return false
}

// TaintCheck validates persisted job outputs against the registered
// secrets. It returns ErrTainted wrapped with the offending key when any
// output value (top-level or per-step) contains a registered secret.
// Execution paths call this before persisting JobResult.Outputs.
func (m *Masker) TaintCheck(outputs map[string]string, stepOutputs map[string]map[string]string) error {
	for k, v := range outputs {
		if m.ContainsSecret(v) {
			return fmt.Errorf("%w: output %q", ErrTainted, k)
		}
	}
	for step, outs := range stepOutputs {
		for k, v := range outs {
			if m.ContainsSecret(v) {
				return fmt.Errorf("%w: step %q output %q", ErrTainted, step, k)
			}
		}
	}
	return nil
}

// Mask replaces occurrences of the raw registered secret values.
func (m *Masker) Mask(s string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.rawReplacer == nil {
		return s
	}
	return m.rawReplacer.Replace(s)
}

// MaskMulti replaces occurrences of the raw secret values and all derived
// forms (URL-escaped, base64/base32, lower- and upper-case hex, JSON-quoted,
// shell-quoted, multiline fragments), including forms split across ASCII
// whitespace by line wrapping (MIME/base64(1)) or indentation.
func (m *Masker) MaskMulti(s string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.multiReplacer == nil {
		return s
	}
	out := m.multiReplacer.Replace(s)
	stripped := stripASCIIWhitespace(out)
	if stripped == out {
		return out
	}
	// A form may span whitespace (wrapped/indented output). Only pay for the
	// whitespace-insensitive pass when the collapsed text still holds a form.
	if m.multiReplacer.Replace(stripped) == stripped {
		return out
	}
	return m.maskAcrossWhitespace(out, stripped)
}

// maskAcrossWhitespace rewrites s so that every masked form match in the
// ASCII-whitespace-collapsed text is replaced in place, preserving the
// original whitespace outside each match. Forms are sorted longest-first by
// maskForms, so the first prefix match at each position is the longest one.
func (m *Masker) maskAcrossWhitespace(s, stripped string) string {
	origIdx := make([]int, 0, len(stripped))
	for i := 0; i < len(s); i++ {
		if !isASCIIWhitespace(s[i]) {
			origIdx = append(origIdx, i)
		}
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for p := 0; p < len(stripped); {
		matched := ""
		for _, f := range m.multiForms {
			if len(f) <= len(stripped)-p && stripped[p:p+len(f)] == f {
				matched = f
				break
			}
		}
		if matched == "" {
			p++
			continue
		}
		start := origIdx[p]
		end := origIdx[p+len(matched)-1] + 1
		b.WriteString(s[last:start])
		b.WriteString(maskReplacement)
		last = end
		p += len(matched)
	}
	b.WriteString(s[last:])
	return b.String()
}

// lowerPercentHex lowercases the hex digits of %XX escapes so a URL-encoded
// form written with lower-case percent hex is still matched. Bytes outside
// escapes are untouched. It returns "" when s has no escapes, avoiding a
// duplicate form.
func lowerPercentHex(s string) string {
	if !strings.Contains(s, "%") {
		return ""
	}
	b := []byte(s)
	changed := false
	for i := 0; i+2 < len(b); i++ {
		if b[i] != '%' {
			continue
		}
		for _, j := range []int{i + 1, i + 2} {
			if b[j] >= 'A' && b[j] <= 'F' {
				b[j] += 'a' - 'A'
				changed = true
			}
		}
	}
	if !changed {
		return ""
	}
	return string(b)
}

// isASCIIWhitespace reports whether b is one of the ASCII whitespace bytes
// stripped before wrapped/indented form matching.
func isASCIIWhitespace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// stripASCIIWhitespace removes ASCII whitespace from s, returning s unchanged
// when it holds none.
func stripASCIIWhitespace(s string) string {
	hasWS := false
	for i := 0; i < len(s); i++ {
		if isASCIIWhitespace(s[i]) {
			hasWS = true
			break
		}
	}
	if !hasWS {
		return s
	}
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !isASCIIWhitespace(s[i]) {
			buf = append(buf, s[i])
		}
	}
	return string(buf)
}

func newMaskReplacer(forms []string) *strings.Replacer {
	pairs := make([]string, 0, len(forms)*2)
	for _, f := range forms {
		pairs = append(pairs, f, maskReplacement)
	}
	return strings.NewReplacer(pairs...)
}

// base32NoPad is the unpadded standard base32 alphabet; base32HexNoPad is the
// unpadded extended-hex alphabet. Both are common CLI encodings (base32(1)).
var (
	base32NoPad    = base32.StdEncoding.WithPadding(base32.NoPadding)
	base32HexNoPad = base32.HexEncoding.WithPadding(base32.NoPadding)
)

// maskForms derives all maskable representations of the registered values and
// sorts them longest-first so the Replacer prefers the longest match. Hex is
// derived in both cases; base64 and base32 in their standard/URL/extended-hex
// alphabets with and without padding; URL escapes in both percent-hex cases.
// Long encoded forms that a tool wraps or indents are matched separately by
// the ASCII-whitespace-insensitive pass in MaskMulti/ContainsSecret, so they
// are not enumerated here.
func maskForms(values []string) []string {
	seen := make(map[string]bool, len(values)*16)
	forms := make([]string, 0, len(values)*16)
	add := func(f string) {
		if f == "" || seen[f] {
			return
		}
		seen[f] = true
		forms = append(forms, f)
	}
	for _, v := range values {
		b := []byte(v)
		add(v)
		add(url.QueryEscape(v))
		add(lowerPercentHex(url.QueryEscape(v)))
		add(url.PathEscape(v))
		add(lowerPercentHex(url.PathEscape(v)))
		add(base64.StdEncoding.EncodeToString(b))
		add(base64.RawStdEncoding.EncodeToString(b))
		add(base64.URLEncoding.EncodeToString(b))
		add(base64.RawURLEncoding.EncodeToString(b))
		add(base32.StdEncoding.EncodeToString(b))
		add(base32NoPad.EncodeToString(b))
		add(base32.HexEncoding.EncodeToString(b))
		add(base32HexNoPad.EncodeToString(b))
		add(strings.ToLower(base32.StdEncoding.EncodeToString(b)))
		add(strings.ToLower(base32.HexEncoding.EncodeToString(b)))
		add(hex.EncodeToString(b))
		add(strings.ToUpper(hex.EncodeToString(b)))
		add(strconv.Quote(v))
		add("'" + v + "'")
		if strings.Contains(v, "\n") {
			lines := strings.Split(v, "\n")
			add(strings.TrimSuffix(lines[0], "\r"))
			add(strings.TrimSuffix(lines[len(lines)-1], "\r"))
			for _, line := range lines {
				add(strings.TrimSuffix(line, "\r"))
			}
		}
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return forms
}

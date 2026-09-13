package secrets

import (
	"context"
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

func (p MacKeychainProvider) Get(ctx context.Context, name string) (string, error) {
	if runtime.GOOS != "darwin" {
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
	maskMaxSecrets   = 64
)

type Masker struct {
	mu            sync.RWMutex
	values        []string
	rawReplacer   *strings.Replacer
	multiReplacer *strings.Replacer
}

// Add registers a secret for masking. Secrets shorter than 3 or longer than
// 8192 bytes are ignored, as are additions beyond 64 secrets.
func (m *Masker) Add(v string) {
	if len(v) < maskMinSecretLen || len(v) > maskMaxSecretLen {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.values) >= maskMaxSecrets {
		return
	}
	m.values = append(m.values, v)
	sort.Slice(m.values, func(i, j int) bool { return len(m.values[i]) > len(m.values[j]) })
	m.rawReplacer = newMaskReplacer(m.values)
	m.multiReplacer = newMaskReplacer(maskForms(m.values))
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
// forms (URL-escaped, base64, hex, JSON-quoted, shell-quoted, multiline
// fragments).
func (m *Masker) MaskMulti(s string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.multiReplacer == nil {
		return s
	}
	return m.multiReplacer.Replace(s)
}

func newMaskReplacer(forms []string) *strings.Replacer {
	pairs := make([]string, 0, len(forms)*2)
	for _, f := range forms {
		pairs = append(pairs, f, maskReplacement)
	}
	return strings.NewReplacer(pairs...)
}

// maskForms derives all maskable representations of the registered values and
// sorts them longest-first so the Replacer prefers the longest match.
func maskForms(values []string) []string {
	seen := make(map[string]bool, len(values)*8)
	forms := make([]string, 0, len(values)*8)
	add := func(f string) {
		if f == "" || seen[f] {
			return
		}
		seen[f] = true
		forms = append(forms, f)
	}
	for _, v := range values {
		add(v)
		add(url.QueryEscape(v))
		add(url.PathEscape(v))
		add(base64.StdEncoding.EncodeToString([]byte(v)))
		add(base64.RawURLEncoding.EncodeToString([]byte(v)))
		add(hex.EncodeToString([]byte(v)))
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

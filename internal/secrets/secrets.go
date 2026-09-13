package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
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

type Masker struct {
	mu     sync.RWMutex
	values []string
}

func (m *Masker) Add(v string) {
	if len(v) < 3 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values = append(m.values, v)
	sort.Slice(m.values, func(i, j int) bool { return len(m.values[i]) > len(m.values[j]) })
}
func (m *Masker) Mask(s string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, v := range m.values {
		s = strings.ReplaceAll(s, v, "***")
	}
	return s
}

package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Named server contexts keep non-secret metadata in the config file and the
// token in the OS credential store (or a file fallback where none exists).
// Ordinary commands then use the active context instead of requiring
// --server/--token on every call.

// Context is one named Kiwi control-plane endpoint.
type Context struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Current bool   `json:"current,omitempty"`
}

// contextFile is the on-disk metadata store (never holds secrets).
type contextFile struct {
	Contexts []Context `json:"contexts"`
}

func kiwiConfigDir() (string, error) {
	if d := os.Getenv("KIWI_CONFIG_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "kiwi"), nil
}

func contextPath() (string, error) {
	dir, err := kiwiConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "contexts.json"), nil
}

func loadContexts() (contextFile, error) {
	p, err := contextPath()
	if err != nil {
		return contextFile{}, err
	}
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return contextFile{}, nil
	}
	if err != nil {
		return contextFile{}, err
	}
	var f contextFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return contextFile{}, fmt.Errorf("parse %s: %w", p, err)
	}
	return f, nil
}

func saveContexts(f contextFile) error {
	p, err := contextPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	sort.Slice(f.Contexts, func(i, j int) bool { return f.Contexts[i].Name < f.Contexts[j].Name })
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(raw, '\n'), 0o600)
}

// SecretStore is the credential seam: OS keychain in production, file
// fallback in environments without one. Config files never hold secrets.
type SecretStore interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}

// FileSecretStore stores secrets under the kiwi config dir with 0600
// permissions. It is the portable fallback; production macOS/Windows/Linux
// should use the OS keychain (see keyring_*.go).
type FileSecretStore struct {
	Dir string
}

func (s FileSecretStore) path(service, account string) string {
	return filepath.Join(s.Dir, "secrets", sanitizeSecretName(service+"_"+account)+".token")
}

func sanitizeSecretName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func (s FileSecretStore) Get(service, account string) (string, error) {
	raw, err := os.ReadFile(s.path(service, account))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (s FileSecretStore) Set(service, account, secret string) error {
	p := s.path(service, account)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(secret), 0o600)
}

func (s FileSecretStore) Delete(service, account string) error {
	err := os.Remove(s.path(service, account))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// DefaultSecretStore returns the platform keychain when available, else the
// file fallback under the kiwi config dir. It is a var so tests can pin the
// file store on hosts without a usable keychain.
var DefaultSecretStore = func() (SecretStore, error) {
	dir, err := kiwiConfigDir()
	if err != nil {
		return nil, err
	}
	if ks := platformKeychain(); ks != nil {
		return ks, nil
	}
	return FileSecretStore{Dir: dir}, nil
}

const secretService = "kiwi-ci"

// ContextCommand implements `kiwi login|logout|context ...`.
func ContextCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kiwi login <url> | kiwi logout | kiwi context [add|use|list|remove]")
	}
	switch args[0] {
	case "login":
		return contextLogin(args[1:])
	case "logout":
		return contextLogout(args[1:])
	case "context":
		return contextManage(args[1:])
	default:
		// `kiwi login ...` is dispatched here as "login"; `kiwi context ...`
		// as "context".
		return fmt.Errorf("usage: kiwi login <url> | kiwi logout | kiwi context [add|use|list|remove]")
	}
}

func contextLogin(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kiwi login <url> [--name NAME] [--token TOKEN]")
	}
	url := strings.TrimRight(args[0], "/")
	name := ""
	token := ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 >= len(args) {
				return fmt.Errorf("--name needs a value")
			}
			name = args[i+1]
			i++
		case "--token":
			if i+1 >= len(args) {
				return fmt.Errorf("--token needs a value")
			}
			token = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if name == "" {
		name = defaultContextName(url)
	}
	if token == "" {
		// Read the token from stdin so it never lands in argv history.
		raw, err := readAllStdin()
		if err != nil {
			return fmt.Errorf("read token from stdin: %w", err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		return fmt.Errorf("token is required (pipe it on stdin or pass --token)")
	}
	store, err := DefaultSecretStore()
	if err != nil {
		return err
	}
	if err := store.Set(secretService, name, token); err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	f, err := loadContexts()
	if err != nil {
		return err
	}
	found := false
	for i := range f.Contexts {
		if f.Contexts[i].Name == name {
			f.Contexts[i].URL = url
			found = true
		}
	}
	if !found {
		f.Contexts = append(f.Contexts, Context{Name: name, URL: url})
	}
	// Login makes the new context current.
	for i := range f.Contexts {
		f.Contexts[i].Current = f.Contexts[i].Name == name
	}
	if err := saveContexts(f); err != nil {
		return err
	}
	fmt.Printf("logged in to %s as context %q\n", url, name)
	return nil
}

func contextLogout(args []string) error {
	f, err := loadContexts()
	if err != nil {
		return err
	}
	name := currentContextName(f)
	if len(args) > 0 {
		name = args[0]
	}
	if name == "" {
		return fmt.Errorf("no active context to log out of")
	}
	store, err := DefaultSecretStore()
	if err != nil {
		return err
	}
	if err := store.Delete(secretService, name); err != nil {
		return err
	}
	kept := f.Contexts[:0]
	for _, c := range f.Contexts {
		if c.Name != name {
			kept = append(kept, c)
		}
	}
	f.Contexts = kept
	if err := saveContexts(f); err != nil {
		return err
	}
	fmt.Printf("logged out of context %q\n", name)
	return nil
}

func contextManage(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		f, err := loadContexts()
		if err != nil {
			return err
		}
		if len(f.Contexts) == 0 {
			fmt.Println("no contexts (kiwi login <url>)")
			return nil
		}
		for _, c := range f.Contexts {
			mark := " "
			if c.Current {
				mark = "*"
			}
			fmt.Printf("%s %-20s %s\n", mark, c.Name, c.URL)
		}
		return nil
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("usage: kiwi context add <name> <url>")
		}
		f, err := loadContexts()
		if err != nil {
			return err
		}
		for i := range f.Contexts {
			if f.Contexts[i].Name == args[1] {
				f.Contexts[i].URL = strings.TrimRight(args[2], "/")
				return saveContexts(f)
			}
		}
		f.Contexts = append(f.Contexts, Context{Name: args[1], URL: strings.TrimRight(args[2], "/")})
		return saveContexts(f)
	case "use":
		if len(args) < 2 {
			return fmt.Errorf("usage: kiwi context use <name>")
		}
		f, err := loadContexts()
		if err != nil {
			return err
		}
		found := false
		for i := range f.Contexts {
			f.Contexts[i].Current = f.Contexts[i].Name == args[1]
			if f.Contexts[i].Current {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("context %q not found", args[1])
		}
		return saveContexts(f)
	case "remove", "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: kiwi context remove <name>")
		}
		return contextLogout([]string{args[1]})
	default:
		return fmt.Errorf("usage: kiwi context [add|use|list|remove]")
	}
}

func currentContextName(f contextFile) string {
	for _, c := range f.Contexts {
		if c.Current {
			return c.Name
		}
	}
	if len(f.Contexts) == 1 {
		return f.Contexts[0].Name
	}
	return ""
}

// ActiveContext resolves the current endpoint + token for ordinary commands.
func ActiveContext() (url, token string, err error) {
	f, err := loadContexts()
	if err != nil {
		return "", "", err
	}
	name := currentContextName(f)
	if name == "" {
		return "", "", fmt.Errorf("no active context (kiwi login <url>)")
	}
	for _, c := range f.Contexts {
		if c.Name == name {
			store, serr := DefaultSecretStore()
			if serr != nil {
				return "", "", serr
			}
			tok, terr := store.Get(secretService, name)
			if terr != nil {
				return "", "", fmt.Errorf("context %q has no stored token (kiwi login)", name)
			}
			return c.URL, tok, nil
		}
	}
	return "", "", fmt.Errorf("context %q not found", name)
}

func defaultContextName(url string) string {
	u := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	u = strings.ReplaceAll(u, "/", "-")
	u = strings.ReplaceAll(u, ":", "-")
	if u == "" {
		return "default"
	}
	return u
}

func readAllStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

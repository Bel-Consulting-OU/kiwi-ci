// Package giturl is the single strict clone-URL parser shared by the control
// plane and the runner. Kiwi can only authorize and enqueue repositories the
// runner can actually clone, so both sides accept exactly the same URL forms;
// a divergence here previously let the server admit scp-style
// git@host:owner/repo URLs that the runner then rejected at checkout.
package giturl

import (
	"errors"
	"fmt"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"net/url"
	"strings"
)

// ParseCloneURL parses a clone URL into its canonical forge host, forge
// repository path (owner/repo, nested groups allowed, no .git) and transport
// scheme normalized to "https" | "ssh" | "http" (scp-style forms are SSH).
//
// Accepted forms:
//
//	https://host/owner/repo(.git)
//	ssh://git@host/owner/repo(.git)
//	git@host:owner/repo(.git)          (scp-like)
//	http://host/owner/repo(.git)       (loopback only)
func ParseCloneURL(raw string) (host, forgePath, scheme string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", "", errors.New("clone URL is empty")
	}
	if strings.HasPrefix(s, "-") {
		return "", "", "", errors.New("clone URL must not start with '-'")
	}
	if i := strings.Index(s, "://"); i >= 0 {
		sch := strings.ToLower(strings.TrimSpace(s[:i]))
		switch sch {
		case "https", "ssh", "http":
		default:
			return "", "", "", fmt.Errorf("unsupported clone URL scheme %q", sch)
		}
		u, uerr := url.Parse(s)
		if uerr != nil {
			return "", "", "", fmt.Errorf("malformed clone URL: %w", uerr)
		}
		if u.Host == "" {
			return "", "", "", errors.New("clone URL names no host")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return "", "", "", errors.New("clone URL must not carry a query or fragment")
		}
		if u.User != nil {
			username := u.User.Username()
			_, hasPassword := u.User.Password()
			if sch != "ssh" || username != "git" || hasPassword {
				return "", "", "", errors.New("clone URL must not carry credentials (userinfo)")
			}
		}
		if sch == "http" && !isLoopbackHost(u.Hostname()) {
			return "", "", "", errors.New("http clone URLs are only allowed for loopback hosts")
		}
		p, perr := cleanPath(u.Path)
		if perr != nil {
			return "", "", "", perr
		}
		h := CanonicalHost(u.Host)
		if h == "" {
			return "", "", "", errors.New("clone URL names no host")
		}
		return h, p, sch, nil
	}
	// scp-like git@host:path
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return "", "", "", errors.New("clone URL must be an absolute URL or an scp-style git@host:path")
	}
	if user := s[:at]; user != "git" {
		return "", "", "", errors.New("scp-style clone URL must use the git user")
	}
	rest := s[at+1:]
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return "", "", "", errors.New("scp-style clone URL must be git@host:path")
	}
	hostPart := rest[:colon]
	if strings.ContainsAny(hostPart, "/?#") || strings.TrimSpace(hostPart) != hostPart || strings.ContainsAny(hostPart, " \t") {
		return "", "", "", errors.New("scp-style clone URL host component is malformed")
	}
	p, perr := cleanPath(rest[colon+1:])
	if perr != nil {
		return "", "", "", perr
	}
	h := CanonicalHost(hostPart)
	if h == "" {
		return "", "", "", errors.New("scp-style clone URL names no host")
	}
	return h, p, "ssh", nil
}

// CanonicalHost normalizes a host (or URL, or scp-like form) to the form
// used in canonical repository identities. It delegates to auth's
// implementation so the two can never disagree — that divergence is exactly
// what let an scp-style URL be authorized on one side and rejected on the
// other.
func CanonicalHost(raw string) string {
	return auth.CanonicalHost(raw)
}

func ForgePathFromFullName(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if strings.Contains(s, "://") || strings.Contains(s, "@") {
		// Legacy "Repository-as-URL" spelling: the path is the identity.
		_, p, _, err := ParseCloneURL(s)
		if err != nil {
			return "", false
		}
		return p, true
	}
	p, err := cleanPath("/" + s)
	if err != nil {
		return "", false
	}
	return p, true
}

// cleanPath normalizes a forge repository path from a URL.
func cleanPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, "//") {
		return "", fmt.Errorf("clone URL repository path %q is malformed", p)
	}
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", errors.New("clone URL names no repository path")
	}
	if len(p) > 4 && strings.EqualFold(p[len(p)-4:], ".git") {
		p = p[:len(p)-4]
		p = strings.TrimSuffix(p, "/")
	}
	if p == "" {
		return "", errors.New("clone URL names no repository path")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("clone URL repository path %q is malformed", p)
		}
	}
	return p, nil
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasPrefix(h, "127.")
}

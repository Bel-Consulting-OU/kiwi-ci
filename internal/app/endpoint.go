package app

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Endpoint is the resolved control-plane coordinate for operational
// commands. One resolution function — never a per-command default that
// silently ignores the active login context.
type Endpoint struct {
	Server string
	Token  string
	// Source names where the values came from (flag, context, env, default).
	Source string
}

const defaultLocalServer = "http://127.0.0.1:8080"

// ResolveEndpoint applies the ONE precedence contract:
//
//	explicit --server/--token
//	  > active saved context (kiwi login / kiwi context use)
//	  > environment (KIWI_SERVER / KIWI_ADMIN_TOKEN)
//	  > safe local default
//
// Credentials must never be sent to a non-loopback plaintext HTTP server
// unless the caller explicitly opts in with KIWI_ALLOW_INSECURE_HTTP=1.
func ResolveEndpoint(flagServer, flagToken string) (Endpoint, error) {
	e := Endpoint{}
	envServer := strings.TrimSpace(os.Getenv("KIWI_SERVER"))
	envToken := strings.TrimSpace(os.Getenv("KIWI_ADMIN_TOKEN"))
	ctxServer, ctxToken, ctxErr := ActiveContext()
	switch {
	case strings.TrimSpace(flagServer) != "":
		e.Server = strings.TrimSpace(flagServer)
		e.Token = strings.TrimSpace(flagToken)
		e.Source = "flag"
	case ctxErr == nil && ctxServer != "":
		e.Server = ctxServer
		e.Token = ctxToken
		e.Source = "context"
	case envServer != "":
		e.Server = envServer
		e.Token = envToken
		e.Source = "env"
	default:
		e.Server = defaultLocalServer
		e.Token = envToken
		e.Source = "default"
	}
	if e.Token == "" {
		e.Token = envToken
	}
	if err := e.validate(); err != nil {
		return Endpoint{}, err
	}
	return e, nil
}

// validate refuses sending a bearer/admin token to a non-loopback plaintext
// HTTP endpoint unless the operator supplied an explicit unsafe override.
func (e Endpoint) validate() error {
	u, err := url.Parse(e.Server)
	if err != nil {
		return fmt.Errorf("server URL %q is not a valid URL: %w", e.Server, err)
	}
	if u.Scheme != "http" {
		return nil
	}
	host := u.Hostname()
	loopback := host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
	if loopback {
		return nil
	}
	if e.Token == "" {
		return nil
	}
	if strings.TrimSpace(os.Getenv("KIWI_ALLOW_INSECURE_HTTP")) == "1" {
		return nil
	}
	return fmt.Errorf("refusing to send a token to plaintext HTTP host %q (set KIWI_ALLOW_INSECURE_HTTP=1 to override)", host)
}

// RequireToken returns the token or a clear error — commands that need
// credentials must not silently proceed unauthenticated.
func (e Endpoint) RequireToken() (string, error) {
	if e.Token == "" {
		return "", fmt.Errorf("no admin token (kiwi login, --token, or KIWI_ADMIN_TOKEN); source=%s", e.Source)
	}
	return e.Token, nil
}

// mustResolveServer is the TUI's endpoint lookup. It returns an error on a
// malformed or refused endpoint (plaintext non-loopback with a token) so the
// caller can report it instead of panicking mid-session.
func resolveServerForTUI(flagServer, flagToken string) (Endpoint, error) {
	return ResolveEndpoint(flagServer, flagToken)
}

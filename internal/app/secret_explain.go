package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// SecretCommand implements `kiwi secret explain NAME [--repo R] [--org O]
// [--env E] [--branch B] [--event E] [--fork] [--trusted] [--json]`.
// It prints why a secret does or does not resolve for a request — the
// product-facing replacement for hidden precedence.
func SecretCommand(args []string) error {
	if len(args) < 2 || args[0] != "explain" {
		return fmt.Errorf("usage: kiwi secret explain NAME [flags]")
	}
	name := args[1]
	fs := flag.NewFlagSet("secret explain", flag.ContinueOnError)
	repo := fs.String("repo", "", "repository full name")
	org := fs.String("org", "", "organization")
	team := fs.String("team", "", "team")
	env := fs.String("env", "", "environment")
	branch := fs.String("branch", "", "branch")
	tag := fs.String("tag", "", "tag")
	event := fs.String("event", "", "event")
	fork := fs.Bool("fork", false, "fork execution")
	untrusted := fs.Bool("untrusted", false, "untrusted execution")
	asJSON := fs.Bool("json", false, "print JSON")
	storePath := fs.String("store", "", "path to a JSON secret-ref store (offline hierarchy demo)")
	jobID := fs.String("job", "", "job id — ask the RUNNING SERVER's SecretDecision (the same authority issueSecret consumes)")
	serverURL := fs.String("server", "", "server base URL (defaults to the active context / KIWI_SERVER)")
	token := fs.String("token", "", "admin token (defaults to the active context / KIWI_ADMIN_TOKEN)")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	// Preferred path: interrogate the running server's SecretDecision. The
	// offline hierarchy below is a LOCAL model for docs and unit tests; it
	// is not the runtime authority and must not be presented as one.
	if *jobID != "" {
		return explainSecretViaServer(*serverURL, *token, *jobID, name, *asJSON)
	}
	h := secrets.NewHierarchy()
	if *storePath != "" {
		raw, err := os.ReadFile(*storePath)
		if err != nil {
			return err
		}
		var refs []secrets.SecretRef
		if err := json.Unmarshal(raw, &refs); err != nil {
			return err
		}
		for _, r := range refs {
			h.Add(r)
		}
	}
	p := secrets.Policy{
		Repository: *repo, Org: *org, Team: *team, Environment: *env,
		Branch: *branch, Tag: *tag, Event: *event,
		Fork: *fork, Trusted: !*untrusted,
	}
	e := h.Explain(name, p)
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(e)
	}
	fmt.Printf("secret:     %s\n", e.Name)
	fmt.Printf("source:     %s\n", orDash(e.Source))
	fmt.Printf("overridden: %s\n", orDash(e.OverriddenBy))
	fmt.Printf("available:  %v\n", e.Available)
	fmt.Printf("reason:     %s\n", e.Reason)
	if e.Expires != "" {
		fmt.Printf("expires:    %s\n", e.Expires)
	}
	if e.Provider != "" {
		fmt.Printf("provider:   %s\n", e.Provider)
	}
	if len(e.Consulted) > 0 {
		fmt.Println("consulted:")
		for _, c := range e.Consulted {
			fmt.Printf("  - %s\n", c)
		}
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// explainSecretViaServer asks the running control plane for the SAME
// SecretDecision issueSecret consumes. This is the authoritative explain
// path: the offline hierarchy is only a local model.
func explainSecretViaServer(baseURL, token, jobID, name string, asJSON bool) error {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		base = strings.TrimSpace(os.Getenv("KIWI_SERVER"))
	}
	if base == "" {
		// Active context wins over the hard-coded local default.
		if ctxURL, ctxToken, err := ActiveContext(); err == nil && ctxURL != "" {
			base = ctxURL
			if token == "" {
				token = ctxToken
			}
		}
	}
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	if token == "" {
		token = strings.TrimSpace(os.Getenv("KIWI_ADMIN_TOKEN"))
	}
	u := strings.TrimRight(base, "/") + "/api/v1/jobs/" + url.PathEscape(jobID) + "/secrets/" + url.PathEscape(name) + "/explain"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("secret explain: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("secret explain: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if asJSON {
		fmt.Println(string(raw))
		return nil
	}
	var d struct {
		Name     string `json:"name"`
		Allowed  bool   `json:"allowed"`
		Reason   string `json:"reason"`
		Declared bool   `json:"declared"`
		Trusted  bool   `json:"trusted"`
		Stage    string `json:"stage"`
		Scope    struct {
			Repository  string `json:"Repository"`
			Environment string `json:"Environment"`
			Trusted     bool   `json:"Trusted"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("secret explain: decode: %w", err)
	}
	fmt.Printf("secret:     %s\n", d.Name)
	fmt.Printf("allowed:    %v\n", d.Allowed)
	fmt.Printf("stage:      %s\n", d.Stage)
	fmt.Printf("declared:   %v\n", d.Declared)
	fmt.Printf("trusted:    %v\n", d.Trusted)
	fmt.Printf("scope:      repo=%s env=%s trusted=%t\n", d.Scope.Repository, d.Scope.Environment, d.Scope.Trusted)
	fmt.Printf("reason:     %s\n", d.Reason)
	return nil
}

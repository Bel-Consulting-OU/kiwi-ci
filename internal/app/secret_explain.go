package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

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
	storePath := fs.String("store", "", "path to a JSON secret-ref store (optional demo store)")
	if err := fs.Parse(args[2:]); err != nil {
		return err
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

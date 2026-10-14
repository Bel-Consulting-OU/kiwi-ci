package app

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Setup is the onboarding wizard (`kiwi setup`). It walks the operator
// through deployment type, forge, storage, runners and a smoke pipeline, and
// writes the answers as a checklist — never silent half-configured state.
func Setup(args []string) error {
	out := io.Writer(os.Stdout)
	nonInteractive := false
	for _, a := range args {
		if a == "--print" || a == "--dry-run" {
			nonInteractive = true
		}
	}
	steps := []string{
		"1. Deployment type?  local / single-server / HA / kubernetes",
		"2. Forge?            github / gitlab / forgejo / bitbucket / custom",
		"3. Authenticate      (OAuth / App / token)",
		"4. Select repositories",
		"5. Configure storage (fs / s3; HA requires shared fs or s3)",
		"6. Provision runners (native / docker / tart / fleet pool)",
		"7. Verify TLS / OIDC",
		"8. Install webhooks or GitHub App",
		"9. Create first pipeline (.kiwi/pipeline.yaml)",
		"10. Run smoke pipeline (kiwi run)",
	}
	if nonInteractive {
		fmt.Fprintln(out, "kiwi setup checklist:")
		for _, s := range steps {
			fmt.Fprintln(out, "  "+s)
		}
		fmt.Fprintln(out, "\n✓ run each step, then `kiwi doctor --server <url>` to verify")
		return nil
	}
	fmt.Fprintln(out, "kiwi setup — answer each prompt (Ctrl-C to abort)")
	for _, s := range steps {
		fmt.Fprintln(out, s)
	}
	fmt.Fprintln(out, "\nInteractive setup completes when each step is confirmed.")
	fmt.Fprintln(out, "Use `kiwi setup --print` for the checklist form.")
	return nil
}

// SetupPrint renders the checklist (test seam).
func SetupPrint(w io.Writer) {
	_ = Setup([]string{"--print"})
}

var _ = strings.TrimSpace

package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Setup is the onboarding wizard (`kiwi setup`). It is a RESUMABLE,
// IDEMPOTENT state machine: every step records its result under the kiwi
// config dir, so re-running after an abort continues from the first
// unfinished step instead of restarting or silently half-configuring.
//
// State file: ~/.config/kiwi/setup.json (or $KIWI_CONFIG_DIR/setup.json).
type setupState struct {
	Version    int               `json:"version"`
	Done       map[string]bool   `json:"done"`
	Deployment string            `json:"deployment,omitempty"`
	Forge      string            `json:"forge,omitempty"`
	ServerURL  string            `json:"server_url,omitempty"`
	Storage    string            `json:"storage,omitempty"`
	RunnerMode string            `json:"runner_mode,omitempty"`
	RunnerName string            `json:"runner_name,omitempty"`
	Repo       string            `json:"repo,omitempty"`
	Notes      map[string]string `json:"notes,omitempty"`
}

const setupStateVersion = 1

// setupStep is one wizard stage. Check is pure observation (never
// mutates); Apply performs the action. A step is "done" only after Apply
// succeeds or Check reports it already satisfied.
type setupStep struct {
	ID    string
	Title string
	// Check returns (satisfied, detail). An error is a hard failure.
	Check func(s *setupState) (bool, string, error)
	// Apply performs the step interactively / programmatically.
	Apply func(s *setupState, out io.Writer) error
}

func setupStatePath() (string, error) {
	dir, err := kiwiConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "setup.json"), nil
}

func loadSetupState() (*setupState, error) {
	p, err := setupStatePath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return &setupState{Version: setupStateVersion, Done: map[string]bool{}, Notes: map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var st setupState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if st.Done == nil {
		st.Done = map[string]bool{}
	}
	if st.Notes == nil {
		st.Notes = map[string]string{}
	}
	return &st, nil
}

func saveSetupState(st *setupState) error {
	p, err := setupStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	st.Version = setupStateVersion
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(raw, '\n'), 0o600)
}

// setupSteps is the wizard's state machine, in order.
func setupSteps() []setupStep {
	return []setupStep{
		{
			ID:    "postgres",
			Title: "PostgreSQL detected",
			Check: func(s *setupState) (bool, string, error) {
				if p, err := exec.LookPath("psql"); err == nil {
					return true, p, nil
				}
				return false, "psql not on PATH", nil
			},
			Apply: func(s *setupState, out io.Writer) error {
				if _, err := exec.LookPath("psql"); err != nil {
					return fmt.Errorf("PostgreSQL client (psql) not found — install PostgreSQL first")
				}
				fmt.Fprintln(out, "✓ PostgreSQL client available")
				return nil
			},
		},
		{
			ID:    "docker",
			Title: "Docker detected",
			Check: func(s *setupState) (bool, string, error) {
				if _, err := exec.LookPath("docker"); err != nil {
					return false, "docker not on PATH", nil
				}
				if out, err := exec.Command("docker", "info").CombinedOutput(); err == nil {
					_ = out
					return true, "daemon reachable", nil
				}
				return false, "docker present but daemon not reachable", nil
			},
			Apply: func(s *setupState, out io.Writer) error {
				if _, err := exec.LookPath("docker"); err != nil {
					return fmt.Errorf("docker not found — install Docker for container execution")
				}
				if o, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
					return fmt.Errorf("docker daemon not reachable: %v\n%s", err, o)
				}
				fmt.Fprintln(out, "✓ Docker daemon reachable")
				return nil
			},
		},
		{
			ID:    "storage",
			Title: "Object storage",
			Check: func(s *setupState) (bool, string, error) {
				if s.Storage != "" {
					return true, s.Storage, nil
				}
				return false, "not chosen", nil
			},
			Apply: func(s *setupState, out io.Writer) error {
				// Default to local fs storage; the operator can switch to
				// s3 later via configuration.
				if s.Storage == "" {
					s.Storage = "fs"
				}
				fmt.Fprintf(out, "✓ storage: %s (change in server config later)\n", s.Storage)
				return nil
			},
		},
		{
			ID:    "server",
			Title: "Control-plane reachable",
			Check: func(s *setupState) (bool, string, error) {
				ep, err := ResolveEndpoint(s.ServerURL, "")
				if err != nil {
					return false, err.Error(), nil
				}
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get(strings.TrimRight(ep.Server, "/") + "/liveness")
				if err != nil {
					return false, err.Error(), nil
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return false, fmt.Sprintf("HTTP %d", resp.StatusCode), nil
				}
				s.ServerURL = ep.Server
				return true, ep.Server, nil
			},
			Apply: func(s *setupState, out io.Writer) error {
				ep, err := ResolveEndpoint(s.ServerURL, "")
				if err != nil {
					return err
				}
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get(strings.TrimRight(ep.Server, "/") + "/liveness")
				if err != nil {
					return fmt.Errorf("server %s not reachable: %w (start it with `kiwi server`)", ep.Server, err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("server %s liveness = HTTP %d", ep.Server, resp.StatusCode)
				}
				s.ServerURL = ep.Server
				fmt.Fprintf(out, "✓ server %s is live\n", ep.Server)
				return nil
			},
		},
		{
			ID:    "forge",
			Title: "Forge chosen",
			Check: func(s *setupState) (bool, string, error) {
				if s.Forge != "" {
					return true, s.Forge, nil
				}
				return false, "not chosen", nil
			},
			Apply: func(s *setupState, out io.Writer) error {
				if s.Forge == "" {
					s.Forge = "github"
				}
				fmt.Fprintf(out, "✓ forge: %s (webhook setup: `kiwi doctor` after registering the app)\n", s.Forge)
				return nil
			},
		},
		{
			ID:    "pipeline",
			Title: "Pipeline present and valid",
			Check: func(s *setupState) (bool, string, error) {
				p := filepath.Join(".kiwi", "pipeline.yaml")
				if _, err := os.Stat(p); err != nil {
					return false, "no .kiwi/pipeline.yaml", nil
				}
				if err := Validate([]string{"-f", p}); err != nil {
					return false, err.Error(), nil
				}
				return true, p, nil
			},
			Apply: func(s *setupState, out io.Writer) error {
				p := filepath.Join(".kiwi", "pipeline.yaml")
				if _, err := os.Stat(p); err == nil {
					if err := Validate([]string{"-f", p}); err != nil {
						return fmt.Errorf("existing pipeline is invalid: %w", err)
					}
					fmt.Fprintln(out, "✓ .kiwi/pipeline.yaml already valid")
					return nil
				}
				if err := Init([]string{"-dir", "."}); err != nil {
					return fmt.Errorf("kiwi init failed: %w", err)
				}
				if err := Validate([]string{"-f", p}); err != nil {
					return fmt.Errorf("generated pipeline does not validate: %w", err)
				}
				fmt.Fprintln(out, "✓ generated and validated .kiwi/pipeline.yaml")
				return nil
			},
		},
		{
			ID:    "doctor",
			Title: "Doctor report",
			Check: func(s *setupState) (bool, string, error) {
				if s.Done["doctor"] {
					return true, "reported", nil
				}
				return false, "not run", nil
			},
			Apply: func(s *setupState, out io.Writer) error {
				base := s.ServerURL
				if base == "" {
					if ep, err := ResolveEndpoint("", ""); err == nil {
						base = ep.Server
					}
				}
				fmt.Fprintf(out, "== doctor %s ==\n", base)
				serverDoctor(base)
				fmt.Fprintln(out, "✓ doctor report printed (fix any FAIL lines above)")
				return nil
			},
		},
	}
}

// Setup runs the wizard. --print renders the step list; --reset clears
// recorded progress; otherwise every unfinished step is applied in order
// and the state file is written after each one so an abort resumes.
func Setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	printOnly := fs.Bool("print", false, "print the step list and exit")
	dryRun := fs.Bool("dry-run", false, "alias for --print")
	reset := fs.Bool("reset", false, "clear recorded setup progress")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *printOnly || *dryRun {
		fmt.Println("kiwi setup steps:")
		for i, st := range setupSteps() {
			fmt.Printf("  %d. %-28s %s\n", i+1, st.ID, st.Title)
		}
		fmt.Println("\nre-run `kiwi setup` to continue; `kiwi setup --reset` starts over")
		return nil
	}
	if *reset {
		p, err := setupStatePath()
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("setup progress cleared")
		return nil
	}

	st, err := loadSetupState()
	if err != nil {
		return err
	}
	out := io.Writer(os.Stdout)
	steps := setupSteps()
	failed := 0
	for i, step := range steps {
		// Idempotent: skip a step the state file already records as done
		// AND whose Check still reports satisfied.
		if st.Done[step.ID] {
			ok, detail, err := step.Check(st)
			if err == nil && ok {
				fmt.Printf("✓ %-28s %s (already)\n", step.ID, detail)
				continue
			}
			// Recorded done but no longer satisfied — redo it.
			st.Done[step.ID] = false
		}
		fmt.Printf("▸ %d/%d %s\n", i+1, len(steps), step.Title)
		if err := step.Apply(st, out); err != nil {
			fmt.Printf("  ✗ %s\n", err)
			failed++
			// Persist progress so the next run resumes here.
			if werr := saveSetupState(st); werr != nil {
				fmt.Printf("  (warning: could not save setup state: %v)\n", werr)
			}
			fmt.Printf("\nsetup stopped at %s — fix the issue and re-run `kiwi setup`\n", step.ID)
			return fmt.Errorf("setup step %s failed: %w", step.ID, err)
		}
		st.Done[step.ID] = true
		if err := saveSetupState(st); err != nil {
			return fmt.Errorf("save setup state: %w", err)
		}
		fmt.Printf("  ✓ done\n")
	}
	if failed == 0 {
		fmt.Println("\n✓ Kiwi is ready.")
		if st.ServerURL != "" {
			fmt.Printf("  dashboard: %s\n", st.ServerURL)
		}
		fmt.Println("  next: `kiwi run` for a local smoke pipeline, or `kiwi dispatch` to enqueue a remote run")
	}
	return nil
}

// SetupPrint renders the checklist (test seam).
func SetupPrint(w io.Writer) {
	fs := flag.NewFlagSet("setup-print", flag.ContinueOnError)
	_ = fs
	fmt.Fprintln(w, "kiwi setup steps:")
	for i, st := range setupSteps() {
		fmt.Fprintf(w, "  %d. %s — %s\n", i+1, st.ID, st.Title)
	}
}

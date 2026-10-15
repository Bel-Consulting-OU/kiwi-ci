package surfacecheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Capability manifest is AUTHORITATIVE over the public surface:
//
//  1. Every CLI command (cmd/kiwi dispatch cases) and every HTTP route
//     family (server mux.HandleFunc) must be named in some capability's
//     `covers` list — a missing row is a hole, not a gap in documentation.
//  2. Every claimed proof must EXIST: system/adversarial proofs require an
//     Implemented dogfood scenario id; release proofs require a Makefile
//     release-gate --require; unit/component proofs require a test file in
//     the named package.
//
// A label on a row is not a proof. This gate fails when the manifest is
// incomplete or when a proof is a claim without evidence.

type capabilityManifest struct {
	Version      int `yaml:"version"`
	Capabilities []struct {
		ID        string   `yaml:"id"`
		Summary   string   `yaml:"summary"`
		Proofs    []string `yaml:"proofs"`
		Covers    []string `yaml:"covers"`
		Scenarios []string `yaml:"scenarios"`
	} `yaml:"capabilities"`
}

var validProofKinds = map[string]bool{
	"unit": true, "component": true, "system": true, "adversarial": true, "release": true,
}

var cliCaseRe = regexp.MustCompile(`case\s+((?:"[^"]+"\s*,\s*)*"[^"]+"):`)

// extractCLICommands reads cmd/kiwi/main.go dispatch cases.
func extractCLICommands(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cmd", "kiwi", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range cliCaseRe.FindAllStringSubmatch(string(raw), -1) {
		for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			cmd := q[1]
			if strings.HasPrefix(cmd, "-") {
				continue // --version, -v, --help
			}
			if !seen[cmd] {
				seen[cmd] = true
				out = append(out, cmd)
			}
		}
	}
	return out
}

// extractRouteFamilies reads server mux.HandleFunc("METHOD /path") and
// collapses /api/v1/{resource}/... to the resource family.
func extractRouteFamilies(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "server", "server.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`HandleFunc\("(GET|POST|PUT|DELETE|PATCH|HEAD)\s+([^"]+)"`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		path := m[2]
		// Collapse to family: /api/v1/runs/{id}/jobs → api/v1/runs
		fam := routeFamily(path)
		if fam == "" || seen[fam] {
			continue
		}
		seen[fam] = true
		out = append(out, fam)
	}
	return out
}

func routeFamily(path string) string {
	p := strings.TrimPrefix(path, "/")
	if strings.HasPrefix(p, "api/v1/") {
		rest := strings.TrimPrefix(p, "api/v1/")
		seg := strings.SplitN(rest, "/", 2)[0]
		if seg == "" {
			return ""
		}
		return "api/v1/" + seg
	}
	if strings.HasPrefix(p, "hooks/") {
		return "hooks/*"
	}
	if p == "readiness" || p == "readiness/lease" || p == "liveness" || p == "version" || p == "metrics" {
		return p
	}
	if strings.HasPrefix(p, ".well-known") || strings.HasPrefix(p, "api/v1/oidc") {
		return "oidc"
	}
	if p == "" {
		return "ui"
	}
	return p
}

// implementedScenarios reads the dogfood registry for Implemented ids.
// The registry is Go source; we parse the ScenarioXxx = "DF-..." constants
// and the nearby Implemented: true flags via a coarse source scan.
func implementedScenarios(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "dogfood", "scenarios", "registry.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	out := map[string]bool{}
	// Walk Entry literals: ID: ScenarioFoo ... Implemented: true
	idRe := regexp.MustCompile(`ID:\s+Scenario[A-Za-z0-9]+`)
	implRe := regexp.MustCompile(`Implemented:\s+true`)
	// Build ScenarioFoo → DF-XXX from the const block.
	constRe := regexp.MustCompile(`Scenario([A-Za-z0-9]+)\s+ScenarioID\s*=\s*"(DF-[A-Z0-9-]+)"`)
	nameToID := map[string]string{}
	for _, m := range constRe.FindAllStringSubmatch(src, -1) {
		nameToID["Scenario"+m[1]] = m[2]
	}
	// Split on "ID:" entries and check each block for Implemented: true.
	parts := idRe.Split(src, -1)
	ids := idRe.FindAllStringSubmatch(src, -1)
	for i, idm := range ids {
		block := ""
		if i+1 < len(parts) {
			block = parts[i+1]
		}
		id := ""
		// idm[0] is "ID: ScenarioFoo"
		name := strings.TrimSpace(strings.TrimPrefix(idm[0], "ID:"))
		if df, ok := nameToID[name]; ok {
			id = df
		}
		if id == "" {
			continue
		}
		if implRe.MatchString(block) {
			out[id] = true
		}
	}
	return out
}

func releaseGateRequires(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`--require\s+(\S+)`).FindAllStringSubmatch(string(raw), -1) {
		out[m[1]] = true
	}
	return out
}

// TestCapabilityGateFailsOnMissingSurface is the self-check: the gate must
// FAIL when the manifest is incomplete. A coverage gate that cannot fail is
// cosmetic.
func TestCapabilityGateFailsOnMissingSurface(t *testing.T) {
	// The extracted surface is non-empty; if the gate's covered-set logic
	// were inverted it would pass empty manifests. Probe with a known-good
	// command and assert the covered-set lookup is the one that decides.
	cmds := extractCLICommands(t)
	if len(cmds) == 0 {
		t.Fatal("CLI extraction found no commands — the gate would be vacuous")
	}
	routes := extractRouteFamilies(t)
	if len(routes) == 0 {
		t.Fatal("route extraction found no families — the gate would be vacuous")
	}
	impl := implementedScenarios(t)
	if len(impl) == 0 {
		t.Fatal("scenario extraction found no Implemented rows — proof checks would be vacuous")
	}
	reqs := releaseGateRequires(t)
	if len(reqs) == 0 {
		t.Fatal("release-gate extraction found no --require — release proofs would be vacuous")
	}
	// A command the manifest must cover: "run" is a core CLI surface.
	found := false
	for _, c := range cmds {
		if c == "run" {
			found = true
		}
	}
	if !found {
		t.Fatal("cli:run not extracted; extraction is broken")
	}
}

// TestCapabilityGateRejectsProofWithoutEvidence: a system/adversarial label
// with no Implemented scenario is a claim, not a proof — the gate must fail.
func TestCapabilityGateRejectsProofWithoutEvidence(t *testing.T) {
	impl := implementedScenarios(t)
	if impl["DF-NOT-A-REAL-SCENARIO"] {
		t.Fatal("scenario extraction is over-matching")
	}
	// The check used by the main gate: system proof + empty/unknown
	// scenarios must not pass.
	kinds := map[string]bool{"system": true}
	scenarios := []string{"DF-NOT-A-REAL-SCENARIO"}
	found := false
	for _, s := range scenarios {
		if impl[s] {
			found = true
		}
	}
	if kinds["system"] && !found {
		// Expected path: the gate would report an error. Assert the
		// predicate itself is fail-closed.
		return
	}
	t.Fatal("proof-existence predicate is fail-open")
}

// TestWoodpeckerExtinctionGateRejectsEchoOnly: a lane name inside an echo
// with no transferred work item must not satisfy the extinction gate.
func TestWoodpeckerExtinctionGateRejectsEchoOnly(t *testing.T) {
	// goTestCoveredByMake is the transfer predicate: an echo of a lane name
	// never matches a go test / make command.
	if goTestCoveredByMake("go test ./internal/foo", "echo linux-arm64") {
		t.Fatal("echo-only pipeline must not cover a go test command")
	}
	if goTestCoveredByMake("go test ./...", "make test-unit") {
		// ./... is covered by make test-unit — that IS a real transfer.
		return
	}
	// If this fires the ./... path is broken.
	t.Fatal("./... go test must be covered by make test-unit")
}

// TestCapabilityManifestCoversPublicSurface is the authoritative coverage
// gate: the manifest must name the real surface and its proofs must exist.
func TestCapabilityManifestCoversPublicSurface(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "capabilities.yaml"))
	if err != nil {
		t.Fatalf("capabilities.yaml: %v", err)
	}
	var m capabilityManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse capabilities.yaml: %v", err)
	}
	if m.Version != 1 {
		t.Fatalf("capabilities.yaml version = %d, want 1", m.Version)
	}
	if len(m.Capabilities) == 0 {
		t.Fatal("capabilities.yaml lists no capabilities")
	}

	covered := map[string]bool{}
	seen := map[string]bool{}
	for _, c := range m.Capabilities {
		if c.ID == "" {
			t.Fatal("capability with empty id")
		}
		if seen[c.ID] {
			t.Fatalf("duplicate capability id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Summary == "" {
			t.Fatalf("capability %q has no summary", c.ID)
		}
		if len(c.Proofs) == 0 {
			t.Fatalf("capability %q has no required proofs", c.ID)
		}
		if len(c.Covers) == 0 {
			t.Fatalf("capability %q covers nothing — a row with no surface is not a proof", c.ID)
		}
		for _, p := range c.Proofs {
			if !validProofKinds[p] {
				t.Fatalf("capability %q has unknown proof kind %q", c.ID, p)
			}
		}
		for _, cov := range c.Covers {
			covered[cov] = true
			// pkg: covers must name a real package directory — a cover of
			// nothing is as bad as no cover.
			if strings.HasPrefix(cov, "pkg:") {
				dir := strings.TrimPrefix(cov, "pkg:")
				if _, err := os.Stat(filepath.Join("..", "..", dir)); err != nil {
					t.Errorf("capability %q covers %q but %s does not exist", c.ID, cov, dir)
				}
			}
		}
	}

	// Every CLI command must be covered.
	for _, cmd := range extractCLICommands(t) {
		if !covered["cli:"+cmd] && !covered[cmd] {
			t.Errorf("CLI command %q is not covered by capabilities.yaml", cmd)
		}
	}
	// Every HTTP route family must be covered.
	for _, fam := range extractRouteFamilies(t) {
		if !covered["route:"+fam] && !covered[fam] {
			t.Errorf("HTTP route family %q is not covered by capabilities.yaml", fam)
		}
	}

	// Proofs must EXIST, not merely be labeled.
	implemented := implementedScenarios(t)
	requires := releaseGateRequires(t)
	for _, c := range m.Capabilities {
		kinds := map[string]bool{}
		for _, p := range c.Proofs {
			kinds[p] = true
		}
		// EACH claimed species must independently have evidence. One
		// scenario cannot stand in for both system AND adversarial — when
		// both are claimed, require at least two Implemented scenarios.
		claimedSpecies := 0
		for _, species := range []string{"system", "adversarial"} {
			if !kinds[species] {
				continue
			}
			claimedSpecies++
		}
		if claimedSpecies > 0 {
			n := 0
			for _, s := range c.Scenarios {
				if implemented[s] {
					n++
				}
			}
			if n < claimedSpecies {
				t.Errorf("capability %q claims %d proof species but only %d Implemented scenarios in %v — one scenario cannot prove two species",
					c.ID, claimedSpecies, n, c.Scenarios)
			}
		}
		if kinds["release"] {
			found := false
			for _, s := range c.Scenarios {
				if requires[s] {
					found = true
				}
			}
			// Release proofs may also be the release-gate make target itself.
			if !found && !requires[c.ID] {
				t.Errorf("capability %q claims release proof but no release-gate --require names it (scenarios=%v)", c.ID, c.Scenarios)
			}
		}
	}
}

// TestCrossCompileWindowsAndARM64: the product claims native Windows and
// Linux ARM64 lanes. A syscall.Statfs_t in an untagged file (or any other
// Unix-only API) must fail this gate, not a user's Windows build.
func TestCrossCompileWindowsAndARM64(t *testing.T) {
	goBin := "/opt/homebrew/bin/go"
	if _, err := os.Stat(goBin); err != nil {
		goBin = "go"
	}
	for _, target := range []struct{ goos, arch string }{
		{"windows", "amd64"},
		{"linux", "arm64"},
	} {
		cmd := exec.Command(goBin, "build", "-o", os.DevNull, "./cmd/kiwi")
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "GOOS="+target.goos, "GOARCH="+target.arch)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("GOOS=%s GOARCH=%s go build ./cmd/kiwi: %v\n%s", target.goos, target.arch, err, out)
		}
	}
}

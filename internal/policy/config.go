package policy

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Config is the organization-wide policy file loaded from disk. Every field
// is a restriction: anything absent stays at the platform default. Unknown
// keys are rejected so policy typos fail closed.
type Config struct {
	AllowedCloneHosts  []string              `yaml:"allowed_clone_hosts"`
	AllowedRunnerPools []string              `yaml:"allowed_runner_pools"`
	AllowedRegions     []string              `yaml:"allowed_regions"`
	RequireDigestPins  bool                  `yaml:"require_digest_pins"`
	RequireRootless    bool                  `yaml:"require_rootless"`
	Network            string                `yaml:"network"`
	SecretAllowlist    []string              `yaml:"secret_allowlist"`
	OIDCAudiences      []string              `yaml:"oidc_audiences"`
	EnvironmentRules   map[string]EnvRule    `yaml:"environment_rules"`
	Repositories       map[string]RepoPolicy `yaml:"repositories"`

	// OPAFile is the path to a Rego policy loaded at startup. OPA is a
	// fail-closed deny gate evaluated before admission; see CompileOPA.
	OPAFile string `yaml:"opa_file"`
	// OPARules embeds the Rego policy source inline. Mutually exclusive
	// with OPAFile.
	OPARules string `yaml:"opa_rules"`
}

// EnvRule restricts a named deployment environment.
type EnvRule struct {
	AllowedBranches   []string `yaml:"allowed_branches"`
	RequiredApprovers int      `yaml:"required_approvers"`
	Concurrency       int      `yaml:"concurrency"`
	OIDCAudiences     []string `yaml:"oidc_audiences"`
}

// RepoPolicy carries per-repository restrictions.
type RepoPolicy struct {
	AllowedCloneHosts  []string `yaml:"allowed_clone_hosts"`
	AllowedRunnerPools []string `yaml:"allowed_runner_pools"`
	AllowedRegions     []string `yaml:"allowed_regions"`
	RequireDigestPins  *bool    `yaml:"require_digest_pins"`
	RequireRootless    *bool    `yaml:"require_rootless"`
	Network            string   `yaml:"network"`
	SecretAllowlist    []string `yaml:"secret_allowlist"`
	OIDCAudiences      []string `yaml:"oidc_audiences"`
	Deployments        *bool    `yaml:"deployments"`
	CrossRepoTrigger   *bool    `yaml:"cross_repo_trigger"`
	GenerateChildGraph *bool    `yaml:"generate_child_graph"`
}

// knownConfigKeys is the strict allowlist for the policy file: unknown keys
// fail closed so a policy typo can never silently widen permissions.
var knownConfigKeys = map[string]map[string]bool{
	"": {
		"allowed_clone_hosts": true, "allowed_runner_pools": true, "allowed_regions": true,
		"require_digest_pins": true, "require_rootless": true, "network": true,
		"secret_allowlist": true, "oidc_audiences": true, "environment_rules": true,
		"repositories": true, "opa_file": true, "opa_rules": true,
	},
	"environment_rules": {
		"allowed_branches": true, "required_approvers": true, "concurrency": true,
		"oidc_audiences": true,
	},
	"repo": {
		"allowed_clone_hosts": true, "allowed_runner_pools": true, "allowed_regions": true,
		"require_digest_pins": true, "require_rootless": true, "network": true,
		"secret_allowlist": true, "oidc_audiences": true, "deployments": true,
		"cross_repo_trigger": true, "generate_child_graph": true,
	},
	"repositories": {
		"allowed_clone_hosts": true, "allowed_runner_pools": true, "allowed_regions": true,
		"require_digest_pins": true, "require_rootless": true, "network": true,
		"secret_allowlist": true, "oidc_audiences": true, "deployments": true,
		"cross_repo_trigger": true, "generate_child_graph": true,
	},
}

// validateConfigNode rejects unknown keys and non-mapping shapes with
// line/column context.
func validateConfigNode(n *yaml.Node, section string, depth int) error {
	if depth > 32 {
		return fmt.Errorf("policy: line %d: nesting too deep", n.Line)
	}
	if n.Kind == yaml.ScalarNode {
		return nil
	}
	if n.Kind == yaml.SequenceNode {
		for _, item := range n.Content {
			if err := validateConfigNode(item, section, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("policy: line %d: unexpected node", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i].Value
		// The repositories map is keyed by arbitrary repository names; its
		// values follow the repository-policy shape.
		if section == "repositories" {
			if err := validateConfigNode(n.Content[i+1], "repo", depth+1); err != nil {
				return err
			}
			continue
		}
		if _, ok := knownConfigKeys[section][key]; !ok {
			return fmt.Errorf("policy: line %d: unknown field %q", n.Content[i].Line, key)
		}
		childSection := section
		switch {
		case section == "" && (key == "environment_rules" || key == "repositories"):
			childSection = key
		case section == "environment_rules" || section == "repo":
		}
		if err := validateConfigNode(n.Content[i+1], childSection, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// Load reads and validates the policy file with strict unknown-key checking.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("policy: file exceeds 1 MiB")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if len(root.Content) == 0 {
		return &Config{}, nil
	}
	doc := root.Content[0]
	if err := validateConfigNode(doc, "", 0); err != nil {
		return nil, err
	}
	var cfg Config
	if err := doc.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Network != "" {
		if _, err := parseNetworkPolicy(c.Network); err != nil {
			return fmt.Errorf("policy: %w", err)
		}
	}
	if c.OPAFile != "" && c.OPARules != "" {
		return fmt.Errorf("policy: opa_file and opa_rules are mutually exclusive")
	}
	if c.OPAFile != "" {
		if _, err := os.ReadFile(c.OPAFile); err != nil {
			return fmt.Errorf("policy: opa_file: %w", err)
		}
	}
	for repo, rp := range c.Repositories {
		if repo == "" {
			return fmt.Errorf("policy: empty repository name")
		}
		// Every repository key is validated with the STRICT ACL
		// configuration schema, exactly like TokenStore.Load: only the
		// unambiguous canonical form "r1:<base64url(host)>:<base64url(full_name)>",
		// the bare-alias form "a1:<base64url(full_name)>" and the plain
		// owner/name alias spelling are accepted. An untagged key with three
		// or more path segments (for example "group/sub/project") is
		// AMBIGUOUS — it could be the dotless host "group" with full name
		// "sub/project", or a bare nested group path — so it is rejected
		// instead of being silently read as host/full-name, which made the
		// intended policy never apply to the named repository (fail open).
		if _, err := auth.ParseRepoGrantConfig(repo); err != nil {
			return fmt.Errorf("policy: repositories key %q: %w", repo, err)
		}
		if rp.Network != "" {
			if _, err := parseNetworkPolicy(rp.Network); err != nil {
				return fmt.Errorf("policy: repository %q: %w", repo, err)
			}
		}
	}
	return nil
}

func parseNetworkPolicy(s string) (pipeline.NetworkPolicy, error) {
	var n pipeline.NetworkPolicy
	if err := n.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Value: s}); err != nil {
		return 0, err
	}
	return n, nil
}

// CompileOPA loads and compiles the configured OPA policy into a prepared
// query, or returns nil when neither opa_file nor opa_rules is set (OPA is
// optional). An error means the policy is unusable and the caller must
// refuse to start: OPA is a deny gate and an unloadable gate is a security
// failure, never a silent pass.
func (c *Config) CompileOPA() (*OPAPolicy, error) {
	if c == nil {
		return nil, nil
	}
	if c.OPAFile != "" && c.OPARules != "" {
		return nil, fmt.Errorf("policy: opa_file and opa_rules are mutually exclusive")
	}
	src := c.OPARules
	if c.OPAFile != "" {
		data, err := os.ReadFile(c.OPAFile)
		if err != nil {
			return nil, fmt.Errorf("policy: opa_file: %w", err)
		}
		src = string(data)
	}
	if src == "" {
		return nil, nil
	}
	return LoadOPAPolicy(src)
}

// RepoPolicyFor returns the repository policy entry for a canonical
// repository identity ("<host>/<owner>/<name>") or a bare alias. Lookup is
// canonical-first; see repoPolicy for the exact alias semantics.
func (c *Config) RepoPolicyFor(repoID string) (RepoPolicy, bool) {
	return c.repoPolicy(repoID)
}

// repoPolicy resolves the policy entry for a repository identity:
//
//   - the lookup key is canonicalized first (auth.NormalizeRepoKey): for a
//     canonical identity that folds equivalent forge-host spellings —
//     GITHUB.COM, github.com., github.com:443 — onto one entry; a bare alias
//     has no host to canonicalize;
//   - the lookup key is classified by the typed positional rule
//     (auth.ParseStoredRepoID): three or more path segments are a canonical
//     identity (its first segment is the host, dotted OR dotless) and a
//     shorter value is a bare alias. There is no dot heuristic, so a dotless
//     host cannot be misclassified;
//   - every CONFIG key is parsed with the STRICT ACL configuration parser
//     (auth.ParseRepoGrantConfig), exactly like TokenStore.Load. Only the
//     explicit canonical form "r1:<base64url(host)>:<base64url(full_name)>",
//     the bare-alias form "a1:<base64url(full_name)>" and the plain
//     owner/name alias spelling are accepted. An untagged three-or-more-
//     segment key is AMBIGUOUS, so it matches NOTHING here (Config.Validate
//     rejects it at load): a programmatically constructed Config cannot
//     smuggle in an ambiguous scope and silently fail open;
//   - an exact canonical identity key wins; failing that, an explicit bare
//     alias key equal to the identity's full name is honored as an EXPLICIT
//     alias applying to every forge presenting that name (aliases are never
//     derived implicitly, and a canonical key never doubles as a bare alias);
//   - a bare lookup key (a submission with no forge host) matches an exact
//     bare alias key first, and otherwise a canonical key sharing its
//     owner/name only when exactly one DISTINCT entry exists: several
//     different entries make the lookup ambiguous and resolve to no entry
//     (fail closed) instead of depending on map iteration order.
func (c *Config) repoPolicy(repoID string) (RepoPolicy, bool) {
	if c == nil {
		return RepoPolicy{}, false
	}
	lookup, err := auth.ParseStoredRepoID(auth.NormalizeRepoKey(strings.TrimSpace(repoID)))
	if err != nil {
		return RepoPolicy{}, false
	}
	if id, ok := lookup.Identity(); ok {
		// Canonical lookup: an exact canonical policy key wins; failing
		// that, an EXPLICIT bare alias key equal to the identity's full
		// name applies to every forge presenting that name. A key that
		// itself parses as a canonical identity is NOT a bare alias and
		// never matches here.
		if rp, ok := lookupCanonicalPolicy(c.Repositories, id); ok {
			return rp, true
		}
		return lookupAliasPolicy(c.Repositories, id.FullName)
	}
	alias, _ := lookup.Alias()
	if rp, ok := lookupAliasPolicy(c.Repositories, alias.FullName); ok {
		return rp, true
	}
	return lookupCanonicalByFullNamePolicy(c.Repositories, alias.FullName)
}

// parsePolicyKey parses one Config.Repositories key with the STRICT ACL
// configuration schema (auth.ParseRepoGrantConfig), the same parser
// TokenStore.Load uses. It reports ok=false for an ambiguous legacy
// three-or-more-segment key (or any malformed key), which therefore matches
// no repository.
func parsePolicyKey(key string) (auth.RepoGrant, bool) {
	grant, err := auth.ParseRepoGrantConfig(key)
	if err != nil {
		return auth.RepoGrant{}, false
	}
	return grant, true
}

// lookupCanonicalPolicy resolves the entry whose STRICT config key is the
// canonical identity id (same host and full name). Equivalent r1: keys
// carrying DIFFERENT policies resolve to no entry (fail closed) instead of
// depending on map iteration order.
func lookupCanonicalPolicy(m map[string]RepoPolicy, id auth.RepoIdentity) (RepoPolicy, bool) {
	var match RepoPolicy
	found, ambiguous := false, false
	for key, rp := range m {
		grant, ok := parsePolicyKey(key)
		if !ok {
			continue
		}
		keyID, ok := grant.Identity()
		if !ok || keyID.Host != id.Host || keyID.FullName != id.FullName {
			continue
		}
		if !found {
			match, found = rp, true
		} else if !reflect.DeepEqual(rp, match) {
			ambiguous = true
		}
	}
	if found && !ambiguous {
		return match, true
	}
	return RepoPolicy{}, false
}

// lookupAliasPolicy resolves the entry whose STRICT config key is an explicit
// bare alias equal to fullName: the plain "owner/name" spelling or the
// explicit "a1:<base64url(full_name)>" form (a nested group path). Equivalent
// alias keys carrying DIFFERENT policies resolve to no entry (fail closed).
func lookupAliasPolicy(m map[string]RepoPolicy, fullName string) (RepoPolicy, bool) {
	var match RepoPolicy
	found, ambiguous := false, false
	for key, rp := range m {
		grant, ok := parsePolicyKey(key)
		if !ok {
			continue
		}
		alias, ok := grant.Alias()
		if !ok || alias.FullName != fullName {
			continue
		}
		if !found {
			match, found = rp, true
		} else if !reflect.DeepEqual(rp, match) {
			ambiguous = true
		}
	}
	if found && !ambiguous {
		return match, true
	}
	return RepoPolicy{}, false
}

// lookupCanonicalByFullNamePolicy resolves a BARE lookup key against
// canonical config keys sharing its owner/name: exactly one DISTINCT canonical
// entry resolves; several different entries make the lookup ambiguous and
// resolve to no entry (fail closed) instead of depending on map iteration
// order. A key that does not parse under the strict configuration schema
// matches nothing.
func lookupCanonicalByFullNamePolicy(m map[string]RepoPolicy, fullName string) (RepoPolicy, bool) {
	var match RepoPolicy
	found, ambiguous := false, false
	seen := map[string]bool{}
	for key, rp := range m {
		grant, ok := parsePolicyKey(key)
		if !ok {
			continue
		}
		id, ok := grant.Identity()
		if !ok || id.FullName != fullName {
			continue
		}
		canonical := id.ID()
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		if !found {
			match, found = rp, true
		} else if !reflect.DeepEqual(rp, match) {
			ambiguous = true
		}
	}
	if found && !ambiguous {
		return match, true
	}
	return RepoPolicy{}, false
}

// GrantsFor returns the boolean capabilities explicitly granted by the
// policy file for a canonical repository identity: Deployments,
// CrossRepoTrigger, and GenerateChildGraph are denied by the trust-domain
// defaults and can only be enabled by an explicit policy statement.
// Unspecified grants stay false.
func (c *Config) GrantsFor(repoID string) Capabilities {
	var g Capabilities
	rp, ok := c.repoPolicy(repoID)
	if !ok {
		return g
	}
	g.Deployments = rp.Deployments != nil && *rp.Deployments
	g.CrossRepoTrigger = rp.CrossRepoTrigger != nil && *rp.CrossRepoTrigger
	g.GenerateChildGraph = rp.GenerateChildGraph != nil && *rp.GenerateChildGraph
	return g
}

// CapabilitiesFor derives the capability RESTRICTION for a canonical
// repository identity ("<host>/<owner>/<name>") from org-level and
// repo-level policy. Unspecified fields pass through
// unrestricted (booleans true, Network Internet, nil sets), because the
// result is intersected with the caller's base capabilities: a zero-value
// field here would silently deny everything.
//
// List-typed restrictions follow the policy-wide nil rules exactly: nil is
// the universal set (no restriction from that level) while an explicitly
// EMPTY list is a deny-all allowlist. A disjoint org/repo intersection is
// therefore a non-nil empty list that denies everything, never an
// unrestricted pass. The returned set is authoritative (Enforced=true).
func (c *Config) CapabilitiesFor(repoID string) Capabilities {
	rest := Capabilities{
		NativeExecution:    true,
		Container:          true,
		Tart:               true,
		Network:            pipeline.NetworkPolicyInternet,
		CacheRead:          true,
		CacheWrite:         true,
		Deployments:        true,
		GenerateChildGraph: true,
		CrossRepoTrigger:   true,
		Enforced:           true,
	}
	if c.RequireRootless {
		rest.NativeExecution = false
		rest.RequireRootless = true
		rest.RequireReadOnlyRootFS = true
		rest.RequireNonRoot = true
	}
	if c.SecretAllowlist != nil {
		m := map[string]bool{}
		for _, s := range c.SecretAllowlist {
			m[s] = true
		}
		rest.Secrets = m
	}
	if c.OIDCAudiences != nil {
		rest.OIDC = cloneStrings(c.OIDCAudiences)
	}
	if c.AllowedRunnerPools != nil {
		rest.RunnerLabels = cloneStrings(c.AllowedRunnerPools)
	}
	if c.Network != "" {
		if n, err := parseNetworkPolicy(c.Network); err == nil {
			rest.Network = n
		} else {
			// Config.Validate rejects unparseable network values in files,
			// but a programmatically constructed Config must never fail
			// open: an unknown network string compiles to no egress.
			rest.Network = pipeline.NetworkPolicyNone
		}
	}
	if rp, ok := c.repoPolicy(repoID); ok {
		if rp.SecretAllowlist != nil {
			m := map[string]bool{}
			for _, s := range rp.SecretAllowlist {
				m[s] = true
			}
			rest.Secrets = intersectSecrets(rest.Secrets, m)
		}
		if rp.OIDCAudiences != nil {
			rest.OIDC = intersectStrings(rest.OIDC, rp.OIDCAudiences)
		}
		if rp.AllowedRunnerPools != nil {
			rest.RunnerLabels = intersectStrings(rest.RunnerLabels, rp.AllowedRunnerPools)
		}
		if rp.RequireRootless != nil && *rp.RequireRootless {
			rest.NativeExecution = false
			rest.RequireRootless = true
			rest.RequireReadOnlyRootFS = true
			rest.RequireNonRoot = true
		}
		if rp.Deployments != nil {
			rest.Deployments = *rp.Deployments
		}
		if rp.CrossRepoTrigger != nil {
			rest.CrossRepoTrigger = *rp.CrossRepoTrigger
		}
		if rp.GenerateChildGraph != nil {
			rest.GenerateChildGraph = *rp.GenerateChildGraph
		}
		// A repository network policy can only narrow the organization
		// policy: the effective policy is the weaker of the two, so a repo
		// level "internet" can never widen an org level "none".
		if rp.Network != "" {
			if n, err := parseNetworkPolicy(rp.Network); err == nil {
				rest.Network = minNetwork(rest.Network, n)
			} else {
				// An unparseable repo-level network value compiles to no
				// egress (fail closed), never to the org ceiling.
				rest.Network = pipeline.NetworkPolicyNone
			}
		}
	}
	return rest
}

// AllowedCloneHostsFor returns the effective clone-host allowlist for a
// canonical repository identity: the organization allowlist intersected
// with the repository allowlist, with every entry canonicalized
// (auth.CanonicalHost) so "GITHUB.COM", "github.com." and "github.com:443"
// all match the canonical host "github.com". nil means unrestricted, an
// empty non-nil list denies every host (a disjoint org/repo intersection is
// deny-all, never "no restriction"), and a non-empty list restricts to its
// entries.
func (c *Config) AllowedCloneHostsFor(repoID string) []string {
	rp, _ := c.repoPolicy(repoID)
	return canonicalHostList(intersectStrings(c.AllowedCloneHosts, rp.AllowedCloneHosts))
}

// canonicalHostList canonicalizes every entry of a host allowlist, keeping
// nil as nil. An entry that canonicalizes to "" can never match a host, so
// it stays as a deny entry (fail closed).
func canonicalHostList(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, h := range in {
		out[i] = auth.CanonicalHost(h)
	}
	return out
}

// AllowedRegionsFor returns the effective placement-region allowlist for a
// canonical repository identity with the same nil/empty rules as
// AllowedCloneHostsFor.
func (c *Config) AllowedRegionsFor(repoID string) []string {
	rp, _ := c.repoPolicy(repoID)
	return intersectStrings(c.AllowedRegions, rp.AllowedRegions)
}

// CloneHostAllowed reports whether host is admitted by the effective
// clone-host allowlist for a canonical repository identity. Comparison is
// canonical on BOTH sides: the queried host and every allowlist entry pass
// through auth.CanonicalHost, so equivalent forge-host spellings match. A
// nil allowlist is unrestricted; a non-nil allowlist admits only its
// entries, so an empty allowlist denies every host — including an
// empty/unparseable host, which fails closed.
func (c *Config) CloneHostAllowed(repoID, host string) bool {
	allowed := c.AllowedCloneHostsFor(repoID)
	if allowed == nil {
		return true
	}
	h := auth.CanonicalHost(host)
	if h == "" {
		return false
	}
	for _, entry := range allowed {
		if entry == h {
			return true
		}
	}
	return false
}

// RegionAllowed reports whether region is admitted by the effective
// placement-region allowlist for a canonical repository identity, with the
// same nil/empty rules as CloneHostAllowed.
func (c *Config) RegionAllowed(repoID, region string) bool {
	allowed := c.AllowedRegionsFor(repoID)
	if allowed == nil {
		return true
	}
	return region != "" && containsString(allowed, region)
}

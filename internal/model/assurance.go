package model

// ExecutionAssurance is the closed ladder of execution-assurance guarantees
// Kiwi can ENFORCE (or fails to enforce) for one attempt. A level states what
// the named controls are enforced to do at execution time; it is deliberately
// NOT a claim about what an arbitrary command may do inside those controls,
// and it never implies secrecy of data the job legitimately receives.
//
// Levels are cumulative up to 2 and then branch:
//
//   - Levels 1, 2 are cumulative: level 2 requires every level-1 control and
//     adds the level-2 control.
//   - Level 3 (network deny-by-default) and level 4 (all declared external
//     authority is Kiwi-mediated) are SIBLING branches above level 2: they
//     share the level-1 and level-2 controls, but neither implies the other.
//     Level 3 requires the effective network to be none. Level 4 does NOT
//     require the network to be denied: a level-4 job may hold allowed egress,
//     and unauthenticated egress is then explicitly outside Kiwi mediation
//     (documented below).
//   - Level 5 (hermetic) requires the level-4 control PLUS network denial
//     PLUS every image digest-pinned.
//
// Because 3 and 4 are siblings, the pure derivation in internal/execution
// reports the level by the audit's strength rule: a job that enforces the
// level-4 control is reported at 4 even when the network is allowed; a job
// that enforces network denial but not the level-4 control is reported at 3;
// a job that enforces both and additionally pins every image is reported at 5.
//
// The exact enforcement of each level:
//
//	0 (uncontrolled): no execution boundary is established. The job executes
//	  with whatever authority the runner process has; no filesystem isolation,
//	  no credential restriction, no network restriction are enforced by Kiwi.
//
//	1 (isolated_filesystem): the filesystem the job's steps observe is an
//	  enforced boundary: a container/Tart runtime sandbox, or a workspace whose
//	  OS-level quota is installed before the workspace is populated. It does
//	  NOT enforce anything about credentials, network or external authority.
//
//	2 (no_ambient_credentials): level 1 PLUS the job cannot obtain ambient
//	  credentials: the effective secret allowlist is explicitly empty (a
//	  non-nil, empty allowlist, verified to deny every secret) and Kiwi never
//	  inherits the runner host environment into the job. It does NOT constrain
//	  the network, OIDC issuance or deployment phases.
//
//	3 (network_denied): level 2 PLUS the effective network is none: the job
//	  has no network access at all (no egress, no service network).
//
//	4 (kiwi_mediated_authority): level 2 PLUS every declared external
//	  authority flows through a Kiwi capability: deployments are gated by the
//	  deployment capability, OIDC audiences by the OIDC allowlist, artifacts
//	  and downloads by the artifact contract/API. It does NOT require network
//	  denial: when the network is allowed, unauthenticated egress is not
//	  constrained by Kiwi (any bytes the job can send without a credential are
//	  outside mediation).
//
//	5 (hermetic): level 4 PLUS network none PLUS every declared image
//	  (container image, service images, Tart VM reference) digest-pinned, so
//	  no executable content can be resolved by tag at execution time.
type ExecutionAssurance int

const (
	// AssuranceUncontrolled is level 0: no enforced execution boundary.
	AssuranceUncontrolled ExecutionAssurance = iota
	// AssuranceIsolatedFilesystem is level 1: an enforced filesystem boundary
	// (container/Tart runtime, or a quota-enforced workspace).
	AssuranceIsolatedFilesystem
	// AssuranceNoAmbientCredentials is level 2: level 1 plus an explicitly
	// empty secret allowlist and no host-environment inheritance.
	AssuranceNoAmbientCredentials
	// AssuranceNetworkDenied is level 3: level 2 plus effective network none.
	AssuranceNetworkDenied
	// AssuranceKiwiMediatedAuthority is level 4: level 2 plus every declared
	// external authority flowing through Kiwi capabilities. The network may
	// be allowed; unauthenticated egress is then not constrained.
	AssuranceKiwiMediatedAuthority
	// AssuranceHermetic is level 5: level 4 plus network none plus all images
	// digest-pinned.
	AssuranceHermetic
)

// ExecutionAssuranceNames maps every level to its stable public name. The
// names are part of the evidence contract (see docs/evidence-contract.md) and
// must not change meaning without a schema bump.
var ExecutionAssuranceNames = map[ExecutionAssurance]string{
	AssuranceUncontrolled:          "uncontrolled",
	AssuranceIsolatedFilesystem:    "isolated_filesystem",
	AssuranceNoAmbientCredentials:  "no_ambient_credentials",
	AssuranceNetworkDenied:         "network_denied",
	AssuranceKiwiMediatedAuthority: "kiwi_mediated_authority",
	AssuranceHermetic:              "hermetic",
}

// Name returns the stable public name of the level, or "" for a value outside
// the closed set. Evidence builders must not mint names for unknown levels.
func (a ExecutionAssurance) Name() string {
	return ExecutionAssuranceNames[a]
}

// Valid reports whether a is one of the defined levels. Evidence that carries
// an out-of-range level is invalid and must be refused, never interpreted.
func (a ExecutionAssurance) Valid() bool {
	_, ok := ExecutionAssuranceNames[a]
	return ok
}

// ExternalEffectsClass is the closed classification of where a job's external
// effects (anything observable outside the execution boundary) come from. It
// is evidence, not configuration: a derivation classifies an attempt from its
// durable records and never upgrades the class.
//
//   - pure: the job has network none, no secrets (explicitly empty allowlist),
//     no OIDC id_token declaration and no deployment phases. The only effects
//     are files the control plane collects through Kiwi (artifacts, test
//     reports, snapshots, caches), which are all declared and mediated.
//   - kiwi_mediated: the job is not pure, has no ambient credentials
//     (explicitly empty secret allowlist, no host-environment inheritance,
//     no native host authority) and every declared external effect
//     (deployments, OIDC, artifacts, downloads) flows through a Kiwi
//     capability. Arbitrary command side effects that are reachable with the
//     granted authority (for example unauthenticated egress when the network
//     is allowed) are outside Kiwi mediation and are NOT constrained.
//   - opaque_external: ambient credentials are possible: the effective secret
//     allowlist is unrestricted (nil policy) or non-empty, the host
//     environment is inherited, or the job runs on the native runtime with
//     host authority. Such a job's effects cannot be attributed to declared
//     Kiwi capabilities; replay/speculation guarantees do not apply to them.
type ExternalEffectsClass string

const (
	// EffectsPure is the pure class.
	EffectsPure ExternalEffectsClass = "pure"
	// EffectsKiwiMediated is the kiwi_mediated class.
	EffectsKiwiMediated ExternalEffectsClass = "kiwi_mediated"
	// EffectsOpaqueExternal is the opaque_external class.
	EffectsOpaqueExternal ExternalEffectsClass = "opaque_external"
)

// Valid reports whether c is one of the defined classes.
func (c ExternalEffectsClass) Valid() bool {
	switch c {
	case EffectsPure, EffectsKiwiMediated, EffectsOpaqueExternal:
		return true
	default:
		return false
	}
}

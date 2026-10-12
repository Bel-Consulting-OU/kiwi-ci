package verifyapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SubjectRef names the authority subject of an obligation: the
// namespace / tenant / project / repository scope whose authorization the
// obligation carries. It is the multi-tenant identity atom of the contract.
//
// Identity rule: SubjectRef participates in the canonical obligation digest
// and in store idempotency (it is part of the obligation's JSON encoding).
// Two obligations with byte-identical content digests but different
// SubjectRefs are DIFFERENT obligations and are never interchangeable
// authority — a candidate verified under tenant A can never discharge an
// otherwise-identical obligation of tenant B.
//
// Field semantics are a STRICT prefix hierarchy and fail closed. The only
// valid shapes are:
//
//	namespace
//	namespace/tenant
//	namespace/tenant/project
//	namespace/tenant/project/repository
//
// Any hole in that chain (tenant-only, project-only, namespace/project,
// tenant/repository, namespace/repository, ...) is refused by
// ValidateHierarchy: an empty dimension is a trailing wildcard ONLY, never
// an independent one. A zero SubjectRef means "no authority subject"; it is
// NOT a global wildcard and covers nothing (global authority is only the
// explicit GlobalVerificationAdmin capability).
type SubjectRef struct {
	// AuthorityNamespace is the trust domain that owns the tenant
	// namespace (e.g. a forge host or an operator identity). Different
	// namespaces never share authorization, even when the other fields
	// coincide.
	AuthorityNamespace string `json:"authority_namespace,omitempty"`
	// TenantID is the billing/ownership tenant inside the namespace.
	TenantID string `json:"tenant_id,omitempty"`
	// ProjectID is the project (or organization) inside the tenant.
	ProjectID string `json:"project_id,omitempty"`
	// RepositoryID is the canonical repository identity inside the project
	// (e.g. "github.com/acme/service"). Finest-grained subject dimension.
	RepositoryID string `json:"repository_id,omitempty"`
}

// IsZero reports whether the reference carries no authority dimensions.
func (s SubjectRef) IsZero() bool {
	return s == SubjectRef{}
}

// Validate reports whether the reference is structurally sound. Each set
// dimension must be a non-blank identifier without control characters, so a
// crafted subject can never smuggle separators or newlines into logs,
// digests or policy keys. A zero reference is structurally valid (it means
// "no subject") but is NOT an authority scope — see ValidateHierarchy.
func (s SubjectRef) Validate() error {
	for name, v := range map[string]string{
		"authority_namespace": s.AuthorityNamespace,
		"tenant_id":           s.TenantID,
		"project_id":          s.ProjectID,
		"repository_id":       s.RepositoryID,
	} {
		if v == "" {
			continue
		}
		if strings.TrimSpace(v) != v {
			return fmt.Errorf("%w: subject_ref.%s has leading or trailing whitespace", ErrInvalid, name)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("%w: subject_ref.%s contains control character", ErrInvalid, name)
			}
		}
	}
	return nil
}

// ValidateHierarchy reports whether the reference is a valid authority
// hierarchy: a strict prefix chain starting at AuthorityNamespace. The only
// valid shapes are namespace, namespace/tenant, namespace/tenant/project
// and namespace/tenant/project/repository. A hole in the chain (tenant-only,
// project-only, namespace/project, tenant/repository, namespace/repository,
// ...) is refused because an empty middle dimension would otherwise act as
// an independent wildcard. The zero reference is NOT a valid hierarchy:
// it is not a scope, and global authority is only the explicit
// GlobalVerificationAdmin capability. Call this whenever a SubjectRef is
// loaded as a scope, attached to a principal, or validated as an
// obligation's authority subject — and defensively inside Includes.
func (s SubjectRef) ValidateHierarchy() error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.AuthorityNamespace == "" {
		return fmt.Errorf("%w: subject_ref requires authority_namespace (valid shapes are namespace[/tenant[/project[/repository]]]; the zero ref is not a scope)", ErrInvalid)
	}
	if s.ProjectID != "" && s.TenantID == "" {
		return fmt.Errorf("%w: subject_ref.project_id requires tenant_id (strict prefix hierarchy)", ErrInvalid)
	}
	if s.RepositoryID != "" && s.ProjectID == "" {
		return fmt.Errorf("%w: subject_ref.repository_id requires project_id (strict prefix hierarchy)", ErrInvalid)
	}
	return nil
}

// Equal reports exact structural equality.
func (s SubjectRef) Equal(other SubjectRef) bool { return s == other }

// Includes reports whether s covers target as an authority scope, using
// trailing wildcards ONLY: every dimension set on s must equal the
// corresponding dimension of target, and s must be a valid strict-prefix
// hierarchy whose AuthorityNamespace is set. Empty dimensions on s are
// therefore wildcards only for the trailing remainder of the chain (a
// namespace scope covers its tenants, a tenant scope covers its projects),
// never an independent hole like "namespace/–/project" spanning every
// tenant.
//
// Fail closed: an invalid hierarchy on either side covers nothing, and the
// zero ref is not a scope (it is not a global wildcard — global authority
// is only the explicit GlobalVerificationAdmin capability). This is the
// predicate Authorizer implementations use so a project-scoped principal
// can act on its repositories but never on a sibling tenant's, even when
// the repository ids collide, and a tenant-only ref can never authorize
// across namespaces.
func (s SubjectRef) Includes(target SubjectRef) bool {
	// Defense in depth: both sides must be real hierarchies before any
	// dimension comparison. This rejects malformed partial scopes
	// ({tenant:acme}, {project:payments}, namespace/project, ...) and the
	// zero ref on either side.
	if err := s.ValidateHierarchy(); err != nil {
		return false
	}
	if err := target.ValidateHierarchy(); err != nil {
		return false
	}
	if s.AuthorityNamespace != target.AuthorityNamespace {
		return false
	}
	if s.TenantID != "" && s.TenantID != target.TenantID {
		return false
	}
	if s.ProjectID != "" && s.ProjectID != target.ProjectID {
		return false
	}
	if s.RepositoryID != "" && s.RepositoryID != target.RepositoryID {
		return false
	}
	return true
}

// String renders the reference in a stable, log-safe
// "namespace/tenant/project/repository" spelling (empty dimensions collapse
// to a single dash). It is presentation only — never a parse target.
func (s SubjectRef) String() string {
	part := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	return part(s.AuthorityNamespace) + "/" + part(s.TenantID) + "/" + part(s.ProjectID) + "/" + part(s.RepositoryID)
}

// SubjectReference returns the obligation's authority subject. A nil
// SubjectRef field yields the zero reference (legacy single-tenant shape).
func (o VerificationObligation) SubjectReference() SubjectRef {
	if o.SubjectRef == nil {
		return SubjectRef{}
	}
	return *o.SubjectRef
}

// ValidateScopes checks an authority-scope configuration map (for example
// the control plane's VerificationScopes) so a malformed partial hierarchy
// can never be loaded as an authorization scope. Loading verification scopes
// from config MUST call this: every entry must pass ValidateHierarchy, and
// an empty map is valid (it just grants nothing).
func ValidateScopes(scopes map[string]SubjectRef) error {
	for name, scope := range scopes {
		if err := scope.ValidateHierarchy(); err != nil {
			return fmt.Errorf("%w: verification scope %q: %v", ErrInvalid, name, err)
		}
	}
	return nil
}

// CanonicalObligationDigest is the identity hash of one obligation: a
// lowercase hex SHA-256 over the canonical JSON encoding of the whole
// obligation, INCLUDING SubjectRef. Same content digests under a different
// subject therefore hash differently and are never interchangeable
// authority. IssuedAt and the optional freshness timestamps are normalized
// to UTC first so an instant is an instant regardless of location tags.
//
// The durable store's submit idempotency (verifystore.ObligationContentDigest)
// hashes the same encoding, so this digest is the cross-surface identity of
// an obligation.
func CanonicalObligationDigest(o VerificationObligation) (Digest, error) {
	n := o
	if n.SubjectRef != nil {
		s := *n.SubjectRef
		if err := s.ValidateHierarchy(); err != nil {
			return "", err
		}
		n.SubjectRef = &s
	}
	n.IssuedAt = utcInstant(n.IssuedAt)
	n.Freshness.NotBefore = utcInstantPtr(n.Freshness.NotBefore)
	n.Freshness.NotAfter = utcInstantPtr(n.Freshness.NotAfter)
	raw, err := json.Marshal(n)
	if err != nil {
		return "", fmt.Errorf("verifyapi: canonical obligation digest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return Digest(hex.EncodeToString(sum[:])), nil
}

// SubjectsEqual reports whether two obligations carry the same authority
// subject. Bind equality is obligation-id + content-digest equality; the
// subject is part of the obligation's identity digest, so two
// otherwise-identical obligations under different subjects are different
// obligations and an outcome bound to one never discharges the other.
func SubjectsEqual(a, b VerificationObligation) bool {
	return a.SubjectReference().Equal(b.SubjectReference())
}

func utcInstant(ts time.Time) time.Time {
	if ts.IsZero() {
		return ts
	}
	return ts.UTC()
}

func utcInstantPtr(tp *time.Time) *time.Time {
	if tp == nil {
		return nil
	}
	t := utcInstant(*tp)
	return &t
}

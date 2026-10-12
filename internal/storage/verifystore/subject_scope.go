package verifystore

import (
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// Subject/scope source-of-truth contract (P7).
//
// The durable verification tables carry two representations of every row:
//
//   - the JSONB payload, the wire-faithful serialization of the whole
//     struct, and
//   - the normalized columns (subject + authority scope on obligations;
//     authority scope on outcomes; group_id / candidate_id / started_at /
//     completed_at as the outcome index columns).
//
// Canonical source of truth: the NORMALIZED COLUMNS are authoritative for
// subject, scope, and the index dimensions. The payload is a faithful
// encoding, not the authority. The write path always emits columns and
// payload together in ONE write-all transaction, deriving both from the same
// Go value, so a successful write can never leave them diverged. The read
// path restores subject/scope onto the returned struct FROM THE COLUMNS, so
// an out-of-band payload edit cannot smuggle a different subject past
// authorization.
//
// Index columns are denormalized from the CLAIM payload (the JSONB written
// in the same statement), never from the derived verified outcome: readers
// such as CompareGroup dispatch on the claim JSON, so the index must agree
// with the claim or the two views diverge. Tests pin this (see
// subject_scope_test.go and the Postgres integration tests).

// SubjectScope is the normalized subject/scope projection of one row. The
// zero value is the legacy single-tenant shape (no authority subject).
type SubjectScope struct {
	// Subject is the obligation's opaque subject name (string field).
	Subject string
	// AuthorityNamespace / TenantID / ProjectID / RepositoryID are the
	// SubjectRef hierarchy dimensions, empty when unset.
	AuthorityNamespace string
	TenantID           string
	ProjectID          string
	RepositoryID       string
}

// ScopeOfObligation derives the normalized subject/scope projection of an
// obligation. The SubjectRef dimensions are taken from the obligation's
// authority subject; Subject is the obligation's subject name. This is the
// ONLY derivation: every write path calls it, so columns and payload are
// produced from one value and cannot drift apart by construction.
func ScopeOfObligation(o verifyapi.VerificationObligation) SubjectScope {
	ref := o.SubjectReference()
	return SubjectScope{
		Subject:            o.Subject,
		AuthorityNamespace: ref.AuthorityNamespace,
		TenantID:           ref.TenantID,
		ProjectID:          ref.ProjectID,
		RepositoryID:       ref.RepositoryID,
	}
}

// ApplyScope returns a copy of o whose subject and authority-scope fields
// are overwritten from the normalized columns. It is the read-path restore
// step: columns are authoritative, so a payload whose subject_ref disagrees
// with the columns is corrected rather than trusted.
func ApplyScope(o verifyapi.VerificationObligation, sc SubjectScope) verifyapi.VerificationObligation {
	out := o
	out.Subject = sc.Subject
	if sc.AuthorityNamespace == "" && sc.TenantID == "" && sc.ProjectID == "" && sc.RepositoryID == "" {
		out.SubjectRef = nil
		return out
	}
	out.SubjectRef = &verifyapi.SubjectRef{
		AuthorityNamespace: sc.AuthorityNamespace,
		TenantID:           sc.TenantID,
		ProjectID:          sc.ProjectID,
		RepositoryID:       sc.RepositoryID,
	}
	return out
}

// ScopeConsistent reports whether the normalized columns agree with what
// ScopeOfObligation derives from the payload. A healthy row is always
// consistent: the write-all path derives both from one value in one
// statement. An inconsistent row is evidence of out-of-band tampering (or a
// bug that bypassed the write path) and must never be silently accepted by
// a test or a repair tool.
func ScopeConsistent(o verifyapi.VerificationObligation, sc SubjectScope) bool {
	return ScopeOfObligation(o) == sc
}

// ClaimIndex is the normalized outcome index projection denormalized from
// the CLAIM payload (the JSONB that GetOutcome returns). See the file
// comment: index columns follow the claim, never the derived outcome.
type ClaimIndex struct {
	GroupID     string
	CandidateID string
	StartedAt   time.Time
	CompletedAt time.Time
}

// ClaimIndexOf derives the outcome index columns from one stored claim.
// Both the claim-only and the verified write paths call it, so the columns
// always match the claim JSON that readers decode.
func ClaimIndexOf(claim verifyapi.VerificationOutcome) ClaimIndex {
	return ClaimIndex{
		GroupID:     claim.Resources.VerificationGroupID,
		CandidateID: claim.Resources.CandidateID,
		StartedAt:   utcTime(claim.StartedAt),
		CompletedAt: utcTime(claim.CompletedAt),
	}
}

// ClaimIndexConsistent reports whether the index columns agree with what
// ClaimIndexOf derives from the claim payload. Same tamper signal as
// ScopeConsistent.
func ClaimIndexConsistent(claim verifyapi.VerificationOutcome, idx ClaimIndex) bool {
	return ClaimIndexOf(claim) == idx
}

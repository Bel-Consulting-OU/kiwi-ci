package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// ExecutionAttestationPredicateType is the predicate type of the final
// execution attestation: it binds the whole terminal attempt (both capsule
// digests, the observed runtime, every artifact/report/snapshot committed
// under the attempt's lease generation) rather than one published artifact.
// The artifact provenance predicate (PredicateType) is untouched: an
// attestation statement uses PredicateType =
// ExecutionAttestationPredicateType and carries its evidence in the
// Attestation block.
const ExecutionAttestationPredicateType = "kiwi-ci/execution-attestation/v1"

// executionAttestationSchemaVersion is the attestation block's schema
// version. It is part of the canonical digest preimage, so a future field
// change must bump it.
const executionAttestationSchemaVersion = 1

// executionAttestationDigestVersion tags the canonical hashing encoding.
const executionAttestationDigestVersion = "kiwi-ci/execution-attestation-digest/v1"

// ExecutionAttestationArtifact is one artifact committed under the attempt:
// the payload digest/size and the digest of its signed provenance statement
// (empty when the contract did not require and the upload did not publish
// one).
type ExecutionAttestationArtifact struct {
	Name             string `json:"name"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
	ProvenanceSHA256 string `json:"provenanceSha256,omitempty"`
}

// ExecutionAttestationReport is one test report delivered under the attempt.
// Name is the report's job key and SuiteDigest is the canonical digest of its
// ordered cases (see TestReportSuiteDigest).
type ExecutionAttestationReport struct {
	Name        string `json:"name"`
	SuiteDigest string `json:"suiteDigest"`
	Generation  int64  `json:"generation"`
}

// ExecutionAttestationSnapshot is one workspace snapshot record committed
// under the attempt.
type ExecutionAttestationSnapshot struct {
	ID         string `json:"id"`
	Phase      string `json:"phase,omitempty"`
	SHA256     string `json:"sha256"`
	Generation int64  `json:"generation"`
}

// ExecutionAttestation is the signed evidence block of a final execution
// attestation: the terminal attempt identity, both capsule digests, the
// executor-observed runtime, and every durable evidence record committed
// under the attempt's lease generation. The JSON field names are the stable
// wire contract consumers verify.
type ExecutionAttestation struct {
	SchemaVersion          int                            `json:"schemaVersion"`
	AttemptID              string                         `json:"attemptId"`
	CapsuleDigest          string                         `json:"capsuleDigest,omitempty"`
	ExecutionCapsuleDigest string                         `json:"executionCapsuleDigest,omitempty"`
	RunID                  string                         `json:"runId"`
	JobID                  string                         `json:"jobId"`
	JobKey                 string                         `json:"jobKey,omitempty"`
	Status                 string                         `json:"status"`
	StartedAt              *time.Time                     `json:"startedAt,omitempty"`
	FinishedAt             *time.Time                     `json:"finishedAt,omitempty"`
	RunnerIdentity         string                         `json:"runnerIdentity,omitempty"`
	ObservedRuntime        *model.ObservedRuntime         `json:"observedRuntime,omitempty"`
	Artifacts              []ExecutionAttestationArtifact `json:"artifacts,omitempty"`
	TestReports            []ExecutionAttestationReport   `json:"testReports,omitempty"`
	Snapshots              []ExecutionAttestationSnapshot `json:"snapshots,omitempty"`
	// WorkspaceRootSHA256 is the manifest root digest of the attempt's
	// pre_job workspace snapshot (the materialized starting state), when one
	// was committed.
	WorkspaceRootSHA256 string `json:"workspaceRootSha256,omitempty"`
	// MaterialRootSHA256 is the manifest root digest of the attempt's
	// post_job workspace snapshot (the outcome material), when one was
	// committed.
	MaterialRootSHA256 string `json:"materialRootSha256,omitempty"`
}

// ExecutionAttestationInput assembles the attestation statement's evidence.
// Every field is durable evidence; nothing is minted at signing time, so two
// builds of the same input are byte-identical and the envelope is
// deterministic across replicas and retries.
type ExecutionAttestationInput struct {
	RunID                  string
	JobID                  string
	JobKey                 string
	Generation             int64
	Status                 string
	StartedAt              *time.Time
	FinishedAt             *time.Time
	RunnerIdentity         string
	CapsuleDigest          string
	ExecutionCapsuleDigest string
	ObservedRuntime        *model.ObservedRuntime
	Artifacts              []ExecutionAttestationArtifact
	TestReports            []ExecutionAttestationReport
	Snapshots              []ExecutionAttestationSnapshot
	WorkspaceRootSHA256    string
	MaterialRootSHA256     string
}

// ExecutionAttestationStatement builds the signed statement of a final
// execution attestation. The subject is the attempt itself: its name is the
// canonical attempt identity and its sha256 is the canonical digest of the
// attestation block (see ExecutionAttestationDigest), so the signature binds
// exactly the evidence fields as a whole. The top-level AttemptID /
// CapsuleDigest / ExecutionCapsuleDigest fields mirror the block so the
// existing provenance constraints (attempt/capsule digests) verify an
// attestation envelope unchanged.
func ExecutionAttestationStatement(in ExecutionAttestationInput) (Statement, error) {
	att := ExecutionAttestation{
		SchemaVersion:          executionAttestationSchemaVersion,
		AttemptID:              model.AttemptID(in.JobID, in.Generation),
		CapsuleDigest:          in.CapsuleDigest,
		ExecutionCapsuleDigest: in.ExecutionCapsuleDigest,
		RunID:                  in.RunID,
		JobID:                  in.JobID,
		JobKey:                 in.JobKey,
		Status:                 in.Status,
		StartedAt:              in.StartedAt,
		FinishedAt:             in.FinishedAt,
		RunnerIdentity:         in.RunnerIdentity,
		ObservedRuntime:        in.ObservedRuntime,
		Artifacts:              append([]ExecutionAttestationArtifact(nil), in.Artifacts...),
		TestReports:            append([]ExecutionAttestationReport(nil), in.TestReports...),
		Snapshots:              append([]ExecutionAttestationSnapshot(nil), in.Snapshots...),
		WorkspaceRootSHA256:    in.WorkspaceRootSHA256,
		MaterialRootSHA256:     in.MaterialRootSHA256,
	}
	SortAttestationEvidence(&att)
	digest, err := ExecutionAttestationDigest(att)
	if err != nil {
		return Statement{}, err
	}
	return Statement{
		Type:                   StatementType,
		Subject:                []Subject{{Name: att.AttemptID, Digest: map[string]string{"sha256": digest}}},
		PredicateType:          ExecutionAttestationPredicateType,
		AttemptID:              att.AttemptID,
		CapsuleDigest:          att.CapsuleDigest,
		ExecutionCapsuleDigest: att.ExecutionCapsuleDigest,
		RunnerIdentity:         att.RunnerIdentity,
		StartTime:              att.StartedAt,
		EndTime:                att.FinishedAt,
		Attestation:            &att,
	}, nil
}

// SortAttestationEvidence orders the evidence lists so the canonical digest
// (and therefore the envelope) is independent of the order the store
// returned rows in. Artifacts sort by (name, sha256); reports by (name,
// suite digest); snapshots by (id, phase).
func SortAttestationEvidence(att *ExecutionAttestation) {
	sort.Slice(att.Artifacts, func(i, j int) bool {
		a, b := att.Artifacts[i], att.Artifacts[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.SHA256 < b.SHA256
	})
	sort.Slice(att.TestReports, func(i, j int) bool {
		a, b := att.TestReports[i], att.TestReports[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.SuiteDigest < b.SuiteDigest
	})
	sort.Slice(att.Snapshots, func(i, j int) bool {
		a, b := att.Snapshots[i], att.Snapshots[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Phase < b.Phase
	})
}

// TestReportSuiteDigest returns the canonical, length-prefixed SHA-256 of one
// test report's ordered cases. Per-delivery metadata (row id, path, created
// time, lease generation) is deliberately excluded: the digest identifies the
// SUITE CONTENT of the attempt, while the generation is carried separately in
// the attestation. Length prefixes make the encoding unambiguous.
func TestReportSuiteDigest(rep model.TestReport) string {
	h := sha256.New()
	var length [8]byte
	write := func(s string) {
		putUint64(length[:], uint64(len(s)))
		_, _ = h.Write(length[:])
		_, _ = io.WriteString(h, s)
	}
	write("kiwi-test-suite/v1")
	putUint64(length[:], uint64(len(rep.Cases)))
	_, _ = h.Write(length[:])
	for _, c := range rep.Cases {
		write(c.Name)
		write(c.Class)
		write(strconv.FormatFloat(c.Duration, 'g', -1, 64))
		write(strconv.FormatBool(c.Passed))
		write(strconv.FormatBool(c.Skipped))
		write(c.Message)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// putUint64 writes v big-endian into b (len(b) >= 8).
func putUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// ExecutionAttestationDigest returns the canonical digest that binds the
// whole attestation block: a length-prefixed encoding (the same
// `%d:%s=%d:` field style as CapsuleDigest) over every field in stable
// order, with the structured lists canonicalized as JSON (encoding/json sorts
// map keys and emits struct fields in declaration order). The digest is the
// attestation statement's subject digest, so a verifier can recompute it from
// the returned statement and detect any field tampering independently of the
// signature.
func ExecutionAttestationDigest(att ExecutionAttestation) (string, error) {
	h := sha256.New()
	field := func(label, value string) {
		fmt.Fprintf(h, "%d:%s=%d:", len(label), label, len(value))
		_, _ = io.WriteString(h, value)
	}
	putJSON := func(label string, v any) error {
		payload, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("provenance: canonicalize %s: %w", label, err)
		}
		field(label, string(payload))
		return nil
	}
	field("attestationVersion", executionAttestationDigestVersion)
	field("schemaVersion", strconv.Itoa(att.SchemaVersion))
	field("attemptId", att.AttemptID)
	field("capsuleDigest", att.CapsuleDigest)
	field("executionCapsuleDigest", att.ExecutionCapsuleDigest)
	field("runId", att.RunID)
	field("jobId", att.JobID)
	field("jobKey", att.JobKey)
	field("status", att.Status)
	field("startedAt", formatTimePtr(att.StartedAt))
	field("finishedAt", formatTimePtr(att.FinishedAt))
	field("runnerIdentity", att.RunnerIdentity)
	if err := putJSON("observedRuntime", att.ObservedRuntime); err != nil {
		return "", err
	}
	if err := putJSON("artifacts", att.Artifacts); err != nil {
		return "", err
	}
	if err := putJSON("testReports", att.TestReports); err != nil {
		return "", err
	}
	if err := putJSON("snapshots", att.Snapshots); err != nil {
		return "", err
	}
	field("workspaceRootSha256", att.WorkspaceRootSHA256)
	field("materialRootSha256", att.MaterialRootSHA256)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// formatTimePtr renders a timestamp canonically (RFC3339Nano UTC); a nil
// pointer encodes as the empty string so an absent field is distinct from
// any real timestamp.
func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// VerifyExecutionAttestation checks the internal consistency of a verified
// execution-attestation statement: the predicate type, the presence of the
// evidence block, the recomputed canonical digest against the subject digest,
// and the top-level mirror fields the constraint checks read. A signature
// proves the statement bytes; this proves the statement is a well-formed
// attestation whose subject genuinely binds its own block, so a valid
// signature over a statement whose fields disagree can never be accepted.
func VerifyExecutionAttestation(st Statement) error {
	if st.PredicateType != ExecutionAttestationPredicateType {
		return fmt.Errorf("provenance: unexpected attestation predicate type %q", st.PredicateType)
	}
	if st.Attestation == nil {
		return fmt.Errorf("provenance: execution attestation has no evidence block")
	}
	want, err := ExecutionAttestationDigest(*st.Attestation)
	if err != nil {
		return err
	}
	if len(st.Subject) == 0 || st.Subject[0].Digest["sha256"] != want {
		return fmt.Errorf("provenance: execution attestation subject does not bind its evidence block")
	}
	if st.Attestation.AttemptID != st.AttemptID {
		return fmt.Errorf("provenance: execution attestation attempt id mismatch: block %q, statement %q", st.Attestation.AttemptID, st.AttemptID)
	}
	if st.Attestation.CapsuleDigest != st.CapsuleDigest || st.Attestation.ExecutionCapsuleDigest != st.ExecutionCapsuleDigest {
		return fmt.Errorf("provenance: execution attestation capsule digests disagree with the statement")
	}
	return nil
}

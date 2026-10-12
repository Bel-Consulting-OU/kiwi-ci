package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Historical compatibility corpus (testdata/contracts) for execution
// attestation statements. The fixtures are the N-2/N-1 PRODUCER BYTES —
// canonical statement bytes as the envelope payload carries them — written
// once and immutable. The golden subject digests and statement-byte hashes
// below are frozen pins: changing the v4/v5 (or v6) encoding fails these
// tests even if the fixtures are regenerated.
const (
	goldenAttestationV4Subject      = "cf7d9443d48933407bbf8c57b6d57e3b8ab453b2579ffaa112b16a5870c30baf"
	goldenAttestationV4StatementSHA = "fd6677a7eb4a0d155ad8d3147c7260609555a0533c44abbdb7580264a14fce4c"
	goldenAttestationV5Subject      = "934a14a062f51920ffcf75c288c33dd738cebd99e10541d0a05c2e9300db7b5d"
	goldenAttestationV5StatementSHA = "ddeb86a1ff8866a6136bd84066fb4402e3ec88a455d3c39a7eb3fd912f3b8836"
	goldenAttestationV6Subject      = "0fa82889045d35d2449b469a41c9af6718726b62959ffea6b27fb8752fcea2d7"
	goldenAttestationV6StatementSHA = "8b7aa123c282f5055eb0a59bb33ba0eea7747afd6f90e9ce6d8881494ed927a1"
)

func loadContractStatement(t *testing.T, name string) (Statement, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", name))
	if err != nil {
		t.Fatalf("read contract fixture %s: %v (the historical compatibility corpus must stay committed)", name, err)
	}
	var st Statement
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("parse contract fixture %s: %v", name, err)
	}
	return st, raw
}

func assertStatementPinned(t *testing.T, name string, st Statement, raw []byte, wantSubject, wantStatementSHA string) {
	t.Helper()
	sum := sha256.Sum256(raw)
	gotStatementSHA := hex.EncodeToString(sum[:])
	if gotStatementSHA != wantStatementSHA {
		t.Fatalf("%s canonical statement bytes sha256 = %s, want frozen %s — the corpus bytes were regenerated or the serializer changed", name, gotStatementSHA, wantStatementSHA)
	}
	if len(st.Subject) == 0 {
		t.Fatalf("%s has no subject", name)
	}
	subject := st.Subject[0].Digest["sha256"]
	if subject != wantSubject {
		t.Fatalf("%s subject digest = %s, want frozen %s", name, subject, wantSubject)
	}
	got, err := ExecutionAttestationDigest(*st.Attestation)
	if err != nil {
		t.Fatalf("%s recompute digest: %v", name, err)
	}
	if got != wantSubject {
		t.Fatalf("%s HEAD digest = %s, want frozen subject %s — the canonical encoding changed", name, got, wantSubject)
	}
	if err := VerifyExecutionAttestation(st); err != nil {
		t.Fatalf("HEAD verifier refused the frozen %s statement: %v", name, err)
	}
}

// TestContractCorpusAttestationV4Frozen proves previously issued schema-v4
// statements (frozen name vocabulary, level+name only) still verify under
// HEAD and still bind their evidence block. The golden digests are pinned in
// this file, so changing the v4 encoding fails this test even if the fixture
// is regenerated.
func TestContractCorpusAttestationV4Frozen(t *testing.T) {
	st, raw := loadContractStatement(t, "attestation_v4.json")
	if st.Attestation == nil || st.Attestation.SchemaVersion != 4 {
		t.Fatalf("fixture schema = %+v, want schemaVersion 4", st.Attestation)
	}
	if st.Attestation.ExecutionAssurance.Facts != nil {
		t.Fatalf("v4 fixture must not carry a facts block: %+v", st.Attestation.ExecutionAssurance.Facts)
	}
	// Frozen v4 vocabulary.
	if st.Attestation.ExecutionAssurance.Level != 3 || st.Attestation.ExecutionAssurance.Name != "network_denied" {
		t.Fatalf("v4 fixture assurance = %+v, want level 3 network_denied under the frozen name map", st.Attestation.ExecutionAssurance)
	}
	assertStatementPinned(t, "attestation_v4.json", st, raw, goldenAttestationV4Subject, goldenAttestationV4StatementSHA)
}

// TestContractCorpusAttestationV5Frozen proves previously issued schema-v5
// statements keep their FROZEN meanings (network_mode=none derives
// network_denied from POLICY; workspace_quota_enforced means configured)
// and keep verifying under HEAD. The golden digests are pinned in this file,
// so changing the v5 encoding fails this test even if the fixture is
// regenerated.
func TestContractCorpusAttestationV5Frozen(t *testing.T) {
	st, raw := loadContractStatement(t, "attestation_v5.json")
	if st.Attestation == nil || st.Attestation.SchemaVersion != 5 {
		t.Fatalf("fixture schema = %+v, want schemaVersion 5", st.Attestation)
	}
	facts := st.Attestation.ExecutionAssurance.Facts
	if facts == nil {
		t.Fatal("v5 fixture must carry the authoritative fact vector")
	}
	if facts.NetworkAccessDenied {
		t.Fatal("v5 fixture must not claim network_access_denied (the field did not exist; denial is POLICY-only under v5)")
	}
	if !facts.WorkspaceQuotaEnforced {
		t.Fatal("v5 fixture should carry the historical workspace_quota_enforced=true (configured) claim")
	}
	if !facts.ValidForSchema(5) {
		t.Fatalf("v5 fixture facts not valid under frozen schema 5: %+v", facts)
	}
	if facts.Valid() {
		t.Fatal("the same facts must NOT be valid under v6 (unobserved workspace_quota_enforced=true is a configured claim, not a hard quota)")
	}
	derived := model.DeriveAssuranceProfileSchema(5, *facts)
	if st.Attestation.ExecutionAssurance.Level != int(derived) || st.Attestation.ExecutionAssurance.Name != derived.Name() {
		t.Fatalf("v5 fixture assurance %+v does not match frozen derivation %d %s", st.Attestation.ExecutionAssurance, int(derived), derived.Name())
	}
	assertStatementPinned(t, "attestation_v5.json", st, raw, goldenAttestationV5Subject, goldenAttestationV5StatementSHA)
}

// TestContractCorpusAttestationV6Frozen proves the current schema-v6 producer
// bytes verify under HEAD and that the subject still binds the evidence
// block. The golden digests are pinned in this file, so the current encoding
// cannot drift without failing here.
func TestContractCorpusAttestationV6Frozen(t *testing.T) {
	st, raw := loadContractStatement(t, "attestation_v6.json")
	if st.Attestation == nil || st.Attestation.SchemaVersion != ExecutionAttestationSchemaVersion() {
		t.Fatalf("fixture schema = %+v, want schemaVersion %d", st.Attestation, ExecutionAttestationSchemaVersion())
	}
	assertStatementPinned(t, "attestation_v6.json", st, raw, goldenAttestationV6Subject, goldenAttestationV6StatementSHA)
}

// TestContractCorpusAttestationsRefuseTamper is the negative half of the
// corpus contract: a frozen statement whose block is edited no longer binds
// its subject, so HEAD refuses it. This proves the fixtures are not just
// accepted blindly.
func TestContractCorpusAttestationsRefuseTamper(t *testing.T) {
	for _, name := range []string{"attestation_v4.json", "attestation_v5.json", "attestation_v6.json"} {
		st, raw := loadContractStatement(t, name)
		if err := VerifyExecutionAttestation(st); err != nil {
			t.Fatalf("%s must verify before tamper: %v", name, err)
		}
		tampered := st
		block := *st.Attestation
		block.Status = "failure"
		tampered.Attestation = &block
		if err := VerifyExecutionAttestation(tampered); err == nil {
			t.Fatalf("%s: tampered block accepted", name)
		} else if !strings.Contains(err.Error(), "does not bind its evidence block") {
			t.Fatalf("%s: unexpected tamper error %v", name, err)
		}
		_ = raw
	}
}

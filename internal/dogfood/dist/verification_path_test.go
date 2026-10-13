package dist_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/portableproof"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/verifystore"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// TestSysDFVerificationProductionPathIntegration is the PRODUCTION
// verification path over real execution evidence: one real job on a real
// topology produces a signed attestation, and that evidence — not a
// fixture — discharges a VerificationObligation through the durable
// PostgreSQL verification store (verifystore), after which the portable
// proof survives every disaster the release gate exercises.
//
// Stage chain (each stage asserts before the next begins):
//
//  1. Real execution → real evidence: trusted work completes on a real
//     runner; the signed execution attestation is fetched over the public
//     API and verifies under JWKS discovery (schema v6, bound to the job).
//  2. VerificationObligation + claim against THAT evidence: the obligation
//     pins candidate / snapshot / contract digests derived from the real
//     run, requires the structural checks and the assurance profile the
//     signed facts derive, and the claim cites the attestation as its only
//     evidence reference.
//  3. Derive (EvidenceVerifier): ProvenanceEvidenceVerifier resolves the
//     envelope, cryptographically derives the outcome (Model A — claim is a
//     proposal), and seals a DerivedVerifiedOutcome. The derived record is
//     a proven pass.
//  4. Acceptance-sign + persist to PostgreSQL (verifystore): the sealed
//     record is written to the production PostgresStore under an HMAC
//     acceptance keyring — the same durable substrate the verification
//     service uses.
//  5. Fetch VerificationProof, verify independently: the proof bundle is
//     reassembled from the durable row (obligation + claim + derived
//     outcome + evidence + acceptance record) and verified with the
//     keyring alone — no store, no server. It is then portable-signed with
//     Ed25519 (portableproof) and verified by a consumer holding only the
//     public key.
//  6. Kill control plane, restart, verify again: SIGKILL the server, start
//     a new one on the same state, reopen the verification store from a
//     fresh process perspective, and re-fetch / re-verify the same proof.
//  7. Backup → destroy → restore, verify same proof again: pg_dump, drop
//     the database, restore the dump, and the SAME portable proof still
//     verifies with the public key alone while the restored store still
//     restores the sealed record.
//  8. Rotate acceptance key, reseal, verify again: install K2 as the
//     current signing key, reseal the persisted bundle under K2, and
//     verify the resealed proof; the portable key is rotated in the
//     public-key discovery document with an operator note.
//
// PostgreSQL-gated (startPostgres): the "Integration" suffix keeps the unit
// profile from selecting it and lets the integration lane's -run Integration
// find it (surfacecheck TestPostgresGatedTestsCarryIntegrationInName).
func TestSysDFVerificationProductionPathIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("verification production path builds binaries and starts real PostgreSQL")
	}

	root := t.TempDir()
	headBin := buildKiwi(t, root)
	headSHA := canonicalSHA256File(t, headBin)
	t.Logf("verify-path: HEAD binary sha256=%s", headSHA)

	pgDSN, _ := startPostgres(t)
	pgAdmin := urlToPSQLAdmin(t, pgDSN)
	dbName := dbNameFromDSN(pgDSN)
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const runnerToken = "verifypath-runner-token"
	const adminToken = "verifypath-admin-token"

	serverPort := freeTCPPort(t)
	serverListen := fmt.Sprintf("127.0.0.1:%d", serverPort)
	serverURL := fmt.Sprintf("http://%s", serverListen)
	srv := spawnServer(t, headBin, serverListen, dataDir, pgDSN, runnerToken, adminToken)
	waitFor(t, "server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	repoURL := startGitMirror(t, root)
	workDir := filepath.Join(root, "work")
	_ = os.MkdirAll(workDir, 0o700)
	_ = spawnRunner(t, headBin, serverURL, runnerToken, "verifypath-runner", workDir, filepath.Join(root, "id"))
	waitFor(t, "runner registered", 30*time.Second, func() bool {
		return apiGet(t, serverURL, adminToken, "/api/v1/runners", &[]any{}) == 200
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// ====================================================================
	// STAGE 1 — real execution → real evidence
	// ====================================================================
	runID := canonicalTriggerTrusted(t, serverURL, adminToken, "verifypath-sched", repoURL, canonicalQuickPipeline)
	var job struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		Status          string `json:"status"`
		Error           string `json:"error"`
		LeaseGeneration int64  `json:"lease_generation"`
		StartedAt       string `json:"started_at"`
		CompletedAt     string `json:"completed_at"`
	}
	waitFor(t, "verify-path job terminal", 120*time.Second, func() bool {
		var jobs []struct {
			ID              string `json:"id"`
			Key             string `json:"key"`
			Status          string `json:"status"`
			Error           string `json:"error"`
			LeaseGeneration int64  `json:"lease_generation"`
			StartedAt       string `json:"started_at"`
			CompletedAt     string `json:"completed_at"`
		}
		if apiGet(t, serverURL, adminToken, "/api/v1/runs/"+runID+"/jobs", &jobs) != 200 {
			return false
		}
		for _, j := range jobs {
			if j.Status == "success" {
				job = j
				return true
			}
			if j.Status == "failure" {
				t.Fatalf("verify-path job failed: %q", j.Error)
			}
		}
		return false
	})

	envBytes := fetchEvidence(t, serverURL, adminToken, job.ID, job.LeaseGeneration)
	if len(envBytes) == 0 {
		t.Fatal("empty attestation envelope")
	}
	envSum := sha256.Sum256(envBytes)
	envDigest := hex.EncodeToString(envSum[:])
	st := verifyEvidence(t, serverURL, envBytes)
	if st.Attestation == nil {
		t.Fatal("verified statement carries no execution attestation")
	}
	if st.Attestation.JobID != job.ID {
		t.Fatalf("attestation job id = %q, want %q", st.Attestation.JobID, job.ID)
	}
	if st.Attestation.SchemaVersion != provenance.ExecutionAttestationSchemaVersion() {
		t.Fatalf("attestation schemaVersion = %d, want %d",
			st.Attestation.SchemaVersion, provenance.ExecutionAttestationSchemaVersion())
	}
	if st.Attestation.EvidenceRootSHA256 == "" {
		t.Fatal("attestation carries no evidence root")
	}
	t.Logf("verify-path STAGE 1 ok: run=%s job=%s attDigest=%s evidenceRoot=%s",
		runID, job.ID, envDigest, st.Attestation.EvidenceRootSHA256)

	// ====================================================================
	// STAGE 2 — VerificationObligation + claim against that evidence
	// ====================================================================
	// RequiredAssurance is DERIVED from the signed control-fact vector the
	// attestation carries — never typed in by the claim.
	facts := model.UnprovenExecutionFacts()
	if st.Attestation.ExecutionAssurance.Facts != nil {
		facts = *st.Attestation.ExecutionAssurance.Facts
	}
	assuranceSchema := st.Attestation.SchemaVersion
	if assuranceSchema == 0 {
		assuranceSchema = provenance.ExecutionAttestationSchemaVersion()
	}
	requiredAssurance := model.DeriveAssuranceProfileSchema(assuranceSchema, facts).Name()
	if requiredAssurance == "" {
		t.Fatal("derived assurance profile has no name")
	}

	// Digests pin the real run: candidate = artifact-side evidence root,
	// snapshot = the attestation envelope bytes, contract = the obligation
	// contract text. All three are sha256 of real production output.
	candidateDigest := verifyapi.Digest(strings.ToLower(st.Attestation.EvidenceRootSHA256))
	snapshotDigest := verifyapi.Digest(envDigest)
	contractSum := sha256.Sum256([]byte("verifypath-contract/v1: job-status-success+evidence-root under derived assurance"))
	contractDigest := verifyapi.Digest(hex.EncodeToString(contractSum[:]))

	ob := verifyapi.VerificationObligation{
		ObligationID:               "ob-verifypath-" + job.ID,
		Subject:                    "release-candidate/" + runID,
		ImmutableCandidateDigest:   candidateDigest,
		SourceSnapshotDigest:       snapshotDigest,
		VerificationContractDigest: contractDigest,
		RequiredChecks:             []string{verifyapi.CheckJobStatusSuccess, verifyapi.CheckEvidenceRoot},
		RequiredAssurance:          requiredAssurance,
		Freshness:                  verifyapi.FreshnessPolicy{MaxAgeSeconds: 24 * 3600},
		IssuedAt:                   time.Now().Add(-2 * time.Hour).UTC(),
	}
	// The claim proposes a pass and cites the real attestation as its only
	// evidence reference. Every authority-bearing value is derived from the
	// envelope — the claim is a proposal.
	claim := verifyapi.VerificationOutcome{
		VerificationID:   "ver-verifypath-" + job.ID,
		ObligationID:     ob.ObligationID,
		CandidateDigest:  ob.ImmutableCandidateDigest,
		SnapshotDigest:   ob.SourceSnapshotDigest,
		ContractDigest:   ob.VerificationContractDigest,
		Outcome:          verifyapi.OutcomePass,
		AssuranceProfile: requiredAssurance,
		CompletedChecks:  []string{verifyapi.CheckJobStatusSuccess, verifyapi.CheckEvidenceRoot},
		ExecutionIDs:     []string{job.ID},
		EvidenceRoot:     candidateDigest,
		Resources: verifyapi.ResourceFacts{
			RunnerClass: "native",
		},
		StartedAt:      time.Now().Add(-time.Hour).UTC(),
		CompletedAt:    time.Now().UTC(),
		ProvenanceRefs: []string{"attestation:" + job.ID},
	}
	if err := ob.Validate(); err != nil {
		t.Fatalf("obligation invalid: %v", err)
	}
	if err := claim.Validate(); err != nil {
		t.Fatalf("claim invalid: %v", err)
	}
	t.Logf("verify-path STAGE 2 ok: obligation=%s claim=%s requiredAssurance=%s candidate=%s",
		ob.ObligationID, claim.VerificationID, requiredAssurance, candidateDigest)

	// ====================================================================
	// STAGE 3 — derive verified outcome (EvidenceVerifier over real evidence)
	// ====================================================================
	evidenceByRef := map[string][]byte{"attestation:" + job.ID: envBytes}
	resolver := jwksResolver(t, serverURL)
	verifier := &verifyapi.ProvenanceEvidenceVerifier{
		Identity: "verifypath-verifier/v1",
		Resolve: func(_ context.Context, ref string) ([]byte, error) {
			b, ok := evidenceByRef[ref]
			if !ok {
				return nil, fmt.Errorf("unknown evidence ref %q", ref)
			}
			return b, nil
		},
		Keys: resolver,
	}
	derived, err := verifier.Verify(ctx, ob, claim)
	if err != nil {
		t.Fatalf("EvidenceVerifier derive: %v", err)
	}
	if !derived.Sealed() {
		t.Fatal("derived outcome is not sealed")
	}
	if !derived.ProvenPass() {
		t.Fatalf("derived outcome is not a proven pass: outcome=%s checks=%+v assurance=%s",
			derived.Outcome().Outcome, derived.Evidence().VerifiedChecks, derived.Evidence().Assurance.Name())
	}
	if derived.Evidence().JobStatus != string(model.StatusSuccess) {
		t.Fatalf("derived job status = %q, want success", derived.Evidence().JobStatus)
	}
	if derived.Evidence().EvidenceRoot != candidateDigest {
		t.Fatalf("derived evidence root = %s, want %s", derived.Evidence().EvidenceRoot, candidateDigest)
	}
	t.Logf("verify-path STAGE 3 ok: sealed proven pass ver=%s checks=%v assurance=%s",
		derived.Outcome().VerificationID, derived.Evidence().CompletedChecks, derived.Evidence().Assurance.Name())

	// ====================================================================
	// STAGE 4 — acceptance-sign + persist to PostgreSQL (verifystore)
	// ====================================================================
	k1, err := verifyapi.NewHMACAcceptanceKey("K1", []byte("verifypath-acceptance-K1-secret-32b!"))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := verifyapi.NewAcceptanceKeyring("K1", map[string]verifyapi.AcceptanceKey{"K1": k1})
	if err != nil {
		t.Fatal(err)
	}
	store, err := verifystore.NewPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatalf("open verification store: %v", err)
	}
	store = store.WithAcceptanceKeyring(ring)
	defer store.Close()

	if err := store.SubmitObligation(ctx, ob); err != nil {
		t.Fatalf("persist obligation: %v", err)
	}
	if err := store.RecordOutcome(ctx, claim); err != nil {
		t.Fatalf("persist claim: %v", err)
	}
	if err := store.RecordVerifiedOutcome(ctx, derived); err != nil {
		t.Fatalf("acceptance-sign + persist verified outcome: %v", err)
	}
	// Independent accept-side check: the store sealed under the keyring's
	// current key.
	sk, err := ring.SigningKey()
	if err != nil || sk.KeyID() != "K1" {
		t.Fatalf("store signing key = %v, %v, want K1", sk, err)
	}
	t.Logf("verify-path STAGE 4 ok: persisted obligation=%s outcome=%s under key K1", ob.ObligationID, claim.VerificationID)

	// ====================================================================
	// STAGE 5 — fetch VerificationProof, verify independently
	// ====================================================================
	proof := fetchVerificationProof(t, pgDSN, store, claim.VerificationID)
	// Independent verify: proof + keyring only. No store, no server.
	restored, err := proof.Verify(ring)
	if err != nil {
		t.Fatalf("independent proof.Verify = %v", err)
	}
	if !restored.ProvenPass() {
		t.Fatal("restored proof must be a proven pass")
	}
	// The proof's acceptance record names K1.
	if proof.Acceptance.KeyID != "K1" {
		t.Fatalf("proof acceptance key = %q, want K1", proof.Acceptance.KeyID)
	}

	// Portable signature: the consumer holds ONLY the Ed25519 public key.
	portSigner, portPub, err := portableproof.GenerateSigner("pk-verifypath-1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := portSigner.SignVerifiedProof(restored, time.Now().UTC())
	if err != nil {
		t.Fatalf("portable sign: %v", err)
	}
	if err := portableproof.Verify(signed, "pk-verifypath-1", portPub); err != nil {
		t.Fatalf("portable verify with public key only = %v", err)
	}
	// Tamper is refused (consumer cannot be fooled into accepting edits).
	tampered := signed
	rawTampered := append([]byte(nil), tampered.Proof...)
	rawTampered[len(rawTampered)/2] ^= 0x1
	tampered.Proof = rawTampered
	if err := portableproof.Verify(tampered, "pk-verifypath-1", portPub); err == nil {
		t.Fatal("tampered portable proof must not verify")
	}
	// Discovery document carries the key.
	disc := portableproof.NewDiscovery(time.Now().UTC())
	doc1, err := portableproof.PublishDoc("pk-verifypath-1", portPub, portableproof.KeyActive, time.Now().UTC(), "initial portable signing key")
	if err != nil {
		t.Fatal(err)
	}
	disc.Keys = []portableproof.PublicKeyDoc{doc1}
	if err := portableproof.VerifyWithDiscovery(signed, disc); err != nil {
		t.Fatalf("discovery verify = %v", err)
	}
	t.Logf("verify-path STAGE 5 ok: proof=%s verified independently; portable Ed25519 sig under pk-verifypath-1 (tamper rejected)", proof.Outcome.VerificationID)

	// ====================================================================
	// STAGE 6 — kill control plane, restart, verify again
	// ====================================================================
	srv.killNow()
	srv = spawnServer(t, headBin, serverListen, dataDir, pgDSN, runnerToken, adminToken)
	waitFor(t, "restarted server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	// Reopen the verification store from a fresh pool — the durable row is
	// the authority, not process memory.
	store.Close()
	store2, err := verifystore.NewPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatalf("reopen verification store after restart: %v", err)
	}
	store2 = store2.WithAcceptanceKeyring(ring)
	defer store2.Close()
	proof2 := fetchVerificationProof(t, pgDSN, store2, claim.VerificationID)
	restored2, err := proof2.Verify(ring)
	if err != nil {
		t.Fatalf("proof.Verify after control-plane restart = %v", err)
	}
	if !restored2.ProvenPass() {
		t.Fatal("restarted proof must stay a proven pass")
	}
	// The portable proof is immutable — the SAME signed envelope still
	// verifies with the public key alone after the restart.
	if err := portableproof.Verify(signed, "pk-verifypath-1", portPub); err != nil {
		t.Fatalf("portable proof after control-plane restart = %v", err)
	}
	// Fetching through the store's restore path also still yields authority.
	restored3, err := store2.QueryOutcome(ctx, claim.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome after restart = %v", err)
	}
	if !restored3.ProvenPass() {
		t.Fatal("QueryOutcome after restart must be a proven pass")
	}
	t.Logf("verify-path STAGE 6 ok: proof survives control-plane kill/restart (proof=%s)", proof2.Outcome.VerificationID)

	// ====================================================================
	// STAGE 7 — backup → destroy → restore, verify same proof again
	// ====================================================================
	store2.Close()
	backupDir := filepath.Join(root, "backup")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dumpPath := filepath.Join(backupDir, "db.dump")
	pgDump := resolvePG(t, "pg_dump")
	if out, err := exec.Command(pgDump, "--format=custom", "-f", dumpPath, pgDSN).CombinedOutput(); err != nil {
		t.Fatalf("pg_dump: %v\n%s", err, out)
	}
	srv.kill()
	psql := resolvePG(t, "psql")
	if out, err := exec.Command(psql, pgAdmin, "-c", "DROP DATABASE IF EXISTS "+dbName).CombinedOutput(); err != nil {
		t.Fatalf("drop database: %v\n%s", err, out)
	}
	if out, err := exec.Command(psql, pgAdmin, "-c", "CREATE DATABASE "+dbName).CombinedOutput(); err != nil {
		t.Fatalf("recreate database: %v\n%s", err, out)
	}
	pgRestore := resolvePG(t, "pg_restore")
	if out, err := exec.Command(pgRestore, "-d", pgDSN, dumpPath).CombinedOutput(); err != nil {
		t.Logf("pg_restore: %v\n%s", err, out)
	}

	// The SAME portable proof verifies before any process touches the
	// restored cluster — it is portable, not ambient.
	if err := portableproof.Verify(signed, "pk-verifypath-1", portPub); err != nil {
		t.Fatalf("portable proof across backup/destroy/restore = %v", err)
	}

	srv2Port := freeTCPPort(t)
	srv2 := spawnServer(t, headBin, fmt.Sprintf("127.0.0.1:%d", srv2Port), dataDir, pgDSN, runnerToken, adminToken)
	defer srv2.kill()
	serverURL2 := fmt.Sprintf("http://127.0.0.1:%d", srv2Port)
	waitFor(t, "restored server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL2 + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	store3, err := verifystore.NewPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatalf("reopen verification store after restore: %v", err)
	}
	store3 = store3.WithAcceptanceKeyring(ring)
	defer store3.Close()
	proof3 := fetchVerificationProof(t, pgDSN, store3, claim.VerificationID)
	restoredAfterDR, err := proof3.Verify(ring)
	if err != nil {
		t.Fatalf("proof.Verify after backup/destroy/restore = %v", err)
	}
	if !restoredAfterDR.ProvenPass() {
		t.Fatal("restored proof must stay a proven pass")
	}
	// Historical evidence on the restored cluster is still byte-identical
	// and still the evidence the proof cites.
	envAfter := fetchEvidence(t, serverURL2, adminToken, job.ID, job.LeaseGeneration)
	if !bytes.Equal(envBytes, envAfter) {
		t.Fatal("attestation envelope changed across backup/destroy/restore")
	}
	t.Logf("verify-path STAGE 7 ok: same proof verified across backup/destroy/restore (proof=%s)", proof3.Outcome.VerificationID)

	// ====================================================================
	// STAGE 8 — rotate acceptance key, reseal, verify again
	// ====================================================================
	k2, err := verifyapi.NewHMACAcceptanceKey("K2", []byte("verifypath-acceptance-K2-secret-32b!"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Rotate(k2); err != nil {
		t.Fatalf("rotate acceptance key: %v", err)
	}
	if sk, err := ring.SigningKey(); err != nil || sk.KeyID() != "K2" {
		t.Fatalf("signing key after rotate = %v, %v, want K2", sk, err)
	}
	// Reseal the persisted bundle under K2 (the keyring still verifies K1).
	persisted := verifyapi.PersistedVerified{
		Obligation:     proof.Obligation,
		SubmittedClaim: proof.SubmittedClaim,
		Outcome:        proof.Outcome,
		Evidence:       proof.Evidence,
		Acceptance:     proof.Acceptance,
	}
	resealedRec, resealedDerived, err := ring.ResealPersisted(persisted, time.Now().UTC())
	if err != nil {
		t.Fatalf("reseal under K2: %v", err)
	}
	if resealedRec.KeyID != "K2" {
		t.Fatalf("resealed key = %q, want K2", resealedRec.KeyID)
	}
	if !resealedDerived.ProvenPass() {
		t.Fatal("resealed record must stay a proven pass")
	}
	resealedProof := verifyapi.NewVerificationProof(verifyapi.PersistedVerified{
		Obligation:     proof.Obligation,
		SubmittedClaim: proof.SubmittedClaim,
		Outcome:        proof.Outcome,
		Evidence:       proof.Evidence,
		Acceptance:     resealedRec,
	})
	resealedVerified, err := resealedProof.Verify(ring)
	if err != nil {
		t.Fatalf("resealed proof.Verify = %v", err)
	}
	// The pre-rotation proof still verifies: K1 remains in the keyring for
	// exactly this reason.
	if _, err := proof.Verify(ring); err != nil {
		t.Fatalf("pre-rotation proof under rotated keyring = %v", err)
	}
	// Portable rotation: sign under the successor key and update the
	// discovery document with the operator note.
	portSigner2, portPub2, err := portableproof.GenerateSigner("pk-verifypath-2")
	if err != nil {
		t.Fatal(err)
	}
	signed2, err := portSigner2.SignVerifiedProof(resealedVerified, time.Now().UTC())
	if err != nil {
		t.Fatalf("portable sign under successor: %v", err)
	}
	doc2, err := portableproof.PublishDoc("pk-verifypath-2", portPub2, portableproof.KeyActive, time.Now().UTC(), "successor")
	if err != nil {
		t.Fatal(err)
	}
	disc.Keys = append(disc.Keys, doc2)
	if err := disc.Rotate("pk-verifypath-1", "pk-verifypath-2", "rotated: acceptance key rolled to K2 with the portable signing key"); err != nil {
		t.Fatalf("portable discovery rotate: %v", err)
	}
	rotatedDoc, _ := disc.Find("pk-verifypath-1")
	if rotatedDoc.Status != portableproof.KeyRotated || rotatedDoc.SupersededByKeyID != "pk-verifypath-2" {
		t.Fatalf("rotated portable key doc = %+v", rotatedDoc)
	}
	if !strings.Contains(rotatedDoc.Note, "acceptance key rolled") {
		t.Fatalf("rotation note missing: %q", rotatedDoc.Note)
	}
	// Historical portable signature still verifies under the rotated key;
	// the new one verifies under the successor.
	if err := portableproof.VerifyWithDiscovery(signed, disc); err != nil {
		t.Fatalf("pre-rotation portable proof after discovery rotate = %v", err)
	}
	if err := portableproof.VerifyWithDiscovery(signed2, disc); err != nil {
		t.Fatalf("post-rotation portable proof = %v", err)
	}
	t.Logf("verify-path STAGE 8 ok: acceptance K1→K2 resealed (resealed key=%s); portable pk-verifypath-1→2 rotated with note",
		resealedRec.KeyID)

	t.Logf("verify-path COMPLETE: run=%s job=%s proof=%s head=%s", runID, job.ID, proof.Outcome.VerificationID, headSHA)
}

// fetchVerificationProof rebuilds the immutable VerificationProof from the
// durable PostgreSQL row: the obligation and claim are read through the
// verification store contract, the derived outcome + evidence + acceptance
// record are read from the exact columns the store wrote (the acceptance
// column is the seal the store computed at persist time). The result is
// snapshotted with verifyapi.NewVerificationProof.
func fetchVerificationProof(t *testing.T, dsn string, store *verifystore.PostgresStore, verificationID string) verifyapi.VerificationProof {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	obID := ""
	{
		// Claim row names the obligation.
		claim, err := store.GetOutcome(ctx, verificationID)
		if err != nil {
			t.Fatalf("GetOutcome %s: %v", verificationID, err)
		}
		obID = claim.ObligationID
	}
	ob, err := store.GetObligation(ctx, obID)
	if err != nil {
		t.Fatalf("GetObligation %s: %v", obID, err)
	}
	restored, err := store.QueryOutcome(ctx, verificationID)
	if err != nil {
		t.Fatalf("QueryOutcome %s: %v", verificationID, err)
	}
	// The acceptance record lives in its own durable column — the seal the
	// store computed at persist time.
	acceptanceJSON := pgScalar(t, dsn,
		fmt.Sprintf(`SELECT acceptance FROM verification_outcomes WHERE verification_id = '%s'`, verificationID))
	if len(acceptanceJSON) == 0 {
		t.Fatalf("outcome %s has no durable acceptance record", verificationID)
	}
	var acceptance verifyapi.AcceptanceRecord
	if err := json.Unmarshal(acceptanceJSON, &acceptance); err != nil {
		t.Fatalf("decode acceptance record: %v", err)
	}
	if acceptance.KeyID == "" || acceptance.MAC == "" {
		t.Fatalf("acceptance record incomplete: %+v", acceptance)
	}
	return verifyapi.NewVerificationProof(verifyapi.PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: restored.SubmittedClaim(),
		Outcome:        restored.Outcome(),
		Evidence:       restored.Evidence(),
		Acceptance:     acceptance,
	})
}

// pgScalar runs one scalar SQL query through psql and returns the trimmed
// cell. Used to read the durable acceptance column the store wrote.
func pgScalar(t *testing.T, dsn, query string) []byte {
	t.Helper()
	psql := resolvePG(t, "psql")
	cmd := exec.Command(psql, dsn, "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", query)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("psql %s: %v\n%s", query, err, out)
	}
	return []byte(strings.TrimSpace(string(out)))
}

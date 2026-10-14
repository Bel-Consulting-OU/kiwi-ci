package verifyapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Historical acceptance fixtures (P2).
//
// The important compatibility question is not "can contemporary code
// construct a V2-like object?" but "can a binary today consume the exact
// bytes an old writer emitted?". These fixtures are FROZEN serialized
// PersistedVerified rows — one per acceptance version — written once and
// restored from disk. The reader must not regenerate them from current
// structures; the generator is gated behind KIWI_REGENERATE_FIXTURES=1 and
// exists only to mint the original bytes.
//
// Layout: testdata/acceptance/v{N}.json. Key material is a fixed test secret
// (not a production key) recorded here so restore can verify the MACs.

const (
	historicalFixtureKeyID  = "acc-hist-fixture"
	historicalFixtureSecret = "historical-fixture-key-secret-32b!"
	historicalFixtureAt     = "2026-01-02T03:06:00Z"
)

// historicalFixturePath is the on-disk home of the frozen acceptance rows.
func historicalFixturePath(t *testing.T, version int) string {
	t.Helper()
	return filepath.Join("testdata", "acceptance", "v"+itoa(version)+".json")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// historicalSealed builds the deterministic sealed record every fixture
// version is minted over: same obligation, claim, outcome and evidence, so
// the only variable across vN.json is the acceptance version and its digest
// / MAC encodings. The seal is produced by the production FuncEvidenceVerifier
// path so the frozen bytes carry a real verifier-derived evidence shape.
func historicalSealed(t *testing.T) (VerificationObligation, DerivedVerifiedOutcome) {
	t.Helper()
	ob := VerificationObligation{
		ObligationID:               "ob-historical",
		Subject:                    "cand-historical",
		ImmutableCandidateDigest:   mustDigest(t, "candidate"),
		SourceSnapshotDigest:       mustDigest(t, "snapshot"),
		VerificationContractDigest: mustDigest(t, "contract"),
		RequiredChecks:             []string{CheckJobStatusSuccess, CheckEvidenceRoot},
		RequiredAssurance:          "uncontrolled",
		Freshness:                  FreshnessPolicy{MaxAgeSeconds: 3600},
		IssuedAt:                   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	claim := VerificationOutcome{
		VerificationID:   "ver-historical",
		ObligationID:     ob.ObligationID,
		CandidateDigest:  ob.ImmutableCandidateDigest,
		SnapshotDigest:   ob.SourceSnapshotDigest,
		ContractDigest:   ob.VerificationContractDigest,
		Outcome:          OutcomePass,
		AssuranceProfile: ob.RequiredAssurance,
		CompletedChecks:  append([]string(nil), ob.RequiredChecks...),
		ExecutionIDs:     []string{"exec-1"},
		EvidenceRoot:     mustDigest(t, "historical-root"),
		ProvenanceRefs:   []string{"att-1"},
		Resources: ResourceFacts{
			QueueLatencyNS:     1_000_000,
			ExecutionLatencyNS: 5_000_000_000,
			WallTimeNS:         5_200_000_000,
			CPUTimeNS:          4_800_000_000,
			PeakMemoryBytes:    64 << 20,
			IOBytes:            1 << 20,
			CacheHits:          3,
			CacheMisses:        1,
			RunnerClass:        "standard",
			RetryCount:         0,
		},
		StartedAt:   ob.IssuedAt.Add(time.Second),
		CompletedAt: ob.IssuedAt.Add(10 * time.Second),
	}
	// Deterministic resolver: every historical fixture restores from the same
	// attestation material, so version encodings are the only variable.
	clock := func() time.Time { return time.Date(2026, 1, 2, 3, 4, 16, 0, time.UTC) }
	f := &FuncEvidenceVerifier{
		Identity: "historical-fixture-verifier/v1",
		Clock:    clock,
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "historical-root"),
				AttestationDigest: mustDigest(t, "historical-att"),
				Status:            "success",
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				Attested:          trustedWindow(),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("seal historical fixture: %v", err)
	}
	if !sealed.ProvenPass() {
		t.Fatal("historical fixture must seal as a proven pass")
	}
	return ob, sealed
}

// signHistoricalRecord mints an acceptance record at the requested version
// and returns the full PersistedVerified row. V1 uses the v1 digests and MAC
// form; V2 uses obligation/v2 + evidence/v2; V3 adds demand/v1; V4 uses
// evidence/v3; V5 is the current Accept() write path.
func signHistoricalRecord(t *testing.T, version int, ob VerificationObligation, sealed DerivedVerifiedOutcome, key AcceptanceKey) PersistedVerified {
	t.Helper()
	at := time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC)
	claim := sealed.SubmittedClaim()
	out := sealed.Outcome()
	ev := sealed.Evidence()

	var rec AcceptanceRecord
	switch version {
	case AcceptanceVersion:
		obDig, err := obligationDigest(ob)
		if err != nil {
			t.Fatal(err)
		}
		outDig, err := outcomeDigest(out)
		if err != nil {
			t.Fatal(err)
		}
		evDig, err := evidenceDigest(ev)
		if err != nil {
			t.Fatal(err)
		}
		rec = AcceptanceRecord{
			AcceptanceVersion:      AcceptanceVersion,
			ObligationDigest:       obDig,
			OutcomeDigest:          outDig,
			VerifiedEvidenceDigest: evDig,
			Algorithm:              key.Algorithm(),
			VerifiedAt:             at,
			KeyID:                  key.KeyID(),
		}
	case AcceptanceVersionV2, AcceptanceVersionV3, AcceptanceVersionV4:
		obDig, err := obligationDigestV2(ob)
		if err != nil {
			t.Fatal(err)
		}
		if version >= AcceptanceVersionV3 {
			obDig, err = obligationDigestV3(ob)
			if err != nil {
				t.Fatal(err)
			}
		}
		claimDig, err := submittedClaimDigest(claim)
		if err != nil {
			t.Fatal(err)
		}
		outDig, err := outcomeDigestV2(out)
		if err != nil {
			t.Fatal(err)
		}
		var evDig Digest
		if version == AcceptanceVersionV2 || version == AcceptanceVersionV3 {
			evDig, err = evidenceDigestV2(ev)
		} else {
			evDig, err = evidenceDigestV3(ev)
		}
		if err != nil {
			t.Fatal(err)
		}
		rec = AcceptanceRecord{
			AcceptanceVersion:      version,
			SchemaVersion:          SchemaVersion,
			ObligationDigest:       obDig,
			SubmittedClaimDigest:   claimDig,
			OutcomeDigest:          outDig,
			VerifiedEvidenceDigest: evDig,
			Subject:                ob.Subject,
			Algorithm:              key.Algorithm(),
			VerifiedAt:             at,
			KeyID:                  key.KeyID(),
		}
		if version >= AcceptanceVersionV3 {
			demandDig, err := effectiveVerificationDemandDigestV1(ob, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec.DemandDigest = demandDig
		}
		if ob.SubjectRef != nil {
			s := *ob.SubjectRef
			rec.SubjectRef = &s
		}
	case AcceptanceVersionV5:
		var err error
		rec, err = Accept(ob, sealed, key, at)
		if err != nil {
			t.Fatalf("Accept v5: %v", err)
		}
	default:
		t.Fatalf("unsupported fixture version %d", version)
	}

	if version != AcceptanceVersionV5 {
		payload, err := acceptancePayload(rec)
		if err != nil {
			t.Fatal(err)
		}
		mac, err := key.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		rec.MAC = mac
	}
	return PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: claim,
		Outcome:        out,
		Evidence:       ev,
		Acceptance:     rec,
	}
}

// TestGenerateHistoricalAcceptanceFixtures mints the frozen vN.json rows.
// It is a no-op unless KIWI_REGENERATE_FIXTURES=1 — normal test runs only
// ever READ the fixtures (see TestHistoricalAcceptanceFixturesFromDisk), so
// the restore contract cannot silently follow a refactor of current
// structures.
func TestGenerateHistoricalAcceptanceFixtures(t *testing.T) {
	if os.Getenv("KIWI_REGENERATE_FIXTURES") != "1" {
		t.Skip("set KIWI_REGENERATE_FIXTURES=1 to mint historical acceptance fixtures")
	}
	key, err := NewHMACAcceptanceKey(historicalFixtureKeyID, []byte(historicalFixtureSecret))
	if err != nil {
		t.Fatal(err)
	}
	ob, sealed := historicalSealed(t)
	dir := filepath.Join("testdata", "acceptance")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{
		AcceptanceVersion,
		AcceptanceVersionV2,
		AcceptanceVersionV3,
		AcceptanceVersionV4,
		AcceptanceVersionV5,
	} {
		persisted := signHistoricalRecord(t, version, ob, sealed, key)
		raw, err := json.MarshalIndent(persisted, "", "  ")
		if err != nil {
			t.Fatalf("marshal v%d: %v", version, err)
		}
		raw = append(raw, '\n')
		path := historicalFixturePath(t, version)
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(raw))
	}
}

// TestHistoricalAcceptanceFixturesFromDisk restores every frozen vN.json and
// asserts the restore contract. Bytes come from disk only — the test never
// rebuilds a record from current Go structures to "check compatibility".
func TestHistoricalAcceptanceFixturesFromDisk(t *testing.T) {
	key, err := NewHMACAcceptanceKey(historicalFixtureKeyID, []byte(historicalFixtureSecret))
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, historicalFixtureAt)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		version     int
		provenPass  bool
		wantSubject string
		wantExecIDs []string
	}{
		{version: AcceptanceVersion, provenPass: true, wantSubject: "cand-historical", wantExecIDs: []string{"exec-1"}},
		{version: AcceptanceVersionV2, provenPass: true, wantSubject: "cand-historical", wantExecIDs: []string{"exec-1"}},
		{version: AcceptanceVersionV3, provenPass: true, wantSubject: "cand-historical", wantExecIDs: []string{"exec-1"}},
		{version: AcceptanceVersionV4, provenPass: true, wantSubject: "cand-historical", wantExecIDs: []string{"exec-1"}},
		{version: AcceptanceVersionV5, provenPass: true, wantSubject: "cand-historical", wantExecIDs: []string{"exec-1"}},
	} {
		t.Run("v"+itoa(tc.version), func(t *testing.T) {
			path := historicalFixturePath(t, tc.version)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture (run KIWI_REGENERATE_FIXTURES=1 once to mint): %v", err)
			}
			var persisted PersistedVerified
			if err := json.Unmarshal(raw, &persisted); err != nil {
				t.Fatalf("unmarshal fixture: %v", err)
			}

			// The fixture bytes must be a complete historical row.
			if persisted.Acceptance.AcceptanceVersion != tc.version {
				t.Fatalf("fixture acceptance_version = %d, want %d", persisted.Acceptance.AcceptanceVersion, tc.version)
			}
			if persisted.Acceptance.KeyID != historicalFixtureKeyID {
				t.Fatalf("fixture key id = %q, want %q", persisted.Acceptance.KeyID, historicalFixtureKeyID)
			}
			if !persisted.Acceptance.VerifiedAt.Equal(at) {
				t.Fatalf("fixture verified_at = %v, want %v", persisted.Acceptance.VerifiedAt, at)
			}

			restored, err := RestoreVerifiedOutcome(persisted, key)
			if err != nil {
				t.Fatalf("restore v%d from disk = %v, want success", tc.version, err)
			}
			if restored.ProvenPass() != tc.provenPass {
				t.Fatalf("ProvenPass = %v, want %v", restored.ProvenPass(), tc.provenPass)
			}
			if persisted.Obligation.Subject != tc.wantSubject {
				t.Fatalf("fixture Subject = %q, want %q", persisted.Obligation.Subject, tc.wantSubject)
			}
			out := restored.Outcome()
			if out.ObligationID != "ob-historical" {
				t.Fatalf("ObligationID = %q, want ob-historical", out.ObligationID)
			}
			if out.VerificationID != "ver-historical" {
				t.Fatalf("VerificationID = %q, want ver-historical", out.VerificationID)
			}
			if !equalStringSlices(out.ExecutionIDs, tc.wantExecIDs) {
				t.Fatalf("ExecutionIDs = %v, want %v", out.ExecutionIDs, tc.wantExecIDs)
			}
			// Authority is re-derived, never trusted from the row: the sealed
			// checks must be the verifier-derived set.
			ev := restored.Evidence()
			if len(ev.VerifiedChecks) != 2 {
				t.Fatalf("VerifiedChecks = %v, want 2 entries", ev.VerifiedChecks)
			}

			// Tamper the frozen bytes: restore must refuse. This is the
			// other half of the contract — old bytes restore, edited bytes
			// never do.
			var forged PersistedVerified
			if err := json.Unmarshal(raw, &forged); err != nil {
				t.Fatal(err)
			}
			forged.Obligation.Subject = "forged-subject"
			if _, err := RestoreVerifiedOutcome(forged, key); err == nil {
				t.Fatal("forged fixture must not restore")
			} else if !errors.Is(err, ErrAcceptance) {
				t.Fatalf("forged fixture error = %v, want ErrAcceptance", err)
			}

			var forgedRec PersistedVerified
			if err := json.Unmarshal(raw, &forgedRec); err != nil {
				t.Fatal(err)
			}
			forgedRec.Acceptance.ObligationDigest = mustDigest(t, "forged")
			if _, err := RestoreVerifiedOutcome(forgedRec, key); err == nil {
				t.Fatal("forged acceptance record must not restore")
			} else if !errors.Is(err, ErrAcceptance) {
				t.Fatalf("forged record error = %v, want ErrAcceptance", err)
			}
		})
	}
}

// TestHistoricalFixturesAreDistinctEncodings: the frozen rows must actually
// exercise different acceptance encodings — if a generator bug wrote the same
// version into every file the compatibility claim would be empty.
func TestHistoricalFixturesAreDistinctEncodings(t *testing.T) {
	key, err := NewHMACAcceptanceKey(historicalFixtureKeyID, []byte(historicalFixtureSecret))
	if err != nil {
		t.Fatal(err)
	}
	macs := map[string]int{}
	versions := map[int]int{}
	for _, version := range []int{
		AcceptanceVersion,
		AcceptanceVersionV2,
		AcceptanceVersionV3,
		AcceptanceVersionV4,
		AcceptanceVersionV5,
	} {
		raw, err := os.ReadFile(historicalFixturePath(t, version))
		if err != nil {
			t.Fatalf("read v%d (run KIWI_REGENERATE_FIXTURES=1 once): %v", version, err)
		}
		var persisted PersistedVerified
		if err := json.Unmarshal(raw, &persisted); err != nil {
			t.Fatal(err)
		}
		if persisted.Acceptance.AcceptanceVersion != version {
			t.Fatalf("v%d file holds acceptance_version %d", version, persisted.Acceptance.AcceptanceVersion)
		}
		versions[persisted.Acceptance.AcceptanceVersion]++
		macs[persisted.Acceptance.MAC]++
		// Every fixture must restore under the shared key.
		if _, err := RestoreVerifiedOutcome(persisted, key); err != nil {
			t.Fatalf("v%d restore: %v", version, err)
		}
	}
	if len(macs) != 5 {
		t.Fatalf("expected 5 distinct MACs across fixtures, got %d", len(macs))
	}
	if len(versions) != 5 {
		t.Fatalf("expected 5 distinct acceptance versions, got %v", versions)
	}
}

// TestHistoricalFixtureV1OmitsClaimBinding: the v1 MAC form does not commit
// the submitted claim digest. Restoring a v1 row whose claim column was
// swapped must still go through sealDerivedOutcome's identity rule — the
// claim cannot assume a different verification identity. This is a live
// property of the frozen v1 bytes, not a reconstruction.
func TestHistoricalFixtureV1OmitsClaimBinding(t *testing.T) {
	key, err := NewHMACAcceptanceKey(historicalFixtureKeyID, []byte(historicalFixtureSecret))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(historicalFixturePath(t, AcceptanceVersion))
	if err != nil {
		t.Fatalf("read v1 fixture: %v", err)
	}
	var persisted PersistedVerified
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Acceptance.SubmittedClaimDigest != "" {
		t.Fatal("v1 acceptance record must not carry a submitted claim digest")
	}
	if persisted.Acceptance.DemandDigest != "" {
		t.Fatal("v1 acceptance record must not carry a demand digest")
	}

	// Swap the claim identity: sealDerivedOutcome refuses even though the
	// v1 MAC does not cover the claim column.
	forged := persisted
	forged.SubmittedClaim = persisted.SubmittedClaim
	forged.SubmittedClaim.VerificationID = "ver-forged"
	if _, err := RestoreVerifiedOutcome(forged, key); err == nil {
		t.Fatal("v1 row with swapped claim identity must not restore")
	} else if !errors.Is(err, ErrUnverified) && !errors.Is(err, ErrAcceptance) {
		t.Fatalf("swapped v1 claim error = %v, want ErrUnverified or ErrAcceptance", err)
	}
}

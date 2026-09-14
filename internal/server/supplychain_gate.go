package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/supplychain"
)

// SBOM and Sigstore attestation wiring. The runner uploads these as
// conventional sibling names of the artifact: `<name>.sbom` and
// `<name>.sigstore`. The server validates them against the job's artifact
// contract and gates the artifact payload itself, so a required-but-missing
// attestation can never ship.

const maxSBOMBytes = 8 << 20

// artifactSidecarPath is the deterministic sidecar location next to a job's
// artifacts: <dir>/<base>.<kind>.json.
func artifactSidecarPath(dir, base, kind string) string {
	return filepath.Join(dir, cleanBlobName(base)+"."+kind+".json")
}

// validateSBOMDocument checks the payload parses as JSON in the declared
// format and carries the format's required identity fields.
func validateSBOMDocument(b []byte, format supplychain.SBOMFormat) error {
	if len(b) == 0 || len(b) > maxSBOMBytes {
		return errors.New("sbom payload is empty or exceeds 8 MiB")
	}
	if !json.Valid(b) {
		return errors.New("sbom payload is not valid JSON")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	switch format {
	case supplychain.SBOMSPDX:
		if v, _ := m["spdxVersion"].(string); v != "SPDX-2.3" {
			return errors.New("spdx-json document must declare spdxVersion \"SPDX-2.3\"")
		}
		if id, _ := m["SPDXID"].(string); id == "" {
			return errors.New("spdx-json document must declare an SPDXID")
		}
	case supplychain.SBOMCycloneDX:
		if v, _ := m["bomFormat"].(string); v != "CycloneDX" {
			return errors.New("cyclonedx-json document must declare bomFormat \"CycloneDX\"")
		}
		if v, _ := m["specVersion"].(string); v != "1.5" {
			return errors.New("cyclonedx-json document must declare specVersion \"1.5\"")
		}
	default:
		return errors.New("unknown sbom format")
	}
	return nil
}

// sigstoreVerifyConfig derives the verification expectations for an
// artifact from its frozen contract declaration.
func sigstoreVerifyConfig(c storage.ArtifactContract) supplychain.SigstoreVerifyConfig {
	return supplychain.SigstoreVerifyConfig{
		ExpectedIssuer:   c.SigstoreIssuer,
		ExpectedIdentity: c.SigstoreIdentity,
	}
}

// uploadSBOM accepts a `<name>.sbom` upload: it must correspond to a
// declared artifact whose contract declares an sbom format, and the payload
// must parse as that format. FS dev mode stores the document as a local
// sidecar next to the job's artifacts; DB mode stores the bytes in the
// shared CAS store and keeps only the digest (the record and the payload
// upload gate resolve it through CAS — no node-local sidecar files).
func (s *Server) uploadSBOM(w http.ResponseWriter, r *http.Request, j model.Job, c storage.ArtifactContract, base string) {
	start := time.Now()
	if strings.TrimSpace(c.SBOM) == "" {
		s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sbom upload without declared sbom format", map[string]string{"name": base})
		http.Error(w, "artifact contract does not declare an sbom format", http.StatusUnprocessableEntity)
		return
	}
	format, err := supplychain.ParseSBOMFormat(c.SBOM)
	if err != nil {
		s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "invalid declared sbom format", map[string]string{"name": base, "format": c.SBOM})
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSBOMBytes))
	if err != nil {
		http.Error(w, "invalid sbom payload", http.StatusBadRequest)
		return
	}
	if err := validateSBOMDocument(body, format); err != nil {
		s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sbom payload rejected", map[string]string{"name": base, "error": err.Error()})
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	sum := sha256Hex(body)
	if s.DB != nil {
		if s.CAS == nil {
			http.Error(w, "sidecar storage requires a blob store", http.StatusServiceUnavailable)
			return
		}
		if _, perr := s.CAS.Put(r.Context(), bytes.NewReader(body)); perr != nil {
			http.Error(w, perr.Error(), 500)
			return
		}
		s.rememberPendingSidecar(j, base, "sbom", sum)
		s.attachSidecarToArtifact(r.Context(), j, base, "sbom", "cas:"+sum, sum)
		s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
		writeJSON(w, http.StatusCreated, map[string]any{"name": base + sbomSuffix, "sha256": sum, "format": string(format)})
		return
	}
	dir := filepath.Join(s.store.Root, "artifacts", j.RunID, j.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sidecar := artifactSidecarPath(dir, base, "sbom")
	if err := writeFileAtomic(sidecar, body, 0o600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.attachSidecarToArtifact(r.Context(), j, base, "sbom", sidecar, sum)
	s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
	writeJSON(w, http.StatusCreated, map[string]any{"name": base + sbomSuffix, "sha256": sum, "format": string(format)})
}

// uploadSigstore accepts a `<name>.sigstore` Sigstore bundle upload. When
// the artifact payload already exists the bundle is verified immediately
// against its digest; otherwise it is stored and the artifact upload gate
// verifies it. A bundle that fails verification is rejected (422) and
// never stored. DB mode stores the bytes in CAS; fs mode keeps the local
// sidecar file.
func (s *Server) uploadSigstore(w http.ResponseWriter, r *http.Request, j model.Job, c storage.ArtifactContract, base string) {
	if !c.SigstoreRequired && c.SigstoreIssuer == "" && c.SigstoreIdentity == "" {
		s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sigstore upload without declared sigstore gate", map[string]string{"name": base})
		http.Error(w, "artifact contract does not declare a sigstore gate", http.StatusUnprocessableEntity)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBlobBytes))
	if err != nil {
		http.Error(w, "invalid sigstore bundle", http.StatusBadRequest)
		return
	}
	cfg := sigstoreVerifyConfig(c)
	if recs, lerr := s.findArtifactByJobName(r.Context(), j.RunID, j.ID, base); lerr == nil && len(recs) > 0 {
		latest := recs[len(recs)-1]
		if err := supplychain.VerifySigstoreBundle(body, latest.SHA256, cfg); err != nil {
			s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle verification failed", map[string]string{"name": base, "error": err.Error()})
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	sum := sha256Hex(body)
	if s.DB != nil {
		if s.CAS == nil {
			http.Error(w, "sidecar storage requires a blob store", http.StatusServiceUnavailable)
			return
		}
		if _, perr := s.CAS.Put(r.Context(), bytes.NewReader(body)); perr != nil {
			http.Error(w, perr.Error(), 500)
			return
		}
		s.rememberPendingSidecar(j, base, "sigstore", sum)
		s.attachSidecarToArtifact(r.Context(), j, base, "sigstore", "cas:"+sum, sum)
		s.auditLocked("artifact.sigstore_stored", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle stored", map[string]string{"name": base, "sha256": sum})
		writeJSON(w, http.StatusCreated, map[string]any{"name": base + sigstoreSuffix, "sha256": sum})
		return
	}
	dir := filepath.Join(s.store.Root, "artifacts", j.RunID, j.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sidecar := artifactSidecarPath(dir, base, "sigstore")
	if err := writeFileAtomic(sidecar, body, 0o600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.attachSidecarToArtifact(r.Context(), j, base, "sigstore", sidecar, sum)
	s.auditLocked("artifact.sigstore_stored", j.LeaseRunnerID, j.RunID, j.ID, "sigstore bundle stored", map[string]string{"name": base, "sha256": sum})
	writeJSON(w, http.StatusCreated, map[string]any{"name": base + sigstoreSuffix, "sha256": sum})
}

// sidecarPendingKey names one pending sidecar in the upload-window map.
func sidecarPendingKey(jobID, base, kind string) string {
	return jobID + "\x00" + cleanBlobName(base) + "\x00" + kind
}

// rememberPendingSidecar records a DB-mode sidecar digest uploaded before
// its artifact payload, so the payload upload gate can resolve the bytes
// through CAS instead of node-local files.
func (s *Server) rememberPendingSidecar(j model.Job, base, kind, digest string) {
	s.mu.Lock()
	s.pendingSidecars[sidecarPendingKey(j.ID, base, kind)] = digest
	s.mu.Unlock()
}

// pendingSidecarDigest returns the CAS digest of a DB-mode sidecar uploaded
// for the job, or "" when unknown.
func (s *Server) pendingSidecarDigest(jobID, base, kind string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingSidecars[sidecarPendingKey(jobID, base, kind)]
}

// attachSidecarToArtifact links a verified sidecar (sbom/sigstore) to the
// existing artifact record for base. Memory mode updates the in-memory
// record; DB mode persists the digest references through the store
// (ArtifactSidecarStore).
func (s *Server) attachSidecarToArtifact(ctx context.Context, j model.Job, base, kind, path, sum string) {
	recs, err := s.findArtifactByJobName(ctx, j.RunID, j.ID, base)
	if err != nil || len(recs) == 0 {
		return
	}
	rec := recs[len(recs)-1]
	if s.DB != nil {
		if ss, ok := s.DB.(storage.ArtifactSidecarStore); ok {
			sbomPath, sbomSum, sigPath, sigSum := "", "", "", ""
			if kind == "sbom" {
				sbomPath, sbomSum = path, sum
			} else {
				sigPath, sigSum = path, sum
			}
			if err := ss.SetArtifactSidecars(ctx, rec.ID, sbomPath, sbomSum, sigPath, sigSum); err != nil {
				s.logError("artifact: sidecar attach failed", "artifact", rec.ID, "error", err.Error())
			}
		}
		return
	}
	s.mu.Lock()
	if cur, ok := s.artifacts[rec.ID]; ok {
		if kind == "sbom" {
			cur.SBOMPath = path
			cur.SBOMSHA256 = sum
		} else {
			cur.SigstorePath = path
			cur.SigstoreSHA256 = sum
		}
		s.artifacts[rec.ID] = cur
		_ = s.persistLocked()
	}
	s.mu.Unlock()
}

// gateArtifactAttestations enforces the SBOM/sigstore requirements at
// artifact-payload upload time. The frozen contract is authoritative; the
// pipeline text is never re-parsed. DB mode resolves the sidecar bytes
// through CAS via the pending-sidecar digests; fs mode reads the local
// sidecar files. It returns an HTTP error string on failure.
func (s *Server) gateArtifactAttestations(ctx context.Context, c storage.ArtifactContract, j model.Job, base string, digest string, dir string) (int, string) {
	if strings.TrimSpace(c.SBOM) != "" {
		format, err := supplychain.ParseSBOMFormat(c.SBOM)
		if err != nil {
			return http.StatusUnprocessableEntity, err.Error()
		}
		b, rerr := s.sidecarBytes(ctx, j, base, "sbom", dir)
		if rerr != nil {
			s.auditLocked("artifact.sbom_missing", j.LeaseRunnerID, j.RunID, j.ID, "required sbom missing at artifact upload", map[string]string{"name": base})
			return http.StatusUnprocessableEntity, "required sbom missing: upload <name>.sbom before the artifact"
		}
		if verr := validateSBOMDocument(b, format); verr != nil {
			s.auditLocked("artifact.sbom_rejected", j.LeaseRunnerID, j.RunID, j.ID, "required sbom invalid", map[string]string{"name": base, "error": verr.Error()})
			return http.StatusUnprocessableEntity, verr.Error()
		}
	}
	if c.SigstoreRequired {
		b, rerr := s.sidecarBytes(ctx, j, base, "sigstore", dir)
		if rerr != nil {
			s.auditLocked("artifact.sigstore_missing", j.LeaseRunnerID, j.RunID, j.ID, "required sigstore missing at artifact upload", map[string]string{"name": base})
			return http.StatusUnprocessableEntity, "required sigstore bundle missing: upload <name>.sigstore before the artifact"
		}
		if verr := supplychain.VerifySigstoreBundle(b, digest, sigstoreVerifyConfig(c)); verr != nil {
			s.auditLocked("artifact.sigstore_rejected", j.LeaseRunnerID, j.RunID, j.ID, "required sigstore bundle failed verification", map[string]string{"name": base, "error": verr.Error()})
			return http.StatusUnprocessableEntity, verr.Error()
		}
	}
	return 0, ""
}

// sidecarBytes resolves one sidecar's bytes for the upload gate: through
// CAS in DB mode (pending sidecar digest), from the local sidecar file in
// fs mode.
func (s *Server) sidecarBytes(ctx context.Context, j model.Job, base, kind, dir string) ([]byte, error) {
	if s.DB != nil {
		if d := s.pendingSidecarDigest(j.ID, base, kind); d != "" && s.CAS != nil {
			rc, _, err := s.CAS.Open(ctx, d)
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxSBOMBytes+1))
		}
		return nil, os.ErrNotExist
	}
	return os.ReadFile(artifactSidecarPath(dir, base, kind))
}

// attachSidecarsToRecord fills the sidecar fields of a freshly built
// artifact record: from the local sidecar files in fs mode, from the CAS
// digest references in DB mode (the bytes already live in the shared
// store).
func (s *Server) attachSidecarsToRecord(ctx context.Context, rec *model.ArtifactRecord, j model.Job, base, dir string) {
	if s.DB != nil {
		if d := s.pendingSidecarDigest(j.ID, base, "sbom"); d != "" {
			rec.SBOMPath = "cas:" + d
			rec.SBOMSHA256 = d
		}
		if d := s.pendingSidecarDigest(j.ID, base, "sigstore"); d != "" {
			rec.SigstorePath = "cas:" + d
			rec.SigstoreSHA256 = d
		}
		return
	}
	if b, err := os.ReadFile(artifactSidecarPath(dir, base, "sbom")); err == nil && json.Valid(b) {
		rec.SBOMPath = artifactSidecarPath(dir, base, "sbom")
		rec.SBOMSHA256 = sha256Hex(b)
	}
	if b, err := os.ReadFile(artifactSidecarPath(dir, base, "sigstore")); err == nil && json.Valid(b) {
		rec.SigstorePath = artifactSidecarPath(dir, base, "sigstore")
		rec.SigstoreSHA256 = sha256Hex(b)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
